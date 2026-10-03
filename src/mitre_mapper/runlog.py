"""Run log core: events, cross-run index, ``run.md``, budget, always-finalize context.

The run log is the single source of truth for what a run did (PLAN D12, §3.9).
Index-row counters are *derived by scanning ``events.jsonl``*, never kept as
separate mutable counters, so MCP-driven and LangChain-driven runs produce
identical rows. The only exceptions are model-call/token totals, which come
from :class:`Budget` (per-call stats are aggregated, not logged per call).

Layout of ``runs/<run_id>/``::

    events.jsonl   one compact JSON object per line (flushed per event)
    prompt.txt     verbatim system prompt (written once)
    intake.md      copy of the intake
    budget.json    snapshot of budget totals (lets abandoned runs keep stats)
    calls/NNNN.json  full tool payloads; events carry call id + sha256 only
    <domain>/...   artifacts via ``write_artifact`` (proposal_<n>.json, ...)
    run.md         short human summary (written by ``finalize``)

and ``runs/index.jsonl`` holds one append-only :class:`RunRecord` line per run
(plus ``ReviewRecord`` lines appended by the future ``review`` command).

Every event line has ``ts`` (UTC, ms, ``Z``), ``seq`` (0-based), ``event``
plus the event's own fields.

Event-field contract (later waves emit to this; fields marked * are read by
``finalize`` to derive the index row / ``run.md``; others are free-form)::

    run_start      run_id, software_name, intake_sha256, domains, model,
                   judge_model, surface ("langchain" | "mcp"), git_sha, prompt_sha256,
                   tool_version, dataset_release, eval_case, max_model_calls, max_tokens,
                   allocations_path (str path of the SX/GX registry the run mints against;
                   null = the canonical ``datasets/allocations.json``. Eval and demo runs use a
                   scratch copy so they never burn real ids; ``delta doctor`` reports those as D009)
                   (``RunLog.open`` recovers header fields from this event)
    intake_invalid errors (list[str])
    domain_resolved* domains (list[str])  -- latest one defines record.domains
    reference_fetch  source_name, url, ok (True), chars, content_type, cached (bool;
                   True = served from the content-addressed cache or frozen evidence dir)
    reference_fetch_failed* source_name, url, error      -- counted; error is human text
                   ("no url", "fetch disabled", "not in frozen evidence", "HTTP 403", ...)
    evidence_truncated source_name, original_chars, kept_chars
    search*        tool, domain, query, k, returned_ids (list[str]), call_id
                   -- empty/missing ``returned_ids`` counts as a zero-hit query
    revoked_redirect from_id, to_id
    tool_call      tool, args, call_id, sha256, ok, summary? (tool-specific facts, e.g.
                   get_evidence: total_chars, offset, returned_chars)
    proposal_draft* domain, attempt, technique_ids, group_ids, declined, rejected_candidates
                   -- attempts[domain] = count of these
    lint_result*   domain, attempt (int, or "final" with phase="final"),
                   findings: [{rule_id, severity: "ERROR"|"WARN"|"INFO", message, target, details}]
    judge_verdict* domain, attempt, approved, prompt_sha256,
                   items: [{name, passed, rationale}]     -- failed names recorded.
                   An unparseable judge answer is logged as approved=False with the single
                   failed item ``judge_output_invalid`` (rationale = the parse error).
                   Judge tokens/latency go through ``RunLog.model_call`` (budget), not here.
    retry          domain, attempt, reason, added, removed (proposal N vs N+1);
                   reason is ``lint_errors: E004,...``, ``judge_rejected: <items>``,
                   ``judge_output_invalid`` or ``no_structured_output: ...``
    group_quote_check domain, attempt, group_id, passed, reason, source,
                   software_aliases_matched, group_aliases_matched  -- one per agent-proposed
                   group mapping per attempt (the E011 check; user-asserted are not checked)
    unmatched_actor* domain, actor, quote, source_name      -- counted; one per
                   ``proposal.unmatched_actors`` entry of the accepted proposal
    user_asserted  kind = "intake" (pinned techniques: domain, techniques) |
                   "group_ref" (existing group asserted via ``groups[].ref``: domain,
                   group_id) | "new_group" (``groups[].new``: name, aliases, techniques)
    merge          kind = "agent_config" (domain, recursion_limit, ...) | "judge_config"
                   (judge: model name or null = judge skipped, logged once) | "cross_domain"
                   (domains, n_techniques, n_groups)
                   | "dedupe_user_asserted" (domain, technique_ids, group_ids: agent-proposed
                   items dropped because the user asserted the same technique/group)
                   | "holdout" (eval runs: objects removed by type, masked relationship ids)
    allocation     attack_id, name, stix_id
    mint           software_id, n_objects, domains,
                   techniques: {domain: [{id, name, user_asserted, sources: [source_name]}]},
                   groups: {domain: [{id, name, user_asserted, kind: "existing"|"new"}]}
                   -- the final mapping; ``run.md`` "Mapping" is rendered from it
    budget_exhausted message, n_model_calls, tokens, max_model_calls, max_tokens
    provider_error message
    run_end        terminal_state, n_model_calls, tokens {in,out}, latency_s,
                   wall_s, error
    error          type, message, traceback

Severity strings are matched case-insensitively. ``error_rule_ids`` and
``warn_rule_ids`` in the row are the sorted unique rule ids across all
``lint_result`` events. ``record.ts`` is the run start time.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import subprocess
import threading
import time
import traceback
import warnings
from collections.abc import Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, get_args

from pydantic import BaseModel, TypeAdapter, ValidationError

from mitre_mapper.models import IndexRecord, ReviewRecord, RunRecord, TerminalState

__all__ = [
    "DEFAULT_MANIFEST_PATH",
    "EVENTS",
    "Budget",
    "BudgetExhausted",
    "ProviderError",
    "RunLog",
    "append_index",
    "close_abandoned",
    "derive_counters",
    "read_index",
    "run_context",
]

EVENTS: frozenset[str] = frozenset(
    {
        "run_start",
        "intake_invalid",
        "domain_resolved",
        "reference_fetch",
        "reference_fetch_failed",
        "evidence_truncated",
        "search",
        "revoked_redirect",
        "tool_call",
        "proposal_draft",
        "lint_result",
        "judge_verdict",
        "retry",
        "group_quote_check",
        "unmatched_actor",
        "user_asserted",
        "merge",
        "allocation",
        "mint",
        "budget_exhausted",
        "provider_error",
        "run_end",
        "error",
    }
)

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "datasets" / "MANIFEST.json"
_RESERVED = frozenset({"ts", "seq", "event"})


def _allocations_label(path: Path | str | None, canonical: Path) -> str | None:
    """``run_start.allocations_path``: null for the canonical registry, else the absolute path."""
    if path is None:
        return None
    p = Path(path).expanduser().resolve()
    return None if p == canonical.expanduser().resolve() else str(p)
_VALID_STATES = frozenset(get_args(TerminalState))
_RECORD_ADAPTER: TypeAdapter[Any] = TypeAdapter(IndexRecord)


class BudgetExhausted(Exception):
    """Raised when a run exceeds its model-call or token cap."""


class ProviderError(Exception):
    """A model provider failure (rate limit, quota, auth). Carries its message."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class Budget:
    """Aggregated model-call budget. Per-call stats are summed, not logged."""

    max_model_calls: int = 60
    max_tokens: int | None = None
    n_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    latency_s: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def record_model_call(self, tokens_in: int, tokens_out: int, latency_s: float) -> None:
        """Record one model call; raise BudgetExhausted once a cap is exceeded."""
        with self._lock:
            self.n_calls += 1
            self.tokens_in += tokens_in
            self.tokens_out += tokens_out
            self.latency_s += latency_s
            if self.n_calls > self.max_model_calls:
                raise BudgetExhausted(
                    f"model call cap exceeded: {self.n_calls} > {self.max_model_calls}"
                )
            if self.max_tokens is not None and self.tokens_in + self.tokens_out > self.max_tokens:
                raise BudgetExhausted(
                    f"token cap exceeded: {self.tokens_in + self.tokens_out} > {self.max_tokens}"
                )

    def snapshot(self) -> dict[str, Any]:
        """JSON-able totals."""
        return {
            "n_model_calls": self.n_calls,
            "tokens": {"in": self.tokens_in, "out": self.tokens_out},
            "latency_s": round(self.latency_s, 3),
            "max_model_calls": self.max_model_calls,
            "max_tokens": self.max_tokens,
        }


# --------------------------------------------------------------------------- helpers


def _now() -> datetime:
    return datetime.now(UTC)


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40].strip("-")
    return slug or "run"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_default(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, datetime):
        return _fmt_ts(obj.astimezone(UTC))
    raise TypeError(f"not JSON-serialisable: {type(obj).__name__}")


def _dumps(obj: Any, **kw: Any) -> str:
    return json.dumps(obj, default=_json_default, ensure_ascii=False, **kw)


def _append_line(path: Path, line: str) -> None:
    """Append one line with a single os.write on an O_APPEND fd (atomic)."""
    data = (line + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        view = memoryview(data)
        while view:  # partial writes are not expected on regular files
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def _read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def _git(args: Sequence[str], cwd: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _git_sha(cwd: Path | None = None) -> str:
    """HEAD sha, ``-dirty`` suffixed if the tree has changes outside ``runs/``.

    Returns "unknown" if git is unavailable. Never raises.
    """
    try:
        cwd = cwd or Path(__file__).resolve().parent
        top = _git(["rev-parse", "--show-toplevel"], cwd)
        sha = _git(["rev-parse", "HEAD"], cwd)
        if not top or not sha or not sha.strip():
            return "unknown"
        status = _git(["status", "--porcelain", "--", ".", ":(exclude)runs"], Path(top.strip()))
        return sha.strip() + ("-dirty" if status and status.strip() else "")
    except Exception:  # noqa: BLE001 - provenance must never crash a run
        return "unknown"


def _tool_version() -> str:
    try:
        return importlib.metadata.version("mitre-mapper")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _dataset_release(manifest_path: Path) -> dict[str, str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return {
            dom: str(info["attack_release"])
            for dom, info in sorted(manifest.get("domains", {}).items())
            if "attack_release" in info
        }
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def _load_intake(intake: str | Path) -> bytes:
    if isinstance(intake, Path):
        return intake.read_bytes()
    if "\n" not in intake and len(intake) < 1024:
        with contextlib.suppress(OSError, ValueError):
            p = Path(intake)
            if p.is_file():
                return p.read_bytes()
    return intake.encode("utf-8")


def derive_counters(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Derive index-row counters from events (the single source of truth)."""
    attempts: dict[str, int] = {}
    error_ids: set[str] = set()
    warn_ids: set[str] = set()
    judge_fail: set[str] = set()
    zero_hit = unmatched = fetch_fail = 0
    domains: list[str] | None = None
    for ev in events:
        name = ev.get("event")
        if name == "proposal_draft":
            dom = str(ev.get("domain", "unknown"))
            attempts[dom] = attempts.get(dom, 0) + 1
        elif name == "lint_result":
            for f in ev.get("findings") or []:
                sev = str(f.get("severity", "")).upper()
                rid = f.get("rule_id")
                if rid and sev == "ERROR":
                    error_ids.add(str(rid))
                elif rid and sev == "WARN":
                    warn_ids.add(str(rid))
        elif name == "judge_verdict":
            for it in ev.get("items") or []:
                if it.get("passed") is False and it.get("name"):
                    judge_fail.add(str(it["name"]))
        elif name == "search":
            if not ev.get("returned_ids"):
                zero_hit += 1
        elif name == "unmatched_actor":
            unmatched += 1
        elif name == "reference_fetch_failed":
            fetch_fail += 1
        elif name == "domain_resolved" and ev.get("domains"):
            domains = [str(d) for d in ev["domains"]]
    return {
        "attempts": attempts,
        "error_rule_ids": sorted(error_ids),
        "warn_rule_ids": sorted(warn_ids),
        "judge_fail_items": sorted(judge_fail),
        "zero_hit_queries": zero_hit,
        "unmatched_actors": unmatched,
        "fetch_failures": fetch_fail,
        "domains": domains,
    }


# --------------------------------------------------------------------------- RunLog


class RunLog:
    """One per run. Use :meth:`start` / :meth:`open` or :func:`run_context`."""

    def __init__(self, run_dir: Path, header: Mapping[str, Any], budget: Budget) -> None:
        self.run_dir = run_dir
        self.runs_dir = run_dir.parent
        self.run_id: str = header["run_id"]
        self.header: dict[str, Any] = dict(header)
        self.budget = budget
        self._seq = 0
        self._call_n = 0
        self._finalized = False
        self._t0 = time.monotonic()
        self._lock = threading.RLock()

    @property
    def events_path(self) -> Path:
        return self.run_dir / "events.jsonl"

    @property
    def finalized(self) -> bool:
        return self._finalized

    # -- construction

    @classmethod
    def start(
        cls,
        runs_dir: Path | str,
        *,
        software_name: str,
        intake_text_or_path: str | Path,
        model: str,
        judge_model: str | None,
        prompt_text: str,
        domains: Sequence[str] = (),
        eval_case: str | None = None,
        budget: Budget | None = None,
        manifest_path: Path | str | None = None,
        surface: str = "langchain",
        allocations_path: Path | str | None = None,
    ) -> RunLog:
        """Create ``runs/<run_id>/`` and emit ``run_start``.

        ``allocations_path`` is recorded as given, except that the canonical registry (the
        ``allocations.json`` next to the manifest) is recorded as null.
        """
        runs_dir = Path(runs_dir)
        runs_dir.mkdir(parents=True, exist_ok=True)
        now = _now()
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        while True:
            run_id = f"{stamp}-{_slug(software_name)}-{secrets.token_hex(3)}"
            run_dir = runs_dir / run_id
            try:
                run_dir.mkdir()
                break
            except FileExistsError:
                continue
        intake_bytes = _load_intake(intake_text_or_path)
        prompt_bytes = prompt_text.encode("utf-8")
        (run_dir / "prompt.txt").write_bytes(prompt_bytes)
        (run_dir / "intake.md").write_bytes(intake_bytes)
        budget = budget or Budget()
        header = {
            "run_id": run_id,
            "software_name": software_name,
            "intake_sha256": _sha256(intake_bytes),
            "domains": list(domains),
            "model": model,
            "judge_model": judge_model,
            "surface": surface,
            "git_sha": _git_sha(),
            "prompt_sha256": _sha256(prompt_bytes),
            "tool_version": _tool_version(),
            "dataset_release": _dataset_release(Path(manifest_path or DEFAULT_MANIFEST_PATH)),
            "eval_case": eval_case,
            "max_model_calls": budget.max_model_calls,
            "max_tokens": budget.max_tokens,
            "allocations_path": _allocations_label(
                allocations_path, Path(manifest_path or DEFAULT_MANIFEST_PATH).parent / "allocations.json"
            ),
        }
        log = cls(run_dir, header, budget)
        log.event("run_start", **header)
        return log

    @classmethod
    def open(cls, run_dir: Path | str) -> RunLog:
        """Reattach to an existing run, recovering header fields from run_start."""
        run_dir = Path(run_dir)
        events = _read_events(run_dir / "events.jsonl")
        start = next((e for e in events if e.get("event") == "run_start"), None)
        if start is None:
            raise ValueError(f"{run_dir} has no run_start event")
        header = {k: v for k, v in start.items() if k not in _RESERVED}
        budget = Budget(
            max_model_calls=header.get("max_model_calls") or 60,
            max_tokens=header.get("max_tokens"),
        )
        with contextlib.suppress(OSError, ValueError, KeyError, TypeError):
            snap = json.loads((run_dir / "budget.json").read_text(encoding="utf-8"))
            budget.n_calls = int(snap["n_model_calls"])
            budget.tokens_in = int(snap["tokens"]["in"])
            budget.tokens_out = int(snap["tokens"]["out"])
            budget.latency_s = float(snap["latency_s"])
        log = cls(run_dir, header, budget)
        log._seq = max((int(e.get("seq", -1)) for e in events), default=-1) + 1
        calls = run_dir / "calls"
        if calls.is_dir():
            log._call_n = sum(1 for _ in calls.glob("*.json"))
        log._finalized = any(e.get("event") == "run_end" for e in events)
        with contextlib.suppress(KeyError, ValueError):
            elapsed = (_now() - _parse_ts(start["ts"])).total_seconds()
            log._t0 = time.monotonic() - max(elapsed, 0.0)
        return log

    # -- writing

    def event(self, event_name: str, /, **fields: Any) -> None:
        """Append one flushed JSON line. Unknown names raise ValueError.

        ``event_name`` is positional-only so events may carry a ``name`` field.
        """
        if event_name not in EVENTS:
            raise ValueError(f"unknown event name: {event_name!r}")
        clash = _RESERVED & fields.keys()
        if clash:
            raise ValueError(f"reserved event field(s): {sorted(clash)}")
        with self._lock:
            line = _dumps({"ts": _fmt_ts(_now()), "seq": self._seq, "event": event_name, **fields})
            _append_line(self.events_path, line)
            self._seq += 1

    def _safe_path(self, relpath: str | Path) -> Path:
        rel = Path(relpath)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"artifact path must be relative within the run dir: {relpath}")
        return self.run_dir / rel

    def write_artifact(self, relpath: str | Path, obj: Any) -> Path:
        """Write ``obj`` as JSON under the run dir (e.g. ``mobile-attack/proposal_1.json``)."""
        path = self._safe_path(relpath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_dumps(obj, indent=2) + "\n", encoding="utf-8")
        return path

    def write_call(self, tool: str, payload: Any) -> tuple[int, str]:
        """Write ``calls/<NNNN>.json``; return ``(call_id, sha256_of_payload)``."""
        with self._lock:
            self._call_n += 1
            n = self._call_n
        payload_json = _dumps(payload, sort_keys=True)
        digest = _sha256(payload_json.encode("utf-8"))
        self.write_artifact(
            f"calls/{n:04d}.json",
            {"call_id": n, "tool": tool, "sha256": digest, "payload": payload},
        )
        return n, digest

    def model_call(self, tokens_in: int, tokens_out: int, latency_s: float) -> None:
        """Record a model call on the budget and snapshot totals to ``budget.json``.

        Raises BudgetExhausted after recording when a cap is exceeded.
        """
        try:
            self.budget.record_model_call(tokens_in, tokens_out, latency_s)
        finally:
            with self._lock:
                (self.run_dir / "budget.json").write_text(
                    _dumps(self.budget.snapshot()), encoding="utf-8"
                )

    # -- finishing

    def finalize(
        self,
        terminal_state: str,
        *,
        error: str | None = None,
        eval_scores: dict[str, Any] | None = None,
    ) -> RunRecord | None:
        """Emit run_end, append the index row, write run.md. Idempotent."""
        with self._lock:
            if self._finalized:
                return None
            if terminal_state not in _VALID_STATES:
                raise ValueError(f"invalid terminal_state: {terminal_state!r}")
            self._finalized = True
            snap = self.budget.snapshot()
            wall_s = round(time.monotonic() - self._t0, 3)
            self.event(
                "run_end",
                terminal_state=terminal_state,
                n_model_calls=snap["n_model_calls"],
                tokens=snap["tokens"],
                latency_s=snap["latency_s"],
                wall_s=wall_s,
                error=error,
            )
            events = _read_events(self.events_path)
            counters = derive_counters(events)
            h = self.header
            start_ts = next((e["ts"] for e in events if e.get("event") == "run_start"), "")
            record = RunRecord(
                run_id=self.run_id,
                ts=start_ts or _fmt_ts(_now()),
                software_name=h["software_name"],
                intake_sha256=h["intake_sha256"],
                domains=counters["domains"] or h.get("domains") or [],
                model=h["model"],
                judge_model=h.get("judge_model"),
                surface=h.get("surface") or "langchain",
                git_sha=h["git_sha"],
                prompt_sha256=h["prompt_sha256"],
                tool_version=h["tool_version"],
                dataset_release=h.get("dataset_release") or {},
                n_model_calls=snap["n_model_calls"],
                tokens=snap["tokens"],
                wall_s=wall_s,
                attempts=counters["attempts"],
                terminal_state=terminal_state,
                error_rule_ids=counters["error_rule_ids"],
                warn_rule_ids=counters["warn_rule_ids"],
                judge_fail_items=counters["judge_fail_items"],
                zero_hit_queries=counters["zero_hit_queries"],
                unmatched_actors=counters["unmatched_actors"],
                fetch_failures=counters["fetch_failures"],
                eval_case=h.get("eval_case"),
                eval_scores=eval_scores,
                review=None,
            )
            (self.run_dir / "run.md").write_text(
                _render_run_md(record, events, error), encoding="utf-8"
            )
            append_index(self.runs_dir, record)
            return record


def _render_run_md(record: RunRecord, events: Sequence[Mapping[str, Any]], error: str | None) -> str:
    lines = [
        f"# {record.software_name}",
        "",
        f"- run_id: `{record.run_id}`",
        f"- terminal state: **{record.terminal_state}**",
        f"- domains / attempts: "
        + (", ".join(f"{d} ({record.attempts.get(d, 0)})" for d in record.domains) or "none")
        + (
            ""
            if set(record.attempts) <= set(record.domains)
            else f" [attempts: {record.attempts}]"
        ),
        f"- model: {record.model}; judge: {record.judge_model or 'none'}",
        f"- git: `{record.git_sha[:12]}{'-dirty' if record.git_sha.endswith('-dirty') else ''}`"
        f"; prompt: `{record.prompt_sha256[:12]}`",
        f"- model calls: {record.n_model_calls}; tokens in/out: "
        f"{record.tokens.get('in', 0)}/{record.tokens.get('out', 0)}; wall: {record.wall_s}s",
        f"- ERROR rules: {', '.join(record.error_rule_ids) or 'none'}",
        f"- WARN rules: {', '.join(record.warn_rule_ids) or 'none'}",
        f"- judge failed items: {', '.join(record.judge_fail_items) or 'none'}",
        f"- zero-hit searches: {record.zero_hit_queries}",
        f"- fetch failures: {record.fetch_failures}",
    ]
    for ev in events:
        if ev.get("event") == "reference_fetch_failed":
            lines.append(
                f"  - {ev.get('source_name') or ev.get('url') or '?'}: {ev.get('error', '')}"
            )
    lines.append(f"- unmatched actors: {record.unmatched_actors}")
    for ev in events:
        if ev.get("event") == "unmatched_actor":
            lines.append(f"  - {ev.get('actor', '?')}: \"{ev.get('quote', '')}\"")
    lines += _render_mapping(events)
    lines += _render_attempts(events)
    msgs = [error] if error else []
    for ev in events:
        if ev.get("event") in ("error", "provider_error", "budget_exhausted") and ev.get("message"):
            m = f"{ev['event']}: {ev['message']}"
            if not error or ev.get("message") not in error:
                msgs.append(m)
    if msgs:
        lines += ["", "## Error", *[f"- {m}" for m in msgs]]
    return "\n".join(lines) + "\n"


def _render_mapping(events: Sequence[Mapping[str, Any]]) -> list[str]:
    """``## Mapping`` from the (last) ``mint`` event: techniques with sources, groups."""
    mint = next((e for e in reversed(events) if e.get("event") == "mint"), None)
    if mint is None:
        return []
    techniques: Mapping[str, Any] = mint.get("techniques") or {}
    groups: Mapping[str, Any] = mint.get("groups") or {}
    lines = ["", "## Mapping"]
    for domain in sorted(set(techniques) | set(groups)):
        lines.append(f"### {domain}")
        for t in techniques.get(domain, []):
            who = "user-asserted" if t.get("user_asserted") else ", ".join(t.get("sources") or []) or "NO SOURCE"
            lines.append(f"- {t.get('id')} {t.get('name')} -- {who}")
        for g in groups.get(domain, []):
            tags = [str(g.get("kind", "?"))] + (["user-asserted"] if g.get("user_asserted") else [])
            lines.append(f"- group {g.get('id')} {g.get('name')} ({', '.join(tags)})")
    return lines


def _render_attempts(events: Sequence[Mapping[str, Any]]) -> list[str]:
    """``## Attempts``: per (domain, attempt) lint ERROR rule ids + judge outcome + quote failures."""
    rows: dict[tuple[str, int], dict[str, Any]] = {}
    final_errors: dict[str, list[str]] = {}
    quote_fails: list[str] = []
    for ev in events:
        name = ev.get("event")
        dom = str(ev.get("domain", "?"))
        att = ev.get("attempt")
        if name == "lint_result":
            errs = sorted(
                {str(f["rule_id"]) for f in ev.get("findings") or [] if str(f.get("severity", "")).upper() == "ERROR"}
            )
            if isinstance(att, int):
                rows.setdefault((dom, att), {})["lint"] = errs
            elif errs:
                final_errors[dom] = errs
        elif name == "judge_verdict" and isinstance(att, int):
            failed = [str(i.get("name")) for i in ev.get("items") or [] if i.get("passed") is False]
            rows.setdefault((dom, att), {})["judge"] = "approved" if ev.get("approved") else failed
        elif name == "group_quote_check" and ev.get("passed") is False:
            quote_fails.append(f"  - {dom} #{att} {ev.get('group_id')}: {ev.get('reason')}")
    if not (rows or final_errors):
        return []
    lines = ["", "## Attempts"]
    for (dom, att), row in sorted(rows.items()):
        lint = row.get("lint")
        parts = [f"lint {'ERROR ' + ', '.join(lint) if lint else 'clean'}" if lint is not None else "no lint"]
        judge = row.get("judge")
        if judge is not None:
            parts.append("judge approved" if judge == "approved" else "judge failed " + ", ".join(judge))
        lines.append(f"- {dom} #{att}: " + "; ".join(parts))
    for dom, errs in sorted(final_errors.items()):
        lines.append(f"- {dom} final lint ERROR {', '.join(errs)}")
    if quote_fails:
        lines += ["- group quote check failures:", *quote_fails]
    return lines


# --------------------------------------------------------------------------- context


@contextlib.contextmanager
def run_context(
    runs_dir: Path | str,
    *,
    software_name: str,
    intake_text_or_path: str | Path,
    model: str,
    judge_model: str | None,
    prompt_text: str,
    domains: Sequence[str] = (),
    eval_case: str | None = None,
    budget: Budget | None = None,
    manifest_path: Path | str | None = None,
    surface: str = "langchain",
    allocations_path: Path | str | None = None,
) -> Iterator[RunLog]:
    """Start a run and guarantee it ends with ``run_end`` + index row + run.md.

    BudgetExhausted / ProviderError are logged, finalized and swallowed; any
    other BaseException is logged, finalized as "error" and re-raised. The body
    sets the real outcome by calling ``log.finalize(...)`` itself.
    """
    log = RunLog.start(
        runs_dir,
        software_name=software_name,
        intake_text_or_path=intake_text_or_path,
        model=model,
        judge_model=judge_model,
        prompt_text=prompt_text,
        domains=domains,
        eval_case=eval_case,
        budget=budget,
        manifest_path=manifest_path,
        surface=surface,
        allocations_path=allocations_path,
    )
    try:
        yield log
    except BudgetExhausted as exc:
        if not log.finalized:
            log.event("budget_exhausted", message=str(exc), **log.budget.snapshot())
            log.finalize("budget_exhausted", error=str(exc))
    except ProviderError as exc:
        if not log.finalized:
            log.event("provider_error", message=exc.message)
            log.finalize("provider_error", error=exc.message)
    except BaseException as exc:
        if not log.finalized:
            tb = "".join(traceback.format_exception(exc, limit=-6))[-2000:]
            log.event("error", type=type(exc).__name__, message=str(exc), traceback=tb)
            log.finalize("error", error=f"{type(exc).__name__}: {exc}")
        raise
    else:
        if not log.finalized:
            log.finalize("error", error="run ended without terminal state")


# --------------------------------------------------------------------------- index


def append_index(runs_dir: Path | str, record: RunRecord | ReviewRecord) -> None:
    """Append one record line to ``runs/index.jsonl`` (single O_APPEND write)."""
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    _append_line(runs_dir / "index.jsonl", record.model_dump_json())


def read_index(runs_dir: Path | str) -> list[RunRecord]:
    """Read run rows, joining the latest ReviewRecord per run_id into ``review``.

    Corrupt lines are skipped with a warning.
    """
    path = Path(runs_dir) / "index.jsonl"
    runs: list[RunRecord] = []
    reviews: dict[str, ReviewRecord] = {}
    if not path.exists():
        return runs
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = _RECORD_ADAPTER.validate_json(line)
        except (ValidationError, ValueError) as exc:
            warnings.warn(
                f"{path}:{lineno}: skipping corrupt index line ({type(exc).__name__})",
                stacklevel=2,
            )
            continue
        if isinstance(rec, ReviewRecord):
            reviews[rec.run_id] = rec
        else:
            runs.append(rec)
    return [
        r.model_copy(update={"review": reviews[r.run_id].summary}) if r.run_id in reviews else r
        for r in runs
    ]


def close_abandoned(
    runs_dir: Path | str,
    *,
    min_idle_s: float = 0.0,
    surface: str | None = None,
    exclude: Collection[str] = (),
) -> list[str]:
    """Finalize runs that have run_start but no run_end as "abandoned".

    A run is abandoned when it never ended: ``min_idle_s`` skips runs whose events file changed more
    recently than that (guards against closing a live run of another process); ``surface`` restricts
    to runs whose ``run_start`` recorded that surface (the MCP server passes ``"mcp"`` so it never
    closes a LangChain run in progress); ``exclude`` skips run ids this process still owns.
    Returns run ids closed.
    """
    runs_dir = Path(runs_dir)
    closed: list[str] = []
    if not runs_dir.is_dir():
        return closed
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        events_path = run_dir / "events.jsonl"
        if not events_path.exists() or run_dir.name in exclude:
            continue
        if min_idle_s and time.time() - events_path.stat().st_mtime < min_idle_s:
            continue
        events = _read_events(events_path)
        names = {e.get("event") for e in events}
        if "run_start" not in names or "run_end" in names:
            continue
        if surface is not None:
            start = next(e for e in events if e.get("event") == "run_start")
            if (start.get("surface") or "langchain") != surface:
                continue
        log = RunLog.open(run_dir)
        log.finalize("abandoned", error="run ended without run_end (session abandoned)")
        closed.append(log.run_id)
    return closed
