"""The single tool surface (PLAN 3.8): plain functions shared by MCP and LangChain.

Every public tool takes a :class:`ToolContext` first and returns a compact,
JSON-able ``dict`` meant for an LLM. Every call goes through ONE logging
wrapper (:func:`_logged`) so MCP-driven and LangChain-driven runs log
identically: a full payload under ``calls/<n>.json`` plus a ``tool_call``
event (``call_id``, ``sha256``, ``ok``); search tools also emit ``search``
(``query``, ``k``, ``returned_ids``, ``call_id``) and revoked lookups emit
``revoked_redirect``. A tool body may set ``call.summary`` (e.g. ``returned_chars`` for
``get_evidence``); it is logged on the ``tool_call`` event as ``summary``.

Tools never raise into the agent: any failure becomes ``{"error": "..."}``.
No LangChain imports here (acceptance criterion 13).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mitre_mapper.allocations import Allocations
from mitre_mapper.lint import LintContext, has_errors, lint
from mitre_mapper.mint import build_objects
from mitre_mapper.models import IntakeSpec, LintFinding, MappingProposal
from mitre_mapper.runlog import RunLog
from mitre_mapper.search import search
from mitre_mapper.store import AttackStore, DomainStore

REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCES_DIR = REPO_ROOT / "skills" / "map-software" / "references"
# judge-rubric.md is deliberately absent: the mapping agent must never read it.
READABLE_REFERENCES = frozenset({"linter-rules.md", "stix-shapes.md"})

_DESC_SHORT = 300
_DESC_LONG = 900


@dataclass
class ToolContext:
    """Everything a tool call needs. One per (run, domain)."""

    log: RunLog
    store: AttackStore
    domain: str
    spec: IntakeSpec
    evidence: dict[str, str] = field(default_factory=dict)
    allocations: Allocations | None = None
    # ATT&CK ids returned by searches since the last reset (run.py resets per attempt
    # to compute ``rejected_candidates``).
    returned_ids: list[str] = field(default_factory=list)

    @property
    def domain_store(self) -> DomainStore:
        return self.store.domain(self.domain)


class _Call:
    """Scratch space a tool body uses to ask the wrapper for extra events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.summary: dict[str, Any] = {}

    def emit(self, name: str, **fields: Any) -> None:
        self.events.append((name, fields))


def _logged(
    fn: Callable[..., dict[str, Any]],
) -> Callable[..., dict[str, Any]]:
    """The one logging wrapper. ``fn(ctx, call, **args)`` -> result dict."""
    tool = fn.__name__

    @functools.wraps(fn)
    def wrapper(ctx: ToolContext, **args: Any) -> dict[str, Any]:
        call = _Call()
        try:
            result = fn(ctx, call, **args)
        except Exception as exc:  # noqa: BLE001 - tools never raise into the agent
            result = {"error": f"{type(exc).__name__}: {exc}"}
        ok = "error" not in result
        try:
            call_id, digest = ctx.log.write_call(tool, {"args": args, "result": result})
            extra = {"summary": call.summary} if call.summary else {}
            ctx.log.event(
                "tool_call", tool=tool, args=args, call_id=call_id, sha256=digest, ok=ok, **extra
            )
            for name, fields in call.events:
                ctx.log.event(name, call_id=call_id, **fields)
        except Exception as exc:  # noqa: BLE001 - logging failure must not kill the agent
            result = {**result, "log_error": f"{type(exc).__name__}: {exc}"}
        return result

    return wrapper


# --------------------------------------------------------------------------- formatting


def _clip(text: str | None, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _tactics(obj: dict[str, Any]) -> list[str]:
    return [p["phase_name"] for p in obj.get("kill_chain_phases", []) if "phase_name" in p]


def _fmt_technique(store: DomainStore, obj: dict[str, Any], limit: int) -> dict[str, Any]:
    attack_id = store.attack_id(obj)
    return {
        "id": attack_id,
        "name": obj.get("name"),
        "description": _clip(obj.get("description"), limit),
        "tactics": _tactics(obj),
        "platforms": obj.get("x_mitre_platforms", []),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
    }


def _fmt_group(store: DomainStore, obj: dict[str, Any], limit: int) -> dict[str, Any]:
    return {
        "id": store.attack_id(obj),
        "name": obj.get("name"),
        "aliases": obj.get("aliases", []),
        "description": _clip(obj.get("description"), limit),
    }


def _fmt_software(store: DomainStore, obj: dict[str, Any], limit: int) -> dict[str, Any]:
    return {
        "id": store.attack_id(obj),
        "name": obj.get("name"),
        "type": obj.get("type"),
        "aliases": obj.get("x_mitre_aliases", []),
        "platforms": obj.get("x_mitre_platforms", []),
        "description": _clip(obj.get("description"), limit),
    }


_FORMATTERS = {"technique": _fmt_technique, "group": _fmt_group, "software": _fmt_software}


def _do_search(ctx: ToolContext, call: _Call, kind: str, query: str, k: int) -> dict[str, Any]:
    store = ctx.domain_store
    k = max(1, min(int(k), 25))
    hits = search(store, kind, query, k)  # type: ignore[arg-type]
    results: list[dict[str, Any]] = []
    for hit in hits:
        obj = store.get_by_stix_id(hit.stix_id)
        row = _FORMATTERS[kind](store, obj, _DESC_SHORT) if obj else {"id": hit.attack_id}
        row["score"] = round(hit.score, 3)
        results.append(row)
    ids = [h.attack_id for h in hits]
    ctx.returned_ids.extend(ids)
    call.emit("search", tool=f"search_{kind}s", query=query, k=k, returned_ids=ids)
    return {"domain": ctx.domain, "query": query, "results": results}


def _do_get(
    ctx: ToolContext, call: _Call, kind: str, attack_id: str, stix_types: tuple[str, ...]
) -> dict[str, Any]:
    store = ctx.domain_store
    for stix_type in stix_types:
        lookup = store.lookup(attack_id, stix_type)
        if lookup.obj is None:
            continue
        if lookup.redirected_from:
            new_id = store.attack_id(lookup.obj)
            call.emit("revoked_redirect", from_id=lookup.redirected_from, to_id=new_id)
        out = _FORMATTERS[kind](store, lookup.obj, _DESC_LONG)
        if lookup.redirected_from:
            out["redirected_from"] = lookup.redirected_from
            out["note"] = f"{lookup.redirected_from} is revoked; showing its successor."
        return out
    return {"error": f"{attack_id} not found as an active {kind} in {ctx.domain}"}


# --------------------------------------------------------------------------- tools


@_logged
def search_techniques(ctx: ToolContext, call: _Call, query: str, k: int = 10) -> dict[str, Any]:
    """BM25 search over active techniques in the current domain."""
    return _do_search(ctx, call, "technique", query, k)


@_logged
def search_groups(ctx: ToolContext, call: _Call, query: str, k: int = 10) -> dict[str, Any]:
    """BM25 search over active groups (names, aliases, descriptions)."""
    return _do_search(ctx, call, "group", query, k)


@_logged
def search_software(ctx: ToolContext, call: _Call, query: str, k: int = 10) -> dict[str, Any]:
    """BM25 search over active malware and tools."""
    return _do_search(ctx, call, "software", query, k)


@_logged
def get_technique(ctx: ToolContext, call: _Call, attack_id: str) -> dict[str, Any]:
    """Fetch one technique by ATT&CK id (revoked ids redirect to the successor)."""
    return _do_get(ctx, call, "technique", attack_id, ("attack-pattern",))


@_logged
def get_group(ctx: ToolContext, call: _Call, attack_id: str) -> dict[str, Any]:
    """Fetch one group by ATT&CK id (e.g. G0046) or by name/alias (e.g. "Carbon Spider")."""
    out = _do_get(ctx, call, "group", attack_id, ("intrusion-set",))
    if "error" not in out:
        return out
    store = ctx.domain_store
    obj = store.resolve_group(attack_id)
    if obj is None:
        return {"error": f"{attack_id} is not an active group id, name or alias in {ctx.domain}"}
    out = _FORMATTERS["group"](store, obj, _DESC_LONG)
    out["matched_by"] = "name_or_alias"
    return out


@_logged
def get_software(ctx: ToolContext, call: _Call, attack_id: str) -> dict[str, Any]:
    """Fetch one malware/tool by ATT&CK id."""
    return _do_get(ctx, call, "software", attack_id, ("malware", "tool"))


@_logged
def get_software_techniques(ctx: ToolContext, call: _Call, attack_id: str) -> dict[str, Any]:
    """Techniques ATT&CK maps for an existing software id (to compare similar software)."""
    store = ctx.domain_store
    ids = store.software_techniques(attack_id)
    rows = []
    for tid in ids:
        lk = store.lookup(tid, "attack-pattern")
        rows.append({"id": tid, "name": lk.obj.get("name") if lk.obj else None})
    return {"software": attack_id, "techniques": rows}


EVIDENCE_WINDOW = 8_000
EVIDENCE_WINDOW_MAX = 20_000


@_logged
def get_evidence(
    ctx: ToolContext,
    call: _Call,
    source_name: str,
    offset: int = 0,
    max_chars: int = EVIDENCE_WINDOW,
) -> dict[str, Any]:
    """Return a window of the fetched evidence text for a reference ``source_name``.

    Long evidence is paged: pass the returned ``next_offset`` as ``offset`` to continue.
    """
    text = ctx.evidence.get(source_name)
    if text is None:
        return {
            "error": f"no evidence available for {source_name!r}",
            "available": sorted(ctx.evidence),
        }
    offset = max(0, int(offset))
    window = max(1, min(int(max_chars), EVIDENCE_WINDOW_MAX))
    chunk = text[offset : offset + window]
    end = offset + len(chunk)
    call.summary = {"total_chars": len(text), "offset": offset, "returned_chars": len(chunk)}
    return {
        "source_name": source_name,
        "text": chunk,
        "offset": offset,
        "returned_chars": len(chunk),
        "total_chars": len(text),
        "next_offset": end if end < len(text) else None,
    }


@_logged
def read_reference(ctx: ToolContext, call: _Call, name: str) -> dict[str, Any]:
    """Read an allow-listed reference document (never the judge rubric)."""
    if name not in READABLE_REFERENCES:
        return {"error": f"{name!r} is not readable", "allowed": sorted(READABLE_REFERENCES)}
    path = REFERENCES_DIR / name
    if not path.is_file():
        return {"error": f"reference {name!r} does not exist yet"}
    return {"name": name, "text": path.read_text(encoding="utf-8")}


# --------------------------------------------------------------------------- lint preview


def now_stix() -> str:
    """UTC timestamp in ATT&CK format (exactly 3 fractional digits)."""
    dt = datetime.now(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def preview_lint(
    spec: IntakeSpec,
    proposal: MappingProposal,
    store: AttackStore,
    allocations: Allocations,
    evidence: dict[str, str],
    created: str,
) -> list[LintFinding]:
    """Mint preview (``commit=False``, never writes allocations) + lint for one domain."""
    domain = proposal.domain
    preview = build_objects(spec, {domain: proposal}, store, allocations, created, commit=False)
    return lint(
        LintContext(
            proposal=proposal,
            domain=domain,
            store=store.domain(domain),
            objects=preview.by_domain.get(domain, []),
            allocations=allocations,
            evidence=evidence,
            spec=spec,
        )
    )


@_logged
def lint_proposal(ctx: ToolContext, call: _Call, proposal: dict[str, Any]) -> dict[str, Any]:
    """Lint a proposal (JSON) without minting; for MCP / dry runs."""
    if ctx.allocations is None:
        return {"error": "ToolContext has no allocations registry"}
    parsed = MappingProposal.model_validate({**proposal, "domain": ctx.domain})
    findings = preview_lint(
        ctx.spec, parsed, ctx.store, ctx.allocations, ctx.evidence, now_stix()
    )
    return {
        "has_errors": has_errors(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


# ``mint_delta`` (refuses on any ERROR, closes the MCP run) arrives with the MCP
# server in Wave 4B; run.py owns committing mints in the map flow.

TOOL_FUNCTIONS: dict[str, Callable[..., dict[str, Any]]] = {
    f.__name__: f
    for f in (
        search_techniques,
        get_technique,
        search_groups,
        get_group,
        search_software,
        get_software,
        get_software_techniques,
        get_evidence,
        read_reference,
        lint_proposal,
    )
}
