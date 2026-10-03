"""Cross-run report (PLAN 3.9): "what is this tool getting tripped up on?".

``build_report(records, events_loader, last=, since=)`` aggregates ``runs/index.jsonl`` rows
and, for evidence, each run's ``events.jsonl`` (events are the source of truth; nothing here
keeps mutable state). ``report --json`` emits the dict below; ``render_text`` is the compact
human view. Every list is capped (``RUN_CAP`` run ids, ``EXAMPLE_CAP`` examples) and every
entry carries ``run_ids`` so a diagnosing agent can open ``runs/<run_id>/events.jsonl``.
Shares are ``n_runs / window.n_runs`` (0..1, 3 dp); rates are per the stated denominator.

JSON schema (``schema_version`` 1; keys are stable, additions only)::

    schema_version, generated_at
    window: {n_runs, since, last, first_ts, last_ts, first_run_id, last_run_id,
             runs_without_events}            # runs whose events.jsonl is missing/archived
    terminal_states: {state: count}          # e.g. {"minted": 3, "lint_failed": 1}
    terminal_state_detail: [{state, n_runs, share_of_runs, run_ids}]   # non-minted first
    rules: {"error": [RULE], "warn": [RULE]}  # sorted by n_runs desc; INFO is never listed
      RULE = {rule_id, severity, n_findings, n_runs, share_of_runs, run_ids,
              examples: [{run_id, domain, attempt, message, target}]}
    judge_items: [{item, n_failed, n_verdicts, fail_rate, n_runs, share_of_runs, run_ids,
                   examples: [{run_id, domain, attempt, rationale}]}]
                                             # fail_rate = failed / verdicts containing item
    judge: {n_verdicts, n_rejected, reject_rate}
    searches: {n_searches, n_zero_hit, zero_hit_rate, n_runs_with_zero_hit, share_of_runs,
               run_ids, example_queries: [{run_id, tool, query, k}],
               top_zero_hit_queries: [{query, count}]}
    fetch: {n_references, n_failures, failure_rate, n_runs, share_of_runs, run_ids,
            by_error: [{error, count}],
            examples: [{run_id, source_name, url, error}]}
    unmatched_actors: [{actor, count, n_runs, share_of_runs, run_ids, example_quote,
                        example_source_name}]
    group_quote_checks: {n_checks, n_failed, fail_rate, n_runs_failed, run_ids,
                         by_reason: [{reason, count}]}
    retries: {n_retries, n_runs, share_of_runs, run_ids, by_reason: [{reason, count}]}
    reviews: {n_reviewed, techniques_accepted, techniques_rejected, groups_accepted,
              groups_rejected, missed_techniques, missed_groups, precision, recall,
              most_rejected: [{id, count, run_ids}], most_missed: [{id, count, run_ids}]}
                                             # precision/recall are micro-averaged, or null
    eval: {case: [{run_id, ts, git_sha, prompt_sha256, scores}]}  # trend in index order;
                                             # scores = the run's eval_scores, as recorded
    cohorts: [COHORT]                        # grouped by (prompt_sha256, git_sha), oldest first
      COHORT = {prompt_sha256, git_sha, n_runs, first_ts, last_ts, run_ids,
                terminal_states, metrics: {name: number|null}}
        metrics: minted_rate, terminal_ok_rate (minted|declined), lint_error_run_share,
        mean_attempts, mean_model_calls, mean_wall_s, zero_hit_per_run, fetch_failures_per_run,
        unmatched_actors_per_run, judge_fail_runs_share, review_precision, review_recall,
        and ``eval.<case>.<numeric score key>`` = mean over that cohort's eval runs.
        ``prompt_sha256``/``git_sha`` are 12-char prefixes (``-dirty`` kept on git_sha).
    cohort_comparison: [{from: {prompt_sha256, git_sha}, to: {...}, diff: {metric: to - from}}]
                                             # consecutive cohorts, only metrics present in both;
                                             # judge a fix by the last entry vs its baseline
    by_surface: {surface: {n_runs, terminal_states}}
    runs: [{run_id, ts, software_name, surface, terminal_state, git_sha, prompt_sha256,
            error_rule_ids, warn_rule_ids, judge_fail_items, eval_case, has_events}]  # <= 200
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mitre_mapper.models import RunRecord

__all__ = [
    "EXAMPLE_CAP",
    "RUN_CAP",
    "SCHEMA_VERSION",
    "ReportError",
    "build_report",
    "events_loader_for",
    "render_text",
    "select_window",
]

SCHEMA_VERSION = 1
RUN_CAP = 10
EXAMPLE_CAP = 5
_RUNS_LIST_CAP = 200
_TOP_CAP = 10
_MSG_CAP = 300

EventsLoader = Callable[[str], "list[dict[str, Any]] | None"]


class ReportError(ValueError):
    """Bad ``--since`` / ``--last``."""


def events_loader_for(runs_dir: Path | str) -> EventsLoader:
    """Loader returning a run's events, or ``None`` if ``events.jsonl`` is absent."""
    base = Path(runs_dir)

    def load(run_id: str) -> list[dict[str, Any]] | None:
        path = base / run_id / "events.jsonl"
        if not path.is_file():
            return None
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out

    return load


# --------------------------------------------------------------------------- window


def select_window(
    records: Sequence[RunRecord], *, last: int | None = None, since: str | None = None
) -> list[RunRecord]:
    """Apply ``since`` (``YYYY-MM-DD[THH:MM...]`` or a run_id, inclusive) then ``last``."""
    rows = list(records)
    if since:
        ids = [r.run_id for r in rows]
        if since in ids:
            rows = rows[ids.index(since) :]
        else:
            try:
                cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ReportError(
                    f"--since {since!r}: not a run_id in the index or an ISO date"
                ) from exc
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=UTC)
            rows = [r for r in rows if _ts(r) >= cutoff]
    if last is not None:
        if last < 0:
            raise ReportError("--last must be >= 0")
        rows = rows[-last:] if last else []
    return rows


def _ts(r: RunRecord) -> datetime:
    try:
        return datetime.fromisoformat(r.ts.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- helpers


def _share(n: int, total: int) -> float:
    return round(n / total, 3) if total else 0.0


def _rate(n: int, total: int) -> float:
    return round(n / total, 4) if total else 0.0


def _cap(text: Any, n: int = _MSG_CAP) -> str:
    s = str(text if text is not None else "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _short(sha: str) -> str:
    return sha[:12] + ("-dirty" if sha.endswith("-dirty") and "-dirty" not in sha[:12] else "")


def _add_run(bucket: list[str], run_id: str) -> None:
    if run_id not in bucket and len(bucket) < RUN_CAP:
        bucket.append(run_id)


def _flat_numeric(obj: Any, prefix: str = "") -> dict[str, float]:
    out: dict[str, float] = {}
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            out.update(_flat_numeric(v, f"{prefix}{k}."))
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        out[prefix.rstrip(".")] = float(obj)
    return out


def _mean(vals: Sequence[float]) -> float | None:
    return round(sum(vals) / len(vals), 4) if vals else None


class _Group:
    """Counter + distinct run ids (capped) + capped examples."""

    def __init__(self) -> None:
        self.count = 0
        self.runs: set[str] = set()
        self.run_ids: list[str] = []
        self.examples: list[dict[str, Any]] = []

    def hit(self, run_id: str, example: dict[str, Any] | None = None) -> None:
        self.count += 1
        self.runs.add(run_id)
        _add_run(self.run_ids, run_id)
        if example is not None and len(self.examples) < EXAMPLE_CAP:
            self.examples.append(example)


# --------------------------------------------------------------------------- build


def build_report(
    records: Sequence[RunRecord],
    events_loader: EventsLoader | None = None,
    *,
    last: int | None = None,
    since: str | None = None,
) -> dict[str, Any]:
    """Aggregate ``records`` (index order) into the JSON-able report described above."""
    rows = select_window(records, last=last, since=since)
    n = len(rows)
    loader: EventsLoader = events_loader or (lambda _rid: None)

    rules: dict[str, dict[str, _Group]] = {"error": defaultdict(_Group), "warn": defaultdict(_Group)}
    judge_items: dict[str, _Group] = defaultdict(_Group)
    judge_seen: Counter[str] = Counter()
    n_verdicts = n_rejected = 0
    n_search = n_zero = 0
    zero_runs: list[str] = []
    zero_run_set: set[str] = set()
    zero_examples: list[dict[str, Any]] = []
    zero_queries: Counter[str] = Counter()
    n_refs = 0
    fetch_runs: set[str] = set()
    fetch_run_ids: list[str] = []
    fetch_by_error: Counter[str] = Counter()
    fetch_examples: list[dict[str, Any]] = []
    n_fetch_fail = 0
    actors: dict[str, _Group] = defaultdict(_Group)
    actor_extra: dict[str, dict[str, Any]] = {}
    n_checks = n_check_fail = 0
    check_runs: set[str] = set()
    check_run_ids: list[str] = []
    check_reasons: Counter[str] = Counter()
    retry_n = 0
    retry_runs: set[str] = set()
    retry_run_ids: list[str] = []
    retry_reasons: Counter[str] = Counter()
    no_events = 0
    has_events: dict[str, bool] = {}
    # per-run facts needed for cohorts (derived from events)
    run_has_lint_error: dict[str, bool] = {}

    for r in rows:
        events = loader(r.run_id)
        has_events[r.run_id] = events is not None
        if events is None:
            no_events += 1
            # fall back to index columns so rule/judge presence is still counted per run
            for sev, ids in (("error", r.error_rule_ids), ("warn", r.warn_rule_ids)):
                for rid in ids:
                    rules[sev][rid].runs.add(r.run_id)
                    _add_run(rules[sev][rid].run_ids, r.run_id)
            for item in r.judge_fail_items:
                judge_items[item].runs.add(r.run_id)
                _add_run(judge_items[item].run_ids, r.run_id)
            run_has_lint_error[r.run_id] = bool(r.error_rule_ids)
            continue
        lint_err = False
        for ev in events:
            name = ev.get("event")
            if name == "lint_result":
                for f in ev.get("findings") or []:
                    sev = str(f.get("severity", "")).upper()
                    rid = f.get("rule_id")
                    if not rid or sev not in ("ERROR", "WARN"):
                        continue
                    lint_err |= sev == "ERROR"
                    rules[sev.lower()][str(rid)].hit(
                        r.run_id,
                        {
                            "run_id": r.run_id,
                            "domain": ev.get("domain"),
                            "attempt": ev.get("attempt"),
                            "message": _cap(f.get("message")),
                            "target": f.get("target"),
                        },
                    )
            elif name == "judge_verdict":
                n_verdicts += 1
                n_rejected += ev.get("approved") is False
                for it in ev.get("items") or []:
                    nm = it.get("name")
                    if not nm:
                        continue
                    judge_seen[str(nm)] += 1
                    if it.get("passed") is False:
                        judge_items[str(nm)].hit(
                            r.run_id,
                            {
                                "run_id": r.run_id,
                                "domain": ev.get("domain"),
                                "attempt": ev.get("attempt"),
                                "rationale": _cap(it.get("rationale")),
                            },
                        )
            elif name == "search":
                n_search += 1
                if not ev.get("returned_ids"):
                    n_zero += 1
                    zero_run_set.add(r.run_id)
                    _add_run(zero_runs, r.run_id)
                    zero_queries[str(ev.get("query", ""))] += 1
                    if len(zero_examples) < EXAMPLE_CAP:
                        zero_examples.append(
                            {
                                "run_id": r.run_id,
                                "tool": ev.get("tool"),
                                "query": _cap(ev.get("query"), 200),
                                "k": ev.get("k"),
                            }
                        )
            elif name == "reference_fetch":
                n_refs += 1
            elif name == "reference_fetch_failed":
                n_refs += 1
                n_fetch_fail += 1
                fetch_runs.add(r.run_id)
                _add_run(fetch_run_ids, r.run_id)
                fetch_by_error[_cap(ev.get("error"), 120)] += 1
                if len(fetch_examples) < EXAMPLE_CAP:
                    fetch_examples.append(
                        {
                            "run_id": r.run_id,
                            "source_name": ev.get("source_name"),
                            "url": ev.get("url"),
                            "error": _cap(ev.get("error"), 200),
                        }
                    )
            elif name == "unmatched_actor":
                actor = str(ev.get("actor", "?"))
                g = actors[actor]
                g.hit(r.run_id)
                actor_extra.setdefault(
                    actor,
                    {
                        "example_quote": _cap(ev.get("quote")),
                        "example_source_name": ev.get("source_name"),
                    },
                )
            elif name == "group_quote_check":
                n_checks += 1
                if ev.get("passed") is False:
                    n_check_fail += 1
                    check_runs.add(r.run_id)
                    _add_run(check_run_ids, r.run_id)
                    check_reasons[_cap(ev.get("reason"), 160)] += 1
            elif name == "retry":
                retry_n += 1
                retry_runs.add(r.run_id)
                _add_run(retry_run_ids, r.run_id)
                retry_reasons[_cap(ev.get("reason"), 160)] += 1
        run_has_lint_error[r.run_id] = lint_err

    # ---- terminal states
    states = Counter(r.terminal_state for r in rows)
    state_runs: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        _add_run(state_runs[r.terminal_state], r.run_id)
    detail = [
        {
            "state": s,
            "n_runs": c,
            "share_of_runs": _share(c, n),
            "run_ids": state_runs[s],
        }
        for s, c in sorted(states.items(), key=lambda kv: (kv[0] == "minted", -kv[1], kv[0]))
    ]

    def rule_list(sev: str, label: str) -> list[dict[str, Any]]:
        out = [
            {
                "rule_id": rid,
                "severity": label,
                "n_findings": g.count,
                "n_runs": len(g.runs),
                "share_of_runs": _share(len(g.runs), n),
                "run_ids": g.run_ids,
                "examples": g.examples,
            }
            for rid, g in rules[sev].items()
        ]
        return sorted(out, key=lambda d: (-d["n_runs"], -d["n_findings"], d["rule_id"]))

    judge_list = sorted(
        (
            {
                "item": nm,
                "n_failed": g.count,
                "n_verdicts": judge_seen.get(nm, 0),
                "fail_rate": _rate(g.count, judge_seen.get(nm, 0)),
                "n_runs": len(g.runs),
                "share_of_runs": _share(len(g.runs), n),
                "run_ids": g.run_ids,
                "examples": g.examples,
            }
            for nm, g in judge_items.items()
        ),
        key=lambda d: (-d["n_runs"], -d["n_failed"], d["item"]),
    )

    actor_list = sorted(
        (
            {
                "actor": a,
                "count": g.count,
                "n_runs": len(g.runs),
                "share_of_runs": _share(len(g.runs), n),
                "run_ids": g.run_ids,
                **actor_extra[a],
            }
            for a, g in actors.items()
        ),
        key=lambda d: (-d["n_runs"], -d["count"], d["actor"]),
    )

    def top(c: Counter[str], key: str) -> list[dict[str, Any]]:
        return [
            {key: k, "count": v}
            for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:_TOP_CAP]
        ]

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window": {
            "n_runs": n,
            "since": since,
            "last": last,
            "first_ts": rows[0].ts if rows else None,
            "last_ts": rows[-1].ts if rows else None,
            "first_run_id": rows[0].run_id if rows else None,
            "last_run_id": rows[-1].run_id if rows else None,
            "runs_without_events": no_events,
        },
        "terminal_states": dict(states),
        "terminal_state_detail": detail,
        "rules": {"error": rule_list("error", "ERROR"), "warn": rule_list("warn", "WARN")},
        "judge_items": judge_list,
        "judge": {
            "n_verdicts": n_verdicts,
            "n_rejected": n_rejected,
            "reject_rate": _rate(n_rejected, n_verdicts),
        },
        "searches": {
            "n_searches": n_search,
            "n_zero_hit": n_zero,
            "zero_hit_rate": _rate(n_zero, n_search),
            "n_runs_with_zero_hit": len(zero_run_set),
            "share_of_runs": _share(len(zero_run_set), n),
            "run_ids": zero_runs,
            "example_queries": zero_examples,
            "top_zero_hit_queries": top(zero_queries, "query"),
        },
        "fetch": {
            "n_references": n_refs,
            "n_failures": n_fetch_fail,
            "failure_rate": _rate(n_fetch_fail, n_refs),
            "n_runs": len(fetch_runs),
            "share_of_runs": _share(len(fetch_runs), n),
            "run_ids": fetch_run_ids,
            "by_error": top(fetch_by_error, "error"),
            "examples": fetch_examples,
        },
        "unmatched_actors": actor_list,
        "group_quote_checks": {
            "n_checks": n_checks,
            "n_failed": n_check_fail,
            "fail_rate": _rate(n_check_fail, n_checks),
            "n_runs_failed": len(check_runs),
            "run_ids": check_run_ids,
            "by_reason": top(check_reasons, "reason"),
        },
        "retries": {
            "n_retries": retry_n,
            "n_runs": len(retry_runs),
            "share_of_runs": _share(len(retry_runs), n),
            "run_ids": retry_run_ids,
            "by_reason": top(retry_reasons, "reason"),
        },
        "reviews": _reviews(rows),
        "eval": _eval_trend(rows),
    }
    cohorts = _cohorts(rows, run_has_lint_error)
    report["cohorts"] = cohorts
    report["cohort_comparison"] = _comparison(cohorts)
    surfaces: dict[str, dict[str, Any]] = {}
    for r in rows:
        s = surfaces.setdefault(r.surface, {"n_runs": 0, "terminal_states": Counter()})
        s["n_runs"] += 1
        s["terminal_states"][r.terminal_state] += 1
    report["by_surface"] = {
        k: {"n_runs": v["n_runs"], "terminal_states": dict(v["terminal_states"])}
        for k, v in sorted(surfaces.items())
    }
    report["runs"] = [
        {
            "run_id": r.run_id,
            "ts": r.ts,
            "software_name": r.software_name,
            "surface": r.surface,
            "terminal_state": r.terminal_state,
            "git_sha": _short(r.git_sha),
            "prompt_sha256": r.prompt_sha256[:12],
            "error_rule_ids": r.error_rule_ids,
            "warn_rule_ids": r.warn_rule_ids,
            "judge_fail_items": r.judge_fail_items,
            "eval_case": r.eval_case,
            "has_events": has_events.get(r.run_id, False),
        }
        for r in rows[-_RUNS_LIST_CAP:]
    ]
    return report


# --------------------------------------------------------------------------- sections


def _review_totals(rows: Iterable[RunRecord]) -> dict[str, Any]:
    tot = Counter[str]()
    n = 0
    for r in rows:
        rv = r.review
        if not rv:
            continue
        n += 1
        for k in (
            "n_techniques_accepted",
            "n_techniques_rejected",
            "n_groups_accepted",
            "n_groups_rejected",
            "n_missed_techniques",
            "n_missed_groups",
        ):
            tot[k] += int(rv.get(k) or 0)
    acc = tot["n_techniques_accepted"] + tot["n_groups_accepted"]
    rej = tot["n_techniques_rejected"] + tot["n_groups_rejected"]
    missed = tot["n_missed_techniques"] + tot["n_missed_groups"]
    return {
        "n_reviewed": n,
        "techniques_accepted": tot["n_techniques_accepted"],
        "techniques_rejected": tot["n_techniques_rejected"],
        "groups_accepted": tot["n_groups_accepted"],
        "groups_rejected": tot["n_groups_rejected"],
        "missed_techniques": tot["n_missed_techniques"],
        "missed_groups": tot["n_missed_groups"],
        "precision": round(acc / (acc + rej), 4) if acc + rej else None,
        "recall": round(acc / (acc + missed), 4) if acc + missed else None,
    }


def _reviews(rows: Sequence[RunRecord]) -> dict[str, Any]:
    out = _review_totals(rows)
    rejected: dict[str, _Group] = defaultdict(_Group)
    missed: dict[str, _Group] = defaultdict(_Group)
    for r in rows:
        rv = r.review or {}
        for key in ("rejected_techniques", "rejected_groups"):
            for i in rv.get(key) or []:
                rejected[str(i)].hit(r.run_id)
        for key in ("missed_techniques", "missed_groups"):
            for i in rv.get(key) or []:
                missed[str(i)].hit(r.run_id)

    def ranked(d: dict[str, _Group]) -> list[dict[str, Any]]:
        return [
            {"id": k, "count": g.count, "run_ids": g.run_ids}
            for k, g in sorted(d.items(), key=lambda kv: (-kv[1].count, kv[0]))[:_TOP_CAP]
        ]

    out["most_rejected"] = ranked(rejected)
    out["most_missed"] = ranked(missed)
    return out


def _eval_trend(rows: Sequence[RunRecord]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if r.eval_scores is None:
            continue
        out.setdefault(r.eval_case or "unknown", []).append(
            {
                "run_id": r.run_id,
                "ts": r.ts,
                "git_sha": _short(r.git_sha),
                "prompt_sha256": r.prompt_sha256[:12],
                "scores": r.eval_scores,
            }
        )
    return out


def _cohorts(rows: Sequence[RunRecord], lint_err: Mapping[str, bool]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[RunRecord]] = {}
    for r in rows:
        groups.setdefault((r.prompt_sha256[:12], _short(r.git_sha)), []).append(r)
    cohorts: list[dict[str, Any]] = []
    for (psha, gsha), rs in groups.items():
        k = len(rs)
        m: dict[str, float | None] = {
            "minted_rate": _rate(sum(r.terminal_state == "minted" for r in rs), k),
            "terminal_ok_rate": _rate(sum(r.terminal_state in ("minted", "declined") for r in rs), k),
            "lint_error_run_share": _rate(sum(lint_err.get(r.run_id, False) for r in rs), k),
            "mean_attempts": _mean([float(sum(r.attempts.values())) for r in rs]),
            "mean_model_calls": _mean([float(r.n_model_calls) for r in rs]),
            "mean_wall_s": _mean([float(r.wall_s) for r in rs]),
            "zero_hit_per_run": _mean([float(r.zero_hit_queries) for r in rs]),
            "fetch_failures_per_run": _mean([float(r.fetch_failures) for r in rs]),
            "unmatched_actors_per_run": _mean([float(r.unmatched_actors) for r in rs]),
            "judge_fail_runs_share": _rate(sum(bool(r.judge_fail_items) for r in rs), k),
        }
        rv = _review_totals(rs)
        m["review_precision"] = rv["precision"]
        m["review_recall"] = rv["recall"]
        by_key: dict[str, list[float]] = defaultdict(list)
        for r in rs:
            if r.eval_scores is not None:
                for key, val in _flat_numeric(r.eval_scores).items():
                    by_key[f"eval.{r.eval_case or 'unknown'}.{key}"].append(val)
        for key in sorted(by_key):
            m[key] = _mean(by_key[key])
        cohorts.append(
            {
                "prompt_sha256": psha,
                "git_sha": gsha,
                "n_runs": k,
                "first_ts": min(r.ts for r in rs),
                "last_ts": max(r.ts for r in rs),
                "run_ids": [r.run_id for r in rs[-RUN_CAP:]],
                "terminal_states": dict(Counter(r.terminal_state for r in rs)),
                "metrics": m,
            }
        )
    return sorted(cohorts, key=lambda c: c["first_ts"])


def _comparison(cohorts: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for a, b in zip(cohorts, cohorts[1:], strict=False):
        diff = {
            k: round(b["metrics"][k] - a["metrics"][k], 4)
            for k in b["metrics"]
            if k in a["metrics"] and a["metrics"][k] is not None and b["metrics"][k] is not None
        }
        out.append(
            {
                "from": {"prompt_sha256": a["prompt_sha256"], "git_sha": a["git_sha"]},
                "to": {"prompt_sha256": b["prompt_sha256"], "git_sha": b["git_sha"]},
                "diff": diff,
            }
        )
    return out


# --------------------------------------------------------------------------- text


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def render_text(rep: Mapping[str, Any], *, examples: int = 1) -> str:
    """Compact human rendering of :func:`build_report` output."""
    w = rep["window"]
    L: list[str] = [
        f"runs: {w['n_runs']}"
        + (f" ({w['first_ts']} .. {w['last_ts']})" if w["n_runs"] else "")
        + (f"  [{w['runs_without_events']} without events]" if w["runs_without_events"] else "")
    ]
    if not w["n_runs"]:
        return "\n".join(L)
    L.append("terminal states: " + ", ".join(f"{k}={v}" for k, v in rep["terminal_states"].items()))
    for d in rep["terminal_state_detail"]:
        if d["state"] != "minted":
            L.append(f"  {d['state']}: {', '.join(d['run_ids'][:3])}")
    for label, key in (("ERROR rules", "error"), ("WARN rules", "warn")):
        rs = rep["rules"][key]
        L.append(f"{label}: " + ("none" if not rs else ""))
        for r in rs[:8]:
            L.append(
                f"  {r['rule_id']}  {r['n_runs']} runs ({_pct(r['share_of_runs'])}), "
                f"{r['n_findings']} findings; e.g. {_cap(r['examples'][0]['message'], 90) if r['examples'] else '-'}"
            )
    ji = rep["judge_items"]
    L.append(
        f"judge: {rep['judge']['n_rejected']}/{rep['judge']['n_verdicts']} verdicts rejected"
        + ("" if ji else "; no failed items")
    )
    for j in ji[:6]:
        L.append(
            f"  {j['item']}  fail {j['n_failed']}/{j['n_verdicts']} ({_pct(j['fail_rate'])}) "
            f"in {j['n_runs']} runs"
        )
    s = rep["searches"]
    L.append(
        f"zero-hit searches: {s['n_zero_hit']}/{s['n_searches']} ({_pct(s['zero_hit_rate'])}), "
        f"{s['n_runs_with_zero_hit']} runs"
    )
    for q in s["top_zero_hit_queries"][: 3 * examples]:
        L.append(f"  {q['count']}x {_cap(q['query'], 80)!r}")
    f = rep["fetch"]
    L.append(
        f"fetch failures: {f['n_failures']}/{f['n_references']} ({_pct(f['failure_rate'])}), "
        f"{f['n_runs']} runs"
    )
    for e in f["by_error"][:3]:
        L.append(f"  {e['count']}x {e['error']}")
    ua = rep["unmatched_actors"]
    L.append(f"unmatched actors: {sum(a['count'] for a in ua)}" + ("" if ua else " none"))
    for a in ua[:5]:
        L.append(f"  {a['actor']}  {a['count']}x in {a['n_runs']} runs")
    g = rep["group_quote_checks"]
    if g["n_checks"]:
        L.append(f"group quote checks failed: {g['n_failed']}/{g['n_checks']}")
        for e in g["by_reason"][:3]:
            L.append(f"  {e['count']}x {e['reason']}")
    t = rep["retries"]
    if t["n_retries"]:
        L.append(f"retries: {t['n_retries']} in {t['n_runs']} runs")
        for e in t["by_reason"][:3]:
            L.append(f"  {e['count']}x {e['reason']}")
    rv = rep["reviews"]
    if rv["n_reviewed"]:
        L.append(
            f"reviews: {rv['n_reviewed']} runs; precision {rv['precision']}; recall {rv['recall']}"
        )
        for key, label in (("most_rejected", "rejected"), ("most_missed", "missed")):
            if rv[key]:
                L.append(f"  {label}: " + ", ".join(f"{e['id']}x{e['count']}" for e in rv[key][:6]))
    if rep["eval"]:
        L.append("eval: " + ", ".join(f"{c}={len(v)} runs" for c, v in rep["eval"].items()))
    L.append("by prompt_sha256 / git_sha:")
    for c in rep["cohorts"]:
        mt = c["metrics"]
        L.append(
            f"  {c['prompt_sha256']} {c['git_sha']}: {c['n_runs']} runs, "
            f"minted {_pct(mt['minted_rate'] or 0)}, lint-error runs {_pct(mt['lint_error_run_share'] or 0)}, "
            f"zero-hit/run {mt['zero_hit_per_run']}"
        )
    if rep["cohort_comparison"]:
        cmp = rep["cohort_comparison"][-1]
        parts = [f"{k} {v:+g}" for k, v in cmp["diff"].items() if v and not k.startswith("eval.")]
        L.append(
            f"latest vs previous cohort ({cmp['from']['git_sha']} -> {cmp['to']['git_sha']}): "
            + (", ".join(parts[:8]) or "no change")
        )
    if len(rep["by_surface"]) > 1:
        L.append(
            "by surface: " + ", ".join(f"{k}={v['n_runs']}" for k, v in rep["by_surface"].items())
        )
    for r in rep["runs"]:
        L.append(f"  - {r['run_id']}  {r['software_name']}  {r['terminal_state']}")
    return "\n".join(L)
