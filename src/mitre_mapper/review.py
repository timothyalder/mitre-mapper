"""User reviews of runs (PLAN 3.9): ``runs/<id>/review.json`` + an index ``ReviewRecord``.

The review is *derived against the run's final mapping*, which is read from the run's
``mint`` event (never from separate state). ``record_review`` writes ``review.json`` and
appends a ``ReviewRecord`` line to ``runs/index.jsonl``; ``runlog.read_index`` joins the
latest record per run into ``RunRecord.review`` (the summary dict below).

Summary keys (``ReviewRecord.summary``; every key always present)::

    reviewer, notes, has_mint (bool: run had a mint event; False -> everything is "missed")
    n_techniques_accepted, n_techniques_rejected, n_groups_accepted, n_groups_rejected
    n_missed_techniques, n_missed_groups
    n_unreviewed          minted agent-proposed items the reviewer did not mark
    rejected_techniques, rejected_groups, missed_techniques, missed_groups   (id lists)
    precision             accepted / (accepted + rejected) over agent-proposed items, or null
    recall                accepted / (accepted + missed), or null

User-asserted items (``user_asserted`` in the mint event) are excluded from precision and
recall: the reviewer did not need to judge what the user themselves asserted.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from mitre_mapper.models import Review, ReviewRecord
from mitre_mapper.runlog import append_index

__all__ = [
    "MintedItem",
    "ReviewError",
    "RunMapping",
    "load_mapping",
    "load_review_file",
    "record_review",
    "summarize_review",
]


class ReviewError(Exception):
    """Unknown run, malformed review file, ..."""


@dataclass
class MintedItem:
    """One technique/group of the run's final mapping."""

    id: str
    name: str
    user_asserted: bool = False


@dataclass
class RunMapping:
    """The run's final mapping, from its (last) ``mint`` event."""

    has_mint: bool = False
    techniques: list[MintedItem] = field(default_factory=list)
    groups: list[MintedItem] = field(default_factory=list)


def _now_ts() -> str:
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _read_events(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _items(by_domain: Mapping[str, Any] | None) -> list[MintedItem]:
    seen: dict[str, MintedItem] = {}
    for _domain, entries in sorted((by_domain or {}).items()):
        for e in entries or []:
            iid = str(e.get("id"))
            prev = seen.get(iid)
            asserted = bool(e.get("user_asserted"))
            if prev is None:
                seen[iid] = MintedItem(iid, str(e.get("name", "")), asserted)
            else:  # same id in two domains: asserted only if asserted everywhere
                prev.user_asserted = prev.user_asserted and asserted
    return list(seen.values())


def load_mapping(run_dir: Path) -> RunMapping:
    """Final mapping of a run from its last ``mint`` event (empty if it never minted)."""
    mint = next(
        (e for e in reversed(_read_events(run_dir / "events.jsonl")) if e.get("event") == "mint"),
        None,
    )
    if mint is None:
        return RunMapping()
    return RunMapping(True, _items(mint.get("techniques")), _items(mint.get("groups")))


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def summarize_review(review: Review, mapping: RunMapping) -> dict[str, Any]:
    """Fold a review + the run's mapping into the index summary (see module docstring)."""
    agent_t = {i.id for i in mapping.techniques if not i.user_asserted}
    agent_g = {i.id for i in mapping.groups if not i.user_asserted}
    t_acc = sorted(t for t, v in review.techniques.items() if v == "accepted" and t in agent_t)
    t_rej = sorted(t for t, v in review.techniques.items() if v == "rejected" and t in agent_t)
    g_acc = sorted(g for g, v in review.groups.items() if v == "accepted" and g in agent_g)
    g_rej = sorted(g for g, v in review.groups.items() if v == "rejected" and g in agent_g)
    unreviewed = (agent_t - set(review.techniques)) | (agent_g - set(review.groups))
    missed_t = sorted(set(review.missed_techniques))
    missed_g = sorted(set(review.missed_groups))
    accepted = len(t_acc) + len(g_acc)
    rejected = len(t_rej) + len(g_rej)
    missed = len(missed_t) + len(missed_g)
    return {
        "reviewer": review.reviewer,
        "notes": review.notes,
        "has_mint": mapping.has_mint,
        "n_techniques_accepted": len(t_acc),
        "n_techniques_rejected": len(t_rej),
        "n_groups_accepted": len(g_acc),
        "n_groups_rejected": len(g_rej),
        "n_missed_techniques": len(missed_t),
        "n_missed_groups": len(missed_g),
        "n_unreviewed": len(unreviewed),
        "rejected_techniques": t_rej,
        "rejected_groups": g_rej,
        "missed_techniques": missed_t,
        "missed_groups": missed_g,
        "precision": _ratio(accepted, accepted + rejected),
        "recall": _ratio(accepted, accepted + missed),
    }


def load_review_file(path: Path, run_id: str) -> Review:
    """Parse a non-interactive review file; ``run_id``/``ts`` default sensibly."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ReviewError(f"{path}: expected a JSON object")
        if data.get("run_id") not in (None, run_id):
            raise ReviewError(f"{path}: run_id {data['run_id']!r} does not match {run_id!r}")
        data["run_id"] = run_id
        data.setdefault("ts", _now_ts())
        return Review.model_validate(data)
    except (OSError, ValueError, ValidationError) as exc:
        if isinstance(exc, ReviewError):
            raise
        raise ReviewError(f"{path}: {exc}") from exc


def record_review(runs_dir: Path | str, run_id: str, review: Review) -> dict[str, Any]:
    """Write ``runs/<id>/review.json`` and append a ``ReviewRecord``; return the summary."""
    run_dir = Path(runs_dir) / run_id
    if not (run_dir / "events.jsonl").is_file():
        raise ReviewError(f"no such run: {run_dir}")
    if review.run_id != run_id:
        review = review.model_copy(update={"run_id": run_id})
    summary = summarize_review(review, load_mapping(run_dir))
    (run_dir / "review.json").write_text(review.model_dump_json(indent=2) + "\n", encoding="utf-8")
    append_index(runs_dir, ReviewRecord(run_id=run_id, ts=review.ts, summary=summary))
    return summary
