"""Eval holdouts (PLAN 4.2): hide the answer from the store by *predicate*, not by list.

A :class:`HoldoutSpec` is applied once, when a domain bundle is loaded
(``AttackStore(holdout=...)``): every object whose name / aliases / description /
external references match ``pattern`` is dropped, so are the objects named in ``drop``
and every relationship left dangling. Relationships whose own text matches but whose
endpoints survive (e.g. ``Dragonfly -> Password Cracking`` naming CrackMapExec) are
*masked*: removed, and reported by id.

The patterns are anchored on purpose. ``\\bnso\\b`` keeps T1430 ("Insomnia" in its
text) and T1660 ("sensors"); an unanchored ``nso`` deletes both.

Pure functions, no I/O, no LangChain.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

_ATTACK_SOURCE = re.compile(r"^mitre-.*attack$")


@dataclass(frozen=True)
class HoldoutSpec:
    """What to hide from the store. Frozen so it can key the store cache."""

    name: str
    pattern: str  # regex over name/aliases/description/external_references of every object
    drop: tuple[tuple[str, str], ...] = ()  # (stix type, ATT&CK id) removed even if the pattern misses
    description: str = ""

    @property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern)

    def searchable_text(self, obj: dict[str, Any]) -> str:
        """The fields the predicate looks at (the leakage probes use the same text)."""
        parts: list[str] = [
            obj.get("name", ""),
            *obj.get("aliases", []),
            *obj.get("x_mitre_aliases", []),
            obj.get("description", "") or "",
        ]
        for ref in obj.get("external_references", []):
            parts += [
                ref.get("source_name", "") or "",
                ref.get("description", "") or "",
                ref.get("url", "") or "",
                ref.get("external_id", "") or "",
            ]
        return "\n".join(parts)

    def matches(self, obj: dict[str, Any]) -> bool:
        return self.regex.search(self.searchable_text(obj)) is not None


@dataclass
class HoldoutReport:
    """What a holdout removed from one domain bundle (logged as a ``merge`` kind=holdout event)."""

    holdout: str
    domain: str
    n_before: int = 0
    n_after: int = 0
    removed_by_type: dict[str, int] = field(default_factory=dict)
    removed_objects: list[str] = field(default_factory=list)  # "<type> <attack id> <name>" for non-relationships
    masked_relationship_ids: list[str] = field(default_factory=list)  # own text matched, endpoints survived

    def to_event(self) -> dict[str, Any]:
        return {
            "name": self.holdout,
            "domain": self.domain,
            "n_before": self.n_before,
            "n_after": self.n_after,
            "removed_by_type": dict(sorted(self.removed_by_type.items())),
            "removed_objects": self.removed_objects,
            "masked_relationship_ids": self.masked_relationship_ids,
        }


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if _ATTACK_SOURCE.match(ref.get("source_name", "")):
            return ref.get("external_id")
    return None


def apply_holdout(
    objects: list[dict[str, Any]], spec: HoldoutSpec, domain: str
) -> tuple[list[dict[str, Any]], HoldoutReport]:
    """Return ``(kept objects, report)``. The input list is not modified."""
    drop_ids = set(spec.drop)
    removed: dict[str, dict[str, Any]] = {}
    matched_relationships: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj["type"] == "relationship":
            if spec.matches(obj):
                matched_relationships[obj["id"]] = obj
            continue
        if spec.matches(obj) or (obj["type"], _attack_id(obj) or "") in drop_ids:
            removed[obj["id"]] = obj
    kept: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    masked: list[str] = []
    for obj in objects:
        if obj["id"] in removed:
            counts[obj["type"]] += 1
            continue
        if obj["type"] == "relationship":
            dangling = obj["source_ref"] in removed or obj["target_ref"] in removed
            if dangling or obj["id"] in matched_relationships:
                counts["relationship"] += 1
                if not dangling:
                    masked.append(obj["id"])
                continue
        kept.append(obj)
    names = sorted(
        f"{o['type']} {_attack_id(o) or '-'} {o.get('name', '')}".strip() for o in removed.values()
    )
    report = HoldoutReport(
        holdout=spec.name,
        domain=domain,
        n_before=len(objects),
        n_after=len(kept),
        removed_by_type=dict(counts),
        removed_objects=names,
        masked_relationship_ids=sorted(masked),
    )
    return kept, report


PEGASUS = HoldoutSpec(
    name="pegasus",
    pattern=r"(?i)pegasus|chrysaor|\bnso\b",
    drop=(("malware", "S0316"),),
    description=(
        "Pegasus for iOS (S0289) eval: drops S0289, S0316 (Pegasus for Android, Jaccard 0.32), the "
        "Chrysaor alias, Confucius and the enterprise T1583/T1584/T1588 citations that name Pegasus."
    ),
)

CRACKMAPEXEC = HoldoutSpec(
    name="crackmapexec",
    pattern=r"(?i)crack\s*map\s*exec",
    drop=(("tool", "S0488"),),
    description=(
        "CrackMapExec (S0488) eval: drops S0488, its relationships and masks the 4 group->technique "
        "relationships that name it (Dragonfly T1110.002/T1588.002, APT39 T1046/T1135)."
    ),
)

HOLDOUTS: dict[str, HoldoutSpec] = {h.name: h for h in (PEGASUS, CRACKMAPEXEC)}


def get_holdout(name: str) -> HoldoutSpec:
    try:
        return HOLDOUTS[name]
    except KeyError:
        raise KeyError(f"unknown holdout {name!r}; known: {sorted(HOLDOUTS)}") from None
