"""Read-only view of the pinned ATT&CK bundles, built on ``MitreAttackData``.

Nothing here mutates a bundle; every method returns deep copies of plain JSON
dicts so callers cannot corrupt the cache. ATT&CK ids are not unique within a
bundle, so every lookup is type-scoped. Liveness (``revoked`` or
``x_mitre_deprecated``) is a store invariant: inactive objects are hidden
unless ``include_inactive=True``, and a revoked id redirects to its successor.
"""

from __future__ import annotations

import copy
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mitreattack.stix20 import MitreAttackData

from mitre_mapper.holdout import HoldoutReport, HoldoutSpec, apply_holdout

_ATTACK_SOURCE = re.compile(r"^mitre-.*attack$")
_MAX_REDIRECTS = 5


def is_inactive(obj: dict[str, Any]) -> bool:
    """True when the object is revoked or deprecated."""
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _fold(name: str) -> str:
    return " ".join(name.casefold().split())


@dataclass
class Lookup:
    obj: dict[str, Any] | None
    redirected_from: str | None = None  # revoked ATT&CK id we followed
    inactive: bool = False  # True only for a dead object returned via include_inactive


class DomainStore:
    """One ATT&CK domain bundle."""

    def __init__(self, domain: str, bundle_path: Path, holdout: HoldoutSpec | None = None) -> None:
        self.domain = domain
        self.bundle_path = Path(bundle_path)
        self.holdout = holdout
        self.holdout_report: HoldoutReport | None = None
        bundle = json.loads(self.bundle_path.read_text(encoding="utf-8"))
        raw = bundle["objects"]
        if holdout is None:
            self.data = MitreAttackData(str(self.bundle_path))
        else:  # eval: hide the answer before anything (incl. MitreAttackData) can see it
            raw, self.holdout_report = apply_holdout(raw, holdout, domain)
            with tempfile.TemporaryDirectory() as tmp:
                held = Path(tmp) / self.bundle_path.name
                held.write_text(json.dumps({**bundle, "objects": raw}), encoding="utf-8")
                self.data = MitreAttackData(str(held))
        self._by_stix: dict[str, dict[str, Any]] = {o["id"]: o for o in raw}
        self._group_names: dict[str, list[dict[str, Any]]] | None = None
        self._by_attack: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for obj in raw:
            attack_id = self.attack_id(obj)
            if attack_id:
                self._by_attack.setdefault((obj["type"], attack_id), []).append(obj)

    @property
    def cache_key(self) -> str:
        """Identity for per-bundle caches: the bundle path plus the holdout, if any."""
        base = str(self.bundle_path.resolve())
        return base if self.holdout is None else f"{base}#holdout={self.holdout.name}"

    @staticmethod
    def attack_id(obj: dict[str, Any]) -> str | None:
        """External id from the first ``mitre-*attack`` reference."""
        for ref in obj.get("external_references", []):
            if _ATTACK_SOURCE.match(ref.get("source_name", "")):
                return ref.get("external_id")
        return None

    def get_by_stix_id(self, stix_id: str) -> dict[str, Any] | None:
        obj = self._by_stix.get(stix_id)
        return copy.deepcopy(obj) if obj else None

    def objects(self, stix_type: str, include_inactive: bool = False) -> list[dict[str, Any]]:
        return [
            copy.deepcopy(o)
            for o in self._by_stix.values()
            if o["type"] == stix_type and (include_inactive or not is_inactive(o))
        ]

    def lookup(self, attack_id: str, stix_type: str, include_inactive: bool = False) -> Lookup:
        """Find an object by ATT&CK id and type, following ``revoked-by`` for dead ids."""
        candidates = self._by_attack.get((stix_type, attack_id), [])
        live = [o for o in candidates if not is_inactive(o)]
        if live:
            return Lookup(copy.deepcopy(live[0]))
        if not candidates:
            return Lookup(None)
        dead = candidates[0]
        if include_inactive:
            return Lookup(copy.deepcopy(dead), inactive=True)
        current = dead
        for _ in range(_MAX_REDIRECTS):
            if not current.get("revoked"):
                return Lookup(None)  # deprecated, no successor
            successor = self.data.get_revoking_object(current["id"])
            if successor is None:
                return Lookup(None)
            current = self._by_stix[successor["id"]]
            if not is_inactive(current):
                return Lookup(copy.deepcopy(current), redirected_from=attack_id)
        return Lookup(None)

    @staticmethod
    def group_names(obj: dict[str, Any]) -> list[str]:
        """Group name followed by its aliases, de-duplicated, order preserved."""
        seen: dict[str, None] = {}
        for name in [obj.get("name", ""), *obj.get("aliases", [])]:
            if name:
                seen.setdefault(name, None)
        return list(seen)

    def _groups_by_name(self) -> dict[str, list[dict[str, Any]]]:
        """Casefolded, whitespace-normalised name/alias -> intrusion-sets (live and dead)."""
        if self._group_names is None:
            index: dict[str, list[dict[str, Any]]] = {}
            for obj in self._by_stix.values():
                if obj["type"] != "intrusion-set":
                    continue
                for name in self.group_names(obj):
                    index.setdefault(_fold(name), []).append(obj)
            self._group_names = index
        return self._group_names

    def resolve_group(self, name: str) -> dict[str, Any] | None:
        """Active group whose name or alias equals ``name`` (case-insensitive).

        An exact *name* match beats an alias match; remaining ties (real aliases
        collide, e.g. ``UAC-0056``) go to the lowest ATT&CK id. If only a revoked
        group matches, its ``revoked-by`` successor is returned. Deprecated groups
        with no successor are never returned.
        """
        matches = self._groups_by_name().get(_fold(name), [])

        def rank(o: dict[str, Any]) -> tuple[bool, str]:
            return (_fold(o["name"]) != _fold(name), self.attack_id(o) or "")

        live = sorted((o for o in matches if not is_inactive(o)), key=rank)
        if live:
            return copy.deepcopy(live[0])
        for dead in sorted(matches, key=rank):
            attack_id = self.attack_id(dead)
            if dead.get("revoked") and attack_id:
                found = self.lookup(attack_id, "intrusion-set")
                if found.obj is not None:
                    return found.obj
        return None

    def software_techniques(self, attack_id: str) -> list[str]:
        """ATT&CK ids of active techniques used by the software, sorted."""
        for stix_type in ("malware", "tool"):
            software = self.lookup(attack_id, stix_type).obj
            if software:
                used = self.data.get_techniques_used_by_software(software["id"])
                ids = {
                    self.attack_id(self._by_stix[u["object"]["id"]])
                    for u in used
                    if not is_inactive(self._by_stix[u["object"]["id"]])
                }
                return sorted(i for i in ids if i)
        return []


class AttackStore:
    """Lazy, cached per-domain stores. ``holdout`` (PLAN 4.2) hides eval answers at load time."""

    def __init__(self, datasets_dir: Path, holdout: HoldoutSpec | None = None) -> None:
        self.datasets_dir = Path(datasets_dir)
        self.holdout = holdout
        self._domains: dict[str, DomainStore] = {}

    def domain(self, domain: str) -> DomainStore:
        if domain not in self._domains:
            path = self.datasets_dir / f"{domain}.json"
            if not path.exists():
                raise FileNotFoundError(f"no dataset for domain {domain!r}: {path}")
            self._domains[domain] = DomainStore(domain, path, self.holdout)
        return self._domains[domain]


_STORES: dict[tuple[Path, HoldoutSpec | None], AttackStore] = {}


def get_store(datasets_dir: Path, holdout: HoldoutSpec | None = None) -> AttackStore:
    """Process-wide cache of :class:`AttackStore` per (datasets directory, holdout).

    A held-out store is cached separately from the plain one, so an eval can score against
    the latter while the agent only ever sees the former.
    """
    key = (Path(datasets_dir).resolve(), holdout)
    if key not in _STORES:
        _STORES[key] = AttackStore(key[0], holdout)
    return _STORES[key]
