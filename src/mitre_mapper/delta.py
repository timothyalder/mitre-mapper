"""Deltas: load, combine, materialize into patched bundles, and ``doctor``.

A delta (``runs/<id>/delta.json``) holds only new objects. ``combine`` merges several by STIX id
(ids are deterministic, so a user-defined group shared by two intake files collapses to one
``intrusion-set``). ``materialize`` writes patched copies of the domain bundles and round-trips
the *whole* patched bundle through ``MitreAttackData``. ``doctor`` re-checks a delta against the
current datasets (targets that went away, upstream now publishing the same software/group,
allocation consistency). The pinned datasets are never written here.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from .allocations import Allocations
from .models import Delta
from .store import DomainStore, is_inactive

_SYNTHETIC_ID = re.compile(r"^(SX|GX)\d{4}$")
_SOFTWARE = ("malware", "tool")


class DeltaError(RuntimeError):
    """A delta could not be loaded, combined or materialized."""


# --------------------------------------------------------------------------- load / combine


def load_delta(run_dir: Path) -> Delta:
    path = Path(run_dir) / "delta.json"
    if not path.is_file():
        raise DeltaError(f"{path} not found (run did not mint a delta)")
    return Delta.model_validate_json(path.read_text(encoding="utf-8"))


def combine(deltas: Sequence[Delta]) -> list[dict[str, Any]]:
    """Objects of all deltas, deduplicated by STIX id, first-seen order.

    For a duplicate software / intrusion-set the first copy wins except that
    ``x_mitre_domains`` becomes the sorted union. Raises if two *different* STIX ids claim the
    same SX/GX id (the global registry should make that impossible).
    """
    merged: dict[str, dict[str, Any]] = {}
    for d in deltas:
        for obj in d.objects:
            have = merged.get(obj["id"])
            if have is None:
                merged[obj["id"]] = copy.deepcopy(obj)
            elif "x_mitre_domains" in obj or "x_mitre_domains" in have:
                have["x_mitre_domains"] = sorted(
                    set(have.get("x_mitre_domains", [])) | set(obj.get("x_mitre_domains", []))
                )
    claims: dict[str, str] = {}
    for obj in merged.values():
        attack_id = DomainStore.attack_id(obj)
        if attack_id and _SYNTHETIC_ID.match(attack_id) and claims.setdefault(attack_id, obj["id"]) != obj["id"]:
            raise DeltaError(f"{attack_id} is claimed by {claims[attack_id]} and {obj['id']}")
    return list(merged.values())


# --------------------------------------------------------------------------- materialize


def _read_bundle(datasets_dir: Path, domain: str) -> dict[str, Any]:
    path = Path(datasets_dir) / f"{domain}.json"
    if not path.is_file():
        raise DeltaError(f"no dataset for {domain}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _patch_bundle(bundle: dict[str, Any], domain: str, objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Append to ``bundle["objects"]`` what belongs in ``domain``; returns the objects added."""
    ids = {o["id"] for o in bundle["objects"]}
    added: list[dict[str, Any]] = []
    for obj in objects:
        if obj["type"] == "relationship":
            continue
        if obj["id"] not in ids and domain in obj.get("x_mitre_domains", [domain]):
            added.append(obj)
            ids.add(obj["id"])
    for obj in objects:
        if (
            obj["type"] == "relationship"
            and obj["id"] not in ids
            and obj["source_ref"] in ids
            and obj["target_ref"] in ids
        ):
            added.append(obj)
            ids.add(obj["id"])
    bundle["objects"].extend(copy.deepcopy(added))
    return added


def roundtrip_problems(path: Path, added: list[dict[str, Any]]) -> list[str]:
    """Load the full patched bundle with ``MitreAttackData`` and check every SX/GX object.

    Each SX/GX object must resolve via ``get_object_by_attack_id``; each SX software's
    ``get_techniques_used_by_software`` must equal the technique targets of its ``uses``
    relationships in the bundle.
    """
    from mitreattack.stix20 import MitreAttackData

    problems: list[str] = []
    try:
        data = MitreAttackData(str(path))
        objs = {o["id"]: o for o in json.loads(path.read_text(encoding="utf-8"))["objects"]}
        for obj in added:
            attack_id = DomainStore.attack_id(obj)
            if obj["type"] == "relationship" or not attack_id or not _SYNTHETIC_ID.match(attack_id):
                continue
            found = data.get_object_by_attack_id(attack_id, obj["type"])
            if found is None or found["id"] != obj["id"]:
                problems.append(f"get_object_by_attack_id({attack_id!r}, {obj['type']!r}) did not resolve")
                continue
            if obj["type"] in _SOFTWARE:
                expected = {
                    r["target_ref"]
                    for r in objs.values()
                    if r["type"] == "relationship"
                    and r.get("relationship_type") == "uses"
                    and r["source_ref"] == obj["id"]
                    and r["target_ref"].startswith("attack-pattern--")
                }
                got = {u["object"]["id"] for u in data.get_techniques_used_by_software(obj["id"])}
                if got != expected:
                    problems.append(
                        f"{attack_id}: get_techniques_used_by_software returned {len(got)} techniques, "
                        f"expected {len(expected)}"
                    )
    except Exception as exc:  # any load failure is the finding
        problems.append(f"{type(exc).__name__}: {exc}")
    return problems


def materialize(
    run_dirs: Sequence[Path],
    *,
    domains: Sequence[str] | None = None,
    out_dir: Path,
    datasets_dir: Path,
) -> dict[str, Path]:
    """Write ``<out_dir>/<domain>.json`` = pinned bundle + the combined deltas' objects.

    Objects go into a domain bundle when their ``x_mitre_domains`` include it; a relationship
    only when both endpoints are in that bundle. Raises :class:`DeltaError` (and writes nothing
    for that domain) if an SX/GX id collides with an upstream object or the patched bundle fails
    the full ``MitreAttackData`` round-trip.
    """
    deltas = [load_delta(Path(r)) for r in run_dirs]
    if not deltas:
        raise DeltaError("no deltas given")
    objects = combine(deltas)
    available = sorted({d for dl in deltas for d in dl.target_domains})
    wanted = list(domains) if domains else available
    missing = [d for d in wanted if d not in available]
    if missing:
        raise DeltaError(f"domain(s) {missing} are not targeted by these deltas (targets: {available})")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for domain in wanted:
        bundle = _read_bundle(datasets_dir, domain)
        upstream = {DomainStore.attack_id(o): o["id"] for o in bundle["objects"] if DomainStore.attack_id(o)}
        for obj in objects:
            attack_id = DomainStore.attack_id(obj)
            if attack_id and _SYNTHETIC_ID.match(attack_id) and attack_id in upstream and upstream[attack_id] != obj["id"]:
                raise DeltaError(f"{attack_id} already exists upstream in {domain} as {upstream[attack_id]}")
        added = _patch_bundle(bundle, domain, objects)
        final = out_dir / f"{domain}.json"
        fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=f"{domain}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh)
            problems = roundtrip_problems(Path(tmp), added)
            if problems:
                raise DeltaError(f"{domain}: patched bundle failed round-trip: " + "; ".join(problems))
            os.replace(tmp, final)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        written[domain] = final
    return written


# --------------------------------------------------------------------------- doctor


class DoctorFinding(BaseModel):
    code: str
    severity: Literal["error", "warn"]
    message: str
    object_id: str | None = None


class DoctorReport(BaseModel):
    run_id: str
    ok: bool = True
    retire: bool = False  # MITRE now publishes matching software/groups
    findings: list[DoctorFinding] = Field(default_factory=list)


class _Bundle:
    """Raw JSON view of one domain bundle (doctor does not need ``MitreAttackData``)."""

    def __init__(self, path: Path) -> None:
        objs = json.loads(path.read_text(encoding="utf-8"))["objects"]
        self.by_id = {o["id"]: o for o in objs}
        self.revoked_by = {
            o["source_ref"]: o["target_ref"]
            for o in objs
            if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"
        }
        self.by_attack_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.names: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for o in objs:
            attack_id = DomainStore.attack_id(o)
            if attack_id:
                self.by_attack_id[attack_id].append(o)
            if o["type"] in (*_SOFTWARE, "intrusion-set") and not is_inactive(o):
                for name in {o["name"], *o.get("aliases", []), *o.get("x_mitre_aliases", [])}:
                    self.names[" ".join(name.casefold().split())].append(o)


_BUNDLES: dict[tuple[str, int, int], _Bundle] = {}


def _bundle(datasets_dir: Path, domain: str) -> _Bundle | None:
    path = Path(datasets_dir) / f"{domain}.json"
    if not path.is_file():
        return None
    st = path.stat()
    key = (str(path.resolve()), st.st_mtime_ns, st.st_size)
    if key not in _BUNDLES:
        _BUNDLES.clear()  # keep one generation per process; stale files are never reused
        _BUNDLES[key] = _Bundle(path)
    return _BUNDLES[key]


def _norm(name: str) -> str:
    return " ".join(name.casefold().split())


def doctor(run_dir: Path, datasets_dir: Path, *, allocations_path: Path | None = None) -> DoctorReport:
    """Check a delta against the current datasets and the allocation registry.

    Codes: D001 endpoint missing; D002 endpoint revoked (successor shown); D003 endpoint
    deprecated; D004 relationship would not be materialized in any target domain (endpoints
    never share a bundle); D005 MITRE now publishes software/group with a matching name or
    alias (retire the delta); D006 allocation record missing or different; D007 SX/GX id
    or minted STIX id present upstream; D008 dataset for a target domain is missing.
    """
    delta = load_delta(Path(run_dir))
    allocs = Allocations(allocations_path or Path(datasets_dir) / "allocations.json")
    report = DoctorReport(run_id=delta.run_id)

    def add(code: str, severity: Literal["error", "warn"], message: str, object_id: str | None = None) -> None:
        report.findings.append(DoctorFinding(code=code, severity=severity, message=message, object_id=object_id))

    bundles: dict[str, _Bundle] = {}
    for domain in delta.target_domains:
        b = _bundle(Path(datasets_dir), domain)
        if b is None:
            add("D008", "error", f"dataset for {domain} is missing")
        else:
            bundles[domain] = b

    ours = {o["id"]: o for o in delta.objects}

    # D001-D004: every relationship endpoint that is not part of the delta.
    for rel in (o for o in delta.objects if o["type"] == "relationship"):
        shared_domain = False
        for end in ("source_ref", "target_ref"):
            ref = rel[end]
            if ref in ours:
                continue
            hits = {d: b.by_id[ref] for d, b in bundles.items() if ref in b.by_id}
            if not hits:
                if bundles:
                    add("D001", "error", f"{end} {ref} no longer exists in {sorted(bundles)}", rel["id"])
                continue
            obj = next(iter(hits.values()))
            label = f"{DomainStore.attack_id(obj) or ref} ({obj.get('name', '?')})"
            if obj.get("revoked"):
                succ = next((b.by_id.get(b.revoked_by.get(ref, "")) for b in bundles.values() if ref in b.revoked_by), None)
                hint = f"; successor {DomainStore.attack_id(succ)} ({succ['name']})" if succ else "; no successor"
                add("D002", "error", f"{end} {label} is revoked{hint}", rel["id"])
            elif obj.get("x_mitre_deprecated"):
                add("D003", "error", f"{end} {label} is deprecated (no successor)", rel["id"])
        # D004: some target domain must contain both endpoints (delta objects count via x_mitre_domains).
        for domain, b in bundles.items():
            def present(ref: str) -> bool:
                o = ours.get(ref)
                return ref in b.by_id or (o is not None and domain in o.get("x_mitre_domains", [domain]))

            if present(rel["source_ref"]) and present(rel["target_ref"]):
                shared_domain = True
        if bundles and not shared_domain:
            add("D004", "error", "endpoints are never in the same domain bundle; materialize would drop it", rel["id"])

    # D005: upstream now has the same software/group.
    for obj in delta.objects:
        if obj["type"] not in (*_SOFTWARE, "intrusion-set"):
            continue
        for name in {obj["name"], *obj.get("aliases", []), *obj.get("x_mitre_aliases", [])}:
            for domain, b in bundles.items():
                for match in b.names.get(_norm(name), []):
                    if match["id"] != obj["id"]:
                        add(
                            "D005",
                            "warn",
                            f"{obj['name']!r} (name/alias {name!r}) now matches upstream "
                            f"{DomainStore.attack_id(match)} {match['name']!r} in {domain}; consider retiring this delta",
                            obj["id"],
                        )
                        report.retire = True

    # D006/D007: allocations.
    for attack_id, stix_id in delta.allocations.items():
        kind = "group" if attack_id.startswith("GX") else "software"
        rec = allocs.lookup(attack_id)
        if rec is None:
            add("D006", "error", f"{attack_id} is not in allocations.json", stix_id)
        elif rec["stix_id"] != stix_id:
            add("D006", "error", f"{attack_id} is allocated to {rec['stix_id']}, delta says {stix_id}", stix_id)
        if stix_id not in ours:
            add("D006", "warn", f"allocated {kind} {attack_id} ({stix_id}) has no object in the delta", stix_id)
    for obj in delta.objects:
        attack_id = DomainStore.attack_id(obj)
        if attack_id and _SYNTHETIC_ID.match(attack_id) and delta.allocations.get(attack_id) != obj["id"]:
            add("D006", "error", f"{attack_id} on {obj['id']} is not in the delta's allocations", obj["id"])
    for domain, b in bundles.items():
        for obj in delta.objects:
            attack_id = DomainStore.attack_id(obj)
            if obj["type"] != "relationship" and attack_id and _SYNTHETIC_ID.match(attack_id):
                if attack_id in b.by_attack_id or obj["id"] in b.by_id:
                    add("D007", "error", f"{attack_id} / {obj['id']} exists upstream in {domain}", obj["id"])

    report.ok = not any(f.severity == "error" for f in report.findings)
    return report


def doctor_all(runs_dir: Path, datasets_dir: Path, *, allocations_path: Path | None = None) -> list[DoctorReport]:
    """:func:`doctor` for every ``runs_dir/*/delta.json``, sorted by run id."""
    runs_dir = Path(runs_dir)
    if not runs_dir.is_dir():
        return []
    return [
        doctor(p.parent, datasets_dir, allocations_path=allocations_path)
        for p in sorted(runs_dir.glob("*/delta.json"))
    ]
