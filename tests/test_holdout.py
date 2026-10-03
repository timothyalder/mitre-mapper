"""Holdout predicates and leakage probes (PLAN 4.2, acceptance #4)."""

from __future__ import annotations

import re

import pytest

from mitre_mapper.holdout import CRACKMAPEXEC, HOLDOUTS, PEGASUS, HoldoutSpec, apply_holdout, get_holdout
from mitre_mapper.search import search
from mitre_mapper.store import AttackStore, get_store

PEGASUS_RE = re.compile(r"(?i)pegasus|chrysaor|\bnso\b")
CME_RE = re.compile(r"(?i)crack\s*map\s*exec")


def ref(name, ext=None, desc=None, url=None):
    return {"source_name": name, "external_id": ext, "description": desc, "url": url}


def obj(typ, oid, name="", desc="", aliases=(), refs=()):
    o = {"type": typ, "id": f"{typ}--{oid}", "name": name, "description": desc,
         "external_references": [ref("mitre-attack", oid.upper()), *refs]}
    if aliases:
        o["aliases"] = list(aliases)
    return o


def rel(rid, src, dst, desc="", refs=()):
    return {"type": "relationship", "id": f"relationship--{rid}", "relationship_type": "uses",
            "source_ref": src, "target_ref": dst, "description": desc, "external_references": list(refs)}


# ---- predicate semantics on synthetic objects ----------------------------------------------


def test_anchored_nso_keeps_substring_lookalikes():
    spec = PEGASUS
    assert spec.matches(obj("malware", "a", desc="linked to the NSO Group"))
    assert spec.matches(obj("malware", "a", desc="vendor nso."))
    assert spec.matches(obj("malware", "a", refs=[ref("x", url="https://c.ca/nso-group-uae/")]))
    assert not spec.matches(obj("attack-pattern", "b", name="Location Tracking", desc="e.g. Insomnia"))
    assert not spec.matches(obj("attack-pattern", "b", desc="sensors in the handset"))


def test_matches_name_alias_description_and_every_reference_field():
    assert PEGASUS.matches(obj("malware", "a", name="Pegasus for iOS"))
    assert PEGASUS.matches(obj("intrusion-set", "a", aliases=["Chrysaor"]))
    assert PEGASUS.matches(obj("attack-pattern", "a", refs=[ref("PegasusCitizenLab")]))
    assert PEGASUS.matches(obj("attack-pattern", "a", refs=[ref("k", desc="the Pegasus spyware")]))
    assert not PEGASUS.matches(obj("attack-pattern", "a", desc="nothing relevant"))
    assert CRACKMAPEXEC.matches(obj("tool", "a", name="Crack Map Exec"))
    assert CRACKMAPEXEC.matches(obj("tool", "a", desc="used crackmapexec"))
    assert not CRACKMAPEXEC.matches(obj("tool", "a", desc="the CME tool"))  # "CME" alone is not matched


def test_apply_removes_matches_drops_and_dangling_relationships_and_reports_masks():
    soft = obj("tool", "soft", name="CrackMapExec")
    twin = obj("tool", "twin", name="Other Tool")
    grp = obj("intrusion-set", "grp", name="Group")
    t1, t2, t3 = (obj("attack-pattern", f"t{i}", name=f"T{i}") for i in (1, 2, 3))
    objects = [
        soft, twin, grp, t1, t2, t3,
        rel("r1", soft["id"], t1["id"]),  # dangling: source dropped
        rel("r2", grp["id"], soft["id"]),  # dangling: target dropped
        rel("r3", grp["id"], t2["id"], desc="Group used CrackMapExec"),  # masked: text matches
        rel("r4", grp["id"], t3["id"], desc="unrelated"),  # survives
        rel("r5", twin["id"], t1["id"]),  # survives
    ]
    spec = HoldoutSpec("t", CRACKMAPEXEC.pattern, drop=(("tool", "OTHER"),))
    # drop by (type, attack id): the fixtures' attack ids are the upper-cased oid
    objects[1]["external_references"][0]["external_id"] = "OTHER"
    kept, report = apply_holdout(objects, spec, "enterprise-attack")
    ids = {o["id"] for o in kept}
    assert soft["id"] not in ids and twin["id"] not in ids
    assert {o["id"] for o in kept if o["type"] == "relationship"} == {"relationship--r4"}
    # r5 touches the dropped twin; r1/r2 touch the dropped tool; only r3 is a *mask*
    assert report.masked_relationship_ids == ["relationship--r3"]
    assert report.removed_by_type == {"tool": 2, "relationship": 4}
    assert report.n_before == len(objects) and report.n_after == len(kept)
    assert "tool OTHER Other Tool" in report.removed_objects
    assert objects and len(objects) == 11  # input untouched


def test_registry():
    assert get_holdout("pegasus") is PEGASUS and set(HOLDOUTS) == {"pegasus", "crackmapexec"}
    assert PEGASUS.pattern == r"(?i)pegasus|chrysaor|\bnso\b"
    assert CRACKMAPEXEC.pattern == r"(?i)crack\s*map\s*exec"
    with pytest.raises(KeyError):
        get_holdout("nope")


# ---- real data: Pegasus (mobile, ~1 s) -----------------------------------------------------


@pytest.fixture(scope="module")
def held_mobile(datasets_dir):
    return get_store(datasets_dir, PEGASUS).domain("mobile-attack")


def test_held_out_store_is_cached_separately_from_the_plain_one(datasets_dir, held_mobile):
    plain = get_store(datasets_dir).domain("mobile-attack")
    assert held_mobile is not plain
    assert get_store(datasets_dir, PEGASUS).domain("mobile-attack") is held_mobile
    assert plain.lookup("S0289", "malware").obj is not None  # the answer key still exists
    assert held_mobile.lookup("S0289", "malware").obj is None


def test_pegasus_removed_counts_on_mobile(held_mobile):
    r = held_mobile.holdout_report
    assert r.removed_by_type["malware"] == 3  # S0289, S0316, S0602 (Circles names NSO Group)
    assert r.removed_by_type["intrusion-set"] == 1  # Confucius (Chrysaor/NSO references)
    assert r.removed_by_type["relationship"] == 32
    assert r.n_before - r.n_after == 36
    assert "malware S0289 Pegasus for iOS" in r.removed_objects
    assert "malware S0316 Pegasus for Android" in r.removed_objects


def test_pegasus_leakage_probe_zero_hits_in_every_searchable_field(held_mobile):
    leaks = []
    for o in held_mobile._by_stix.values():
        if PEGASUS.regex.search(PEGASUS.searchable_text(o)):
            leaks.append((o["type"], o.get("name")))
    assert leaks == []
    # also through MitreAttackData, which backs every library helper
    for fn in (held_mobile.data.get_software, held_mobile.data.get_groups):
        assert not [x["name"] for x in fn() if PEGASUS_RE.search(x["name"])]
    assert PEGASUS_RE.search("Pegasus") and PEGASUS_RE.search("the NSO Group")  # the probe regex itself


@pytest.mark.parametrize("query", ["pegasus", "Chrysaor", "NSO Group", "pegasus for ios spyware", "nso"])
def test_pegasus_search_results_never_surface_held_out_objects(held_mobile, query):
    for kind in ("technique", "group", "software"):
        for hit in search(held_mobile, kind, query, k=25):
            obj = held_mobile.get_by_stix_id(hit.stix_id)
            assert not PEGASUS.regex.search(PEGASUS.searchable_text(obj)), (kind, hit.name)
            assert hit.attack_id not in {"S0289", "S0316", "S0602", "G0142"}


def test_unanchored_nso_trap_t1430_and_t1660_survive(held_mobile, datasets_dir):
    for tid in ("T1430", "T1660"):
        assert held_mobile.lookup(tid, "attack-pattern").obj is not None, tid
    # ...and the trap is real: an unanchored pattern would have deleted both
    unanchored = HoldoutSpec("trap", r"(?i)pegasus|chrysaor|nso")
    plain = get_store(datasets_dir).domain("mobile-attack")
    for tid in ("T1430", "T1660"):
        assert unanchored.matches(plain.lookup(tid, "attack-pattern").obj), tid
        assert not PEGASUS.matches(plain.lookup(tid, "attack-pattern").obj), tid


def test_pegasus_holdout_keeps_everything_else_loadable(held_mobile):
    assert held_mobile.data.get_techniques()  # MitreAttackData built from the filtered bundle
    assert held_mobile.software_techniques("S0289") == []


# ---- real data: CrackMapExec (enterprise: slow) --------------------------------------------


@pytest.fixture(scope="module")
def held_enterprise(datasets_dir):
    return get_store(datasets_dir, CRACKMAPEXEC).domain("enterprise-attack")


@pytest.mark.slow
def test_crackmapexec_removed_and_masked_counts(held_enterprise, datasets_dir):
    r = held_enterprise.holdout_report
    assert r.removed_by_type == {"tool": 1, "relationship": 30}
    assert r.removed_objects == ["tool S0488 CrackMapExec"]
    assert len(r.masked_relationship_ids) == 4  # Dragonfly T1110.002/T1588.002, APT39 T1046/T1135
    plain = AttackStore(datasets_dir).domain("enterprise-attack")
    masked = set()
    for rid in r.masked_relationship_ids:
        rel_obj = plain.get_by_stix_id(rid)
        src, dst = plain.get_by_stix_id(rel_obj["source_ref"]), plain.get_by_stix_id(rel_obj["target_ref"])
        masked.add((src["name"], plain.attack_id(dst)))
    assert masked == {("Dragonfly", "T1110.002"), ("Dragonfly", "T1588.002"), ("APT39", "T1046"), ("APT39", "T1135")}


@pytest.mark.slow
def test_crackmapexec_leakage_probe_and_masks_on_enterprise(held_enterprise, datasets_dir):
    leaks = [o["id"] for o in held_enterprise._by_stix.values() if CME_RE.search(CRACKMAPEXEC.searchable_text(o))]
    assert leaks == []
    assert held_enterprise.lookup("S0488", "tool").obj is None
    for query in ("crackmapexec", "crack map exec", "CME SMB post-exploitation"):
        for kind in ("technique", "group", "software"):
            for hit in search(held_enterprise, kind, query, k=25):
                obj = held_enterprise.get_by_stix_id(hit.stix_id)
                assert not CME_RE.search(CRACKMAPEXEC.searchable_text(obj))
    # the masked group->technique links are really gone, unmasked ones survive
    plain = AttackStore(datasets_dir).domain("enterprise-attack")
    dragonfly = held_enterprise.lookup("G0035", "intrusion-set").obj
    used = {
        held_enterprise.attack_id(held_enterprise.get_by_stix_id(u["object"]["id"]))
        for u in held_enterprise.data.get_techniques_used_by_group(dragonfly["id"])
    }
    used_plain = {
        plain.attack_id(plain.get_by_stix_id(u["object"]["id"]))
        for u in plain.data.get_techniques_used_by_group(plain.lookup("G0035", "intrusion-set").obj["id"])
    }
    assert {"T1110.002", "T1588.002"} <= used_plain and not ({"T1110.002", "T1588.002"} & used)
    assert len(used) > 10  # Dragonfly keeps its other techniques
