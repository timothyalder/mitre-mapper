"""Delta combine / materialize / doctor (Wave 4A). Real mobile bundle; allocations in tmp_path."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mitre_mapper import delta as delta_mod
from mitre_mapper.allocations import Allocations
from mitre_mapper.delta import DeltaError, combine, doctor, doctor_all, load_delta, materialize
from mitre_mapper.mint import build_objects
from mitre_mapper.models import (
    Delta,
    EvidenceQuote,
    IntakeGroup,
    IntakeSpec,
    MappingProposal,
    NewGroup,
    TechniqueMapping,
)
from mitre_mapper.store import AttackStore

CREATED = "2026-10-03T12:34:56.000Z"
ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
ACTOR = NewGroup(
    name="Example Actor",
    aliases=["Shared Actor"],
    description="A user-defined actor.",
    techniques=["T1404"],
)


@pytest.fixture(scope="module")
def mobile_only(tmp_path_factory) -> Path:
    """Datasets dir holding only the (copied) mobile bundle; the real files are never touched."""
    d = tmp_path_factory.mktemp("datasets")
    shutil.copy(DATASETS / "mobile-attack.json", d / "mobile-attack.json")
    return d


@pytest.fixture(scope="module")
def store(mobile_only) -> AttackStore:
    return AttackStore(mobile_only)


def make_run(tmp_path: Path, store: AttackStore, name: str, *, group: NewGroup | None = ACTOR, tid="T1430") -> Path:
    spec = IntakeSpec(
        name=name,
        type="malware",
        platforms=["iOS"],
        body=f"{name} is spyware.",
        groups=[IntakeGroup(new=group)] if group else [],
    )
    proposal = MappingProposal(
        domain="mobile-attack",
        techniques=[
            TechniqueMapping(
                technique_id=tid,
                rationale="It tracks location.",
                evidence=[EvidenceQuote(source_name="x", quote="q")],
            )
        ],
    )
    allocs = Allocations(tmp_path / "allocations.json")
    run_id = f"run-{name.replace(' ', '-')}"
    res = build_objects(spec, {"mobile-attack": proposal}, store, allocs, CREATED, commit=True, run_id=run_id)
    run_dir = tmp_path / "runs" / run_id
    run_dir.mkdir(parents=True)
    d = Delta(
        run_id=run_id,
        created=CREATED,
        dataset_manifest={},
        tool_version="t",
        git_sha="g",
        prompt_sha256="p",
        allocations=res.allocations,
        target_domains=["mobile-attack"],
        objects=res.objects,
    )
    (run_dir / "delta.json").write_text(d.model_dump_json(indent=1))
    return run_dir


def test_combine_two_deltas_sharing_a_group_yields_one_intrusion_set(tmp_path, store):
    a = make_run(tmp_path, store, "Alpha Spy")
    b = make_run(tmp_path, store, "Beta Spy")
    objs = combine([load_delta(a), load_delta(b)])
    types = [o["type"] for o in objs]
    assert types.count("intrusion-set") == 1  # acceptance #12
    assert types.count("malware") == 2
    group = next(o for o in objs if o["type"] == "intrusion-set")
    rels = [o for o in objs if o["type"] == "relationship" and o["source_ref"] == group["id"]]
    assert len(rels) == 3  # 2 group->software + the shared group->T1404, collapsed
    assert len({r["id"] for r in objs}) == len(objs)


def test_combine_unions_domains_of_duplicate_objects(tmp_path, store):
    a = load_delta(make_run(tmp_path, store, "Alpha Spy"))
    b = a.model_copy(deep=True)
    for o in b.objects:
        if o["type"] in ("malware", "intrusion-set"):
            o["x_mitre_domains"] = ["enterprise-attack"]
    objs = combine([a, b])
    assert len(objs) == len(a.objects)
    assert all(
        o["x_mitre_domains"] == ["enterprise-attack", "mobile-attack"]
        for o in objs
        if o["type"] in ("malware", "intrusion-set")
    )


def test_combine_rejects_conflicting_synthetic_id(tmp_path, store):
    a = load_delta(make_run(tmp_path, store, "Alpha Spy", group=None))
    b = a.model_copy(deep=True)
    soft = next(o for o in b.objects if o["type"] == "malware")
    soft["id"] = "malware--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12
    with pytest.raises(DeltaError, match="SX0001"):
        combine([a, b])


def test_materialize_loads_and_resolves(tmp_path, store, mobile_only):
    a = make_run(tmp_path, store, "Alpha Spy")
    b = make_run(tmp_path, store, "Beta Spy")
    out = tmp_path / "out"
    written = materialize([a, b], out_dir=out, datasets_dir=mobile_only)
    assert list(written) == ["mobile-attack"]
    bundle = json.loads(written["mobile-attack"].read_text())
    orig = json.loads((mobile_only / "mobile-attack.json").read_text())
    assert bundle["objects"][: len(orig["objects"])] == orig["objects"]  # original objects untouched
    added = bundle["objects"][len(orig["objects"]):]
    assert [o["type"] for o in added].count("intrusion-set") == 1
    assert [o["type"] for o in added].count("malware") == 2
    from mitreattack.stix20 import MitreAttackData

    data = MitreAttackData(str(written["mobile-attack"]))
    assert data.get_object_by_attack_id("SX0001", "malware")["name"] == "Alpha Spy"
    assert data.get_object_by_attack_id("GX0001", "intrusion-set")["name"] == "Example Actor"
    soft = data.get_object_by_attack_id("SX0002", "malware")
    assert {data.get_attack_id(u["object"]["id"]) for u in data.get_techniques_used_by_software(soft["id"])} == {"T1430"}
    assert not list(out.glob("*.tmp"))
    assert (mobile_only / "mobile-attack.json").read_bytes() == (DATASETS / "mobile-attack.json").read_bytes()


def test_materialize_unknown_domain_and_upstream_collision(tmp_path, store, mobile_only):
    a = make_run(tmp_path, store, "Alpha Spy", group=None)
    with pytest.raises(DeltaError, match="not targeted"):
        materialize([a], domains=["ics-attack"], out_dir=tmp_path / "o", datasets_dir=mobile_only)
    # an upstream object that already carries SX0001 -> refuse
    bad = tmp_path / "bad"
    bad.mkdir()
    bundle = json.loads((mobile_only / "mobile-attack.json").read_text())
    clash = next(o for o in bundle["objects"] if o["type"] == "malware")
    clash["external_references"][0]["external_id"] = "SX0001"
    (bad / "mobile-attack.json").write_text(json.dumps(bundle))
    with pytest.raises(DeltaError, match="already exists upstream"):
        materialize([a], out_dir=tmp_path / "o2", datasets_dir=bad)
    assert not list((tmp_path / "o2").glob("*.json"))


def test_doctor_clean(tmp_path, store, mobile_only):
    run = make_run(tmp_path, store, "Alpha Spy")
    rep = doctor(run, mobile_only, allocations_path=tmp_path / "allocations.json")
    assert rep.ok and not rep.retire and rep.findings == []


def test_doctor_flags_revoked_target_with_successor(tmp_path, store, mobile_only):
    run = make_run(tmp_path, store, "Alpha Spy", group=None)
    bundle = json.loads((mobile_only / "mobile-attack.json").read_text())
    live = next(o for o in bundle["objects"] if o["type"] == "attack-pattern" and o["external_references"][0]["external_id"] == "T1430")
    successor = next(o for o in bundle["objects"] if o["type"] == "attack-pattern" and o["id"] != live["id"] and not o.get("revoked") and not o.get("x_mitre_deprecated"))
    live["revoked"] = True
    bundle["objects"].append(
        {"type": "relationship", "id": "relationship--" + "1" * 8 + "-1111-4111-8111-" + "1" * 12,
         "relationship_type": "revoked-by", "source_ref": live["id"], "target_ref": successor["id"],
         "created": CREATED, "modified": CREATED}
    )
    d = tmp_path / "revoked-ds"
    d.mkdir()
    (d / "mobile-attack.json").write_text(json.dumps(bundle))
    rep = doctor(run, d, allocations_path=tmp_path / "allocations.json")
    assert not rep.ok
    f = next(f for f in rep.findings if f.code == "D002")
    assert "T1430" in f.message and successor["name"] in f.message
    # revoked target is still "in the bundle" so the rel is not dropped
    assert not any(f.code == "D004" for f in rep.findings)


def test_doctor_flags_missing_target_and_allocation_problems(tmp_path, store, mobile_only):
    run = make_run(tmp_path, store, "Alpha Spy", group=None)
    bundle = json.loads((mobile_only / "mobile-attack.json").read_text())
    tid = next(r for r in load_delta(run).objects if r["type"] == "relationship")["target_ref"]
    bundle["objects"] = [o for o in bundle["objects"] if o["id"] != tid]
    d = tmp_path / "missing-ds"
    d.mkdir()
    (d / "mobile-attack.json").write_text(json.dumps(bundle))
    (tmp_path / "other-alloc.json").write_text('{"schema_version": 1, "software": {}, "groups": {}}')
    rep = doctor(run, d, allocations_path=tmp_path / "other-alloc.json")
    codes = {f.code for f in rep.findings}
    assert {"D001", "D004", "D006"} <= codes and not rep.ok


def test_doctor_recommends_retiring_when_upstream_publishes_same_name(tmp_path, store, mobile_only):
    run = make_run(tmp_path, store, "Pegasus for iOS", group=None)  # S0289 exists upstream
    rep = doctor(run, mobile_only, allocations_path=tmp_path / "allocations.json")
    assert rep.retire and rep.ok
    assert any(f.code == "D005" and "S0289" in f.message for f in rep.findings)


def test_doctor_flags_upstream_id_collision(tmp_path, store, mobile_only):
    run = make_run(tmp_path, store, "Alpha Spy", group=None)
    bundle = json.loads((mobile_only / "mobile-attack.json").read_text())
    next(o for o in bundle["objects"] if o["type"] == "malware")["external_references"][0]["external_id"] = "SX0001"
    d = tmp_path / "collide-ds"
    d.mkdir()
    (d / "mobile-attack.json").write_text(json.dumps(bundle))
    rep = doctor(run, d, allocations_path=tmp_path / "allocations.json")
    assert any(f.code == "D007" for f in rep.findings)


def test_doctor_all(tmp_path, store, mobile_only):
    make_run(tmp_path, store, "Alpha Spy")
    make_run(tmp_path, store, "Beta Spy")
    reps = doctor_all(tmp_path / "runs", mobile_only, allocations_path=tmp_path / "allocations.json")
    assert [r.run_id for r in reps] == ["run-Alpha-Spy", "run-Beta-Spy"] and all(r.ok for r in reps)
    assert doctor_all(tmp_path / "none", mobile_only) == []
    assert delta_mod.load_delta  # public API sanity


@pytest.mark.slow
def test_materialize_enterprise_and_cross_domain_software(tmp_path, attack_store, datasets_dir):
    """Software accepted in both domains lands in both bundles; rels are partitioned by domain."""
    spec = IntakeSpec(name="Dual Spy", type="malware", platforms=["Windows", "iOS"], body="Dual spyware.")

    def prop(domain, tid):
        return MappingProposal(
            domain=domain,
            techniques=[TechniqueMapping(technique_id=tid, rationale="r", evidence=[EvidenceQuote(source_name="x", quote="q")])],
        )

    allocs = Allocations(tmp_path / "allocations.json")
    res = build_objects(
        spec,
        {"enterprise-attack": prop("enterprise-attack", "T1059.001"), "mobile-attack": prop("mobile-attack", "T1430")},
        attack_store, allocs, CREATED, commit=True, run_id="run-dual",
    )
    run_dir = tmp_path / "runs" / "run-dual"
    run_dir.mkdir(parents=True)
    (run_dir / "delta.json").write_text(
        Delta(
            run_id="run-dual", created=CREATED, dataset_manifest={}, tool_version="t", git_sha="g", prompt_sha256="p",
            allocations=res.allocations, target_domains=["enterprise-attack", "mobile-attack"], objects=res.objects,
        ).model_dump_json()
    )
    written = materialize([run_dir], out_dir=tmp_path / "out", datasets_dir=datasets_dir)
    assert set(written) == {"enterprise-attack", "mobile-attack"}
    for domain, tid in (("enterprise-attack", "T1059.001"), ("mobile-attack", "T1430")):
        orig = {o["id"] for o in json.loads((datasets_dir / f"{domain}.json").read_text())["objects"]}
        new = [o for o in json.loads(written[domain].read_text())["objects"] if o["id"] not in orig]
        assert [o["type"] for o in new].count("malware") == 1
        rels = [o for o in new if o["type"] == "relationship"]
        assert len(rels) == 1 and rels[0]["target_ref"] in orig
        assert rels[0]["target_ref"] == attack_store.domain(domain).lookup(tid, "attack-pattern").obj["id"]
    rep = doctor(run_dir, datasets_dir, allocations_path=tmp_path / "allocations.json")
    assert rep.ok, rep.findings
