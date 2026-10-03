import json
import re
from pathlib import Path

import pytest
import stix2
import stix2.v20 as stix

from mitre_mapper import mint
from mitre_mapper.allocations import Allocations
from mitre_mapper.mint import (
    MITRE_IDENTITY,
    MITRE_MARKING,
    build_objects,
    deterministic_uuid4,
    mint_software,
    mint_technique_relationship,
    relationship_stix_id,
    software_stix_id,
)
from mitre_mapper.models import (
    EvidenceQuote,
    ExternalReference,
    IntakeSpec,
    MappingProposal,
    TechniqueMapping,
)

CREATED = "2026-10-03T12:34:56.000Z"
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

LOOKOUT = ExternalReference(
    source_name="Lookout Pegasus",
    url="https://info.lookout.com/pegasus.pdf",
    description="Lookout. (2016). Technical Analysis of Pegasus Spyware.",
)


@pytest.fixture
def spec() -> IntakeSpec:
    return IntakeSpec(
        name="Pegasus for iOS (thin)",
        type="malware",
        aliases=["Pegasus", "Pegasus for iOS (thin)"],
        platforms=["iOS"],
        references=[LOOKOUT],
        body="Pegasus is iOS spyware.",
    )


def mapping(tid="T1430", user_asserted=False, sources=("Lookout Pegasus",)):
    return TechniqueMapping(
        technique_id=tid,
        rationale="It tracks location.",
        evidence=[EvidenceQuote(source_name=s, quote="q") for s in sources],
        user_asserted=user_asserted,
    )


def test_uuid4_is_deterministic_and_v4():
    a = deterministic_uuid4("x", "y")
    assert a == deterministic_uuid4("x", "y") != deterministic_uuid4("x", "z")
    assert a.version == 4
    assert software_stix_id("Foo  Bar", "tool") == software_stix_id("foo bar", "tool")
    assert software_stix_id("foo", "tool") != software_stix_id("foo", "malware")
    assert relationship_stix_id("uses", "a--1", "b--2").startswith("relationship--")


def test_mint_software_fields(spec):
    obj = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    assert obj["type"] == "malware" and obj["labels"] == ["malware"]
    assert obj["created_by_ref"] == obj["x_mitre_modified_by_ref"] == MITRE_IDENTITY
    assert obj["object_marking_refs"] == [MITRE_MARKING]
    assert obj["x_mitre_version"] == "1.0" and obj["x_mitre_attack_spec_version"] == "3.3.0"
    assert obj["x_mitre_deprecated"] is False and obj["x_mitre_platforms"] == ["iOS"]
    assert obj["x_mitre_aliases"] == ["Pegasus for iOS (thin)", "Pegasus"]
    assert obj["description"] == "Pegasus is iOS spyware."
    assert obj["external_references"][0] == {
        "source_name": "mitre-attack",
        "external_id": "SX0001",
        "url": "https://attack.mitre.org/software/SX0001",
    }
    assert obj["external_references"][1]["source_name"] == "Lookout Pegasus"


def test_x_mitre_domains_sorted_and_tool_label(spec):
    tool = spec.model_copy(update={"type": "tool"})
    obj = mint_software(tool, "SX0002", ["mobile-attack", "enterprise-attack"], CREATED)
    assert obj["x_mitre_domains"] == ["enterprise-attack", "mobile-attack"]
    assert obj["type"] == "tool" and obj["labels"] == ["tool"]


def test_timestamps_have_exactly_three_fraction_digits(spec):
    obj = mint_software(spec, "SX0001", ["mobile-attack"], "2026-10-03T12:34:56.120Z")
    assert obj["created"] == obj["modified"] == "2026-10-03T12:34:56.120Z"
    assert TS.match(obj["created"])
    for bad in ("2026-10-03T12:34:56Z", "2026-10-03T12:34:56.1234Z", "2026-10-03"):
        with pytest.raises(ValueError):
            mint_software(spec, "SX0001", ["mobile-attack"], bad)


def test_relationship_profile_matches_real_uses_relationships(spec, mobile_store):
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    technique = mobile_store.lookup("T1430", "attack-pattern").obj
    rel = mint_technique_relationship(software, technique, mapping(), [LOOKOUT], CREATED)
    real = next(
        o for o in mobile_store._by_stix.values()
        if o["type"] == "relationship" and o["relationship_type"] == "uses"
        and o["source_ref"].startswith("malware--")
        and o["target_ref"].startswith("attack-pattern--")
        and o.get("external_references")
    )
    assert set(real) - {"external_references"} <= set(rel)
    assert rel["relationship_type"] == "uses"
    assert rel["source_ref"] == software["id"] and rel["target_ref"] == technique["id"]
    assert rel["description"] == "It tracks location.(Citation: Lookout Pegasus)"
    assert [r["source_name"] for r in rel["external_references"]] == ["Lookout Pegasus"]
    assert TS.match(rel["created"]) and TS.match(rel["modified"])


def test_user_asserted_without_evidence_cites_pool(spec, mobile_store):
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    technique = mobile_store.lookup("T1430", "attack-pattern").obj
    intake = ExternalReference(source_name="mitre-mapper intake", description="user")
    m = mapping(user_asserted=True, sources=())
    rel = mint_technique_relationship(software, technique, m, [intake], CREATED)
    assert rel["external_references"][0]["source_name"] == "mitre-mapper intake"
    assert "(Citation: mitre-mapper intake)" in rel["description"]


def test_objects_are_real_stix2_objects(spec, mobile_store):
    """Output must reparse as stix2.v20 objects (acceptance #14)."""
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    technique = mobile_store.lookup("T1430", "attack-pattern").obj
    rel = mint_technique_relationship(software, technique, mapping(), [LOOKOUT], CREATED)
    assert isinstance(stix2.parse(software, allow_custom=True, version="2.0"), stix.Malware)
    assert isinstance(stix2.parse(rel, allow_custom=True, version="2.0"), stix.Relationship)


def test_mint_py_builds_only_through_stix2_classes():
    source = Path(mint.__file__).read_text()
    assert not re.search(r"""["']type["']\s*:""", source), "hand-written STIX dict in mint.py"
    assert "stix.Malware" in source and "stix.Tool" in source and "stix.Relationship" in source
    assert "allow_custom=True" in source and "serialize()" in source
    assert "langchain" not in source


def test_uuid5_is_rejected_by_stix2():
    import uuid

    with pytest.raises(Exception, match="not a valid STIX identifier"):
        stix.Malware(
            id=f"malware--{uuid.uuid5(uuid.NAMESPACE_DNS, 'x')}", name="x", labels=["malware"]
        )


def test_build_objects_preview_then_commit(spec, attack_store, tmp_path):
    alloc = Allocations(tmp_path / "allocations.json")
    proposals = {
        "mobile-attack": MappingProposal(
            domain="mobile-attack",
            techniques=[mapping("T1430"), mapping("T1404"), mapping("T1059.001")],  # last: not mobile
        )
    }
    preview = build_objects(spec, proposals, attack_store, alloc, CREATED, commit=False)
    assert not (tmp_path / "allocations.json").exists()
    assert list(preview.allocations) == ["SX0001"]
    assert preview.software["external_references"][0]["external_id"] == "SX0001"
    assert len(preview.objects) == 3  # software + 2 resolvable techniques
    assert preview.by_domain["mobile-attack"] == preview.objects

    committed = build_objects(spec, proposals, attack_store, alloc, CREATED, commit=True, run_id="r1")
    assert committed.objects == preview.objects
    assert alloc.lookup("SX0001")["first_run"] == "r1"
    assert json.loads((tmp_path / "allocations.json").read_text())["software"]["SX0001"]


def test_build_objects_commit_requires_run_id(spec, attack_store, tmp_path):
    with pytest.raises(ValueError):
        build_objects(spec, {}, attack_store, Allocations(tmp_path / "a.json"), CREATED, commit=True)


def test_declined_proposal_has_software_only(spec, attack_store, tmp_path):
    proposals = {
        "mobile-attack": MappingProposal(
            domain="mobile-attack", declined=True, decline_rationale="not enough evidence"
        )
    }
    result = build_objects(
        spec, proposals, attack_store, Allocations(tmp_path / "a.json"), CREATED, commit=False
    )
    assert [o["type"] for o in result.objects] == ["malware"]


def test_revoked_technique_mints_against_successor(spec, attack_store, mobile_store, tmp_path):
    proposals = {"mobile-attack": MappingProposal(domain="mobile-attack", techniques=[mapping("T1579")])}
    result = build_objects(
        spec, proposals, attack_store, Allocations(tmp_path / "a.json"), CREATED, commit=False
    )
    successor = mobile_store.lookup("T1634.001", "attack-pattern").obj
    assert result.objects[1]["target_ref"] == successor["id"]


# --- groups (Wave 3C) -----------------------------------------------------------

from mitre_mapper.intake import INTAKE_SOURCE  # noqa: E402
from mitre_mapper.mint import (  # noqa: E402
    group_stix_id,
    mint_group,
    mint_group_software_relationship,
    mint_group_technique_relationship,
)
from mitre_mapper.models import GroupMapping, IntakeGroup, NewGroup  # noqa: E402

INTAKE_REF = ExternalReference(source_name=INTAKE_SOURCE, description="user")
NEW = NewGroup(
    name="Example Actor",
    aliases=["EA", "Example Actor", "Team Ex"],
    description="A user-defined actor.",
    references=[ExternalReference(source_name="Vendor Report", url="https://x.example/r", description="Vendor.")],
    techniques=["T1404", "T1059.001"],
)


def group_spec(base, *groups, **kw):
    return base.model_copy(update={"groups": [IntakeGroup(**g) for g in groups], **kw})


def test_group_id_is_normalized_name_only():
    assert group_stix_id("Example  Actor") == group_stix_id("example actor")
    assert group_stix_id("a").startswith("intrusion-set--")
    assert deterministic_uuid4("a", "intrusion-set").version == 4
    assert group_stix_id("a") != software_stix_id("a", "tool")


def test_mint_group_matches_real_intrusion_set_profile(mobile_store):
    obj = mint_group(NEW, "GX0001", ["mobile-attack"], CREATED, NEW.references)
    real = next(o for o in mobile_store.objects("intrusion-set") if o.get("aliases"))
    required = {k for k in real if k != "x_mitre_contributors"}  # contributors: ~50% of real groups
    assert required <= set(obj), required - set(obj)
    assert obj["type"] == "intrusion-set"
    assert obj["external_references"][0] == {
        "source_name": "mitre-attack",
        "external_id": "GX0001",
        "url": "https://attack.mitre.org/groups/GX0001",
    }
    assert obj["aliases"] == ["Example Actor", "EA", "Team Ex"]  # name first, no duplicates
    assert "x_mitre_aliases" not in obj
    assert obj["created_by_ref"] == obj["x_mitre_modified_by_ref"] == MITRE_IDENTITY
    assert obj["object_marking_refs"] == [MITRE_MARKING] and obj["revoked"] is False
    assert obj["x_mitre_version"] == "1.0" and obj["x_mitre_attack_spec_version"] == "3.3.0"
    assert obj["x_mitre_domains"] == ["mobile-attack"] and obj["x_mitre_deprecated"] is False
    sources = [r["source_name"] for r in obj["external_references"]]
    assert sources[1:] == ["EA", "Team Ex", "Vendor Report", INTAKE_SOURCE]
    alias_ref = obj["external_references"][1]
    assert alias_ref["description"] == f"(Citation: {INTAKE_SOURCE})"
    assert isinstance(stix2.parse(obj, allow_custom=True, version="2.0"), stix.IntrusionSet)
    with pytest.raises(ValueError):
        mint_group(NEW, "GX0001", ["mobile-attack"], "2026-10-03", [])


def test_real_aliases_convention_is_name_first(mobile_store):
    for g in mobile_store.objects("intrusion-set"):
        assert g["aliases"][0] == g["name"]


def test_agent_proposed_group_link_carries_quote_and_citation(mobile_store, spec):
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    group = mobile_store.resolve_group("Confucius")
    m = GroupMapping(group_id="G0142", quote="Confucius deployed Pegasus.", source_name="Lookout Pegasus")
    rel = mint_group_software_relationship(group, software, m, [LOOKOUT, INTAKE_REF], CREATED)
    real = next(
        o for o in mobile_store._by_stix.values()
        if o["type"] == "relationship" and o["relationship_type"] == "uses"
        and o["source_ref"].startswith("intrusion-set--") and o["target_ref"].startswith("malware--")
        and o.get("external_references")
    )
    assert set(real) - {"external_references"} <= set(rel)
    assert rel["source_ref"] == group["id"] and rel["target_ref"] == software["id"]
    assert rel["description"] == "Confucius deployed Pegasus.(Citation: Lookout Pegasus)"
    assert rel["external_references"] == [LOOKOUT.model_dump(exclude_none=True)]
    assert rel["id"] == relationship_stix_id("uses", group["id"], software["id"])


def test_user_asserted_group_link_cites_intake(mobile_store, spec):
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    group = mobile_store.resolve_group("Confucius")
    for m in (None, GroupMapping(group_id="G0142", user_asserted=True)):
        rel = mint_group_software_relationship(group, software, m, [LOOKOUT, INTAKE_REF], CREATED)
        assert rel["external_references"][0]["source_name"] == INTAKE_SOURCE
        assert f"(Citation: {INTAKE_SOURCE})" in rel["description"]


def test_group_technique_relationship(mobile_store):
    group = mint_group(NEW, "GX0001", ["mobile-attack"], CREATED, NEW.references)
    technique = mobile_store.lookup("T1404", "attack-pattern").obj
    rel = mint_group_technique_relationship(group, technique, [INTAKE_REF], CREATED)
    assert rel["source_ref"] == group["id"] and rel["target_ref"] == technique["id"]
    assert rel["external_references"][0]["source_name"] == INTAKE_SOURCE and rel["revoked"] is False


def test_build_objects_mints_new_group_and_relationships(spec, attack_store, tmp_path):
    s = group_spec(spec, {"new": NEW})
    proposals = {"mobile-attack": MappingProposal(domain="mobile-attack", techniques=[mapping("T1430")])}
    alloc = Allocations(tmp_path / "a.json")
    preview = build_objects(s, proposals, attack_store, alloc, CREATED, commit=False)
    assert not (tmp_path / "a.json").exists()
    assert preview.allocations == {"SX0001": preview.software["id"], "GX0001": group_stix_id("Example Actor")}
    by_type = [(o["type"], o.get("relationship_type")) for o in preview.objects]
    # software, technique rel, group, group->software, group->T1404 (T1059.001 is not mobile)
    assert by_type == [
        ("malware", None), ("relationship", "uses"), ("intrusion-set", None),
        ("relationship", "uses"), ("relationship", "uses"),
    ]
    group = preview.objects[2]
    assert group["external_references"][0]["external_id"] == "GX0001"
    targets = {o["target_ref"] for o in preview.objects[3:]}
    assert preview.software["id"] in targets and len(targets) == 2
    committed = build_objects(s, proposals, attack_store, alloc, CREATED, commit=True, run_id="r1")
    assert committed.objects == preview.objects
    assert alloc.lookup("GX0001")["first_run"] == "r1"
    assert alloc.record_for("group", group["id"])["definition_sha256"]


def test_two_new_groups_get_distinct_preview_ids(spec, attack_store, tmp_path):
    other = NewGroup(name="Second Actor", description="d")
    s = group_spec(spec, {"new": NEW}, {"new": other}, {"new": NEW})  # duplicate collapses
    proposals = {"mobile-attack": MappingProposal(domain="mobile-attack", techniques=[mapping()])}
    result = build_objects(s, proposals, attack_store, Allocations(tmp_path / "a.json"), CREATED, commit=False)
    assert sorted(a for a in result.allocations if a.startswith("GX")) == ["GX0001", "GX0002"]
    assert [o["name"] for o in result.objects if o["type"] == "intrusion-set"] == [
        "Example Actor", "Second Actor"
    ]


def test_shared_new_group_across_two_runs_is_one_group(spec, attack_store, tmp_path):
    """Acceptance #12: the same user-defined group in two runs has one stix id and one GX id."""
    alloc = Allocations(tmp_path / "a.json")
    other_spec = spec.model_copy(update={"name": "Other Spyware", "aliases": []})
    results = []
    for software_spec, run_id in ((spec, "r1"), (other_spec, "r2")):
        s = group_spec(software_spec, {"new": NEW})
        proposals = {"mobile-attack": MappingProposal(domain="mobile-attack", techniques=[mapping()])}
        results.append(build_objects(s, proposals, attack_store, alloc, CREATED, commit=True, run_id=run_id))
    first, second = results
    assert first.software["id"] != second.software["id"]
    groups = [[o for o in r.objects if o["type"] == "intrusion-set"] for r in results]
    assert groups[0][0]["id"] == groups[1][0]["id"] == group_stix_id("Example Actor")
    gx = [k for k in first.allocations if k.startswith("GX")]
    assert gx == [k for k in second.allocations if k.startswith("GX")] == ["GX0001"]
    assert groups[0] == groups[1]
    # combining the two deltas dedupes the shared group by stix id
    combined = {o["id"]: o for r in results for o in r.objects}
    assert sum(o["type"] == "intrusion-set" for o in combined.values()) == 1
    assert alloc.lookup("SX0002")["name"] == "Other Spyware"


def test_proposed_existing_group_links_software(spec, attack_store, mobile_store, tmp_path):
    gm = GroupMapping(group_id="G0142", quote="Confucius deployed Pegasus.", source_name="Lookout Pegasus")
    proposals = {"mobile-attack": MappingProposal(domain="mobile-attack", techniques=[mapping()], groups=[
        gm, GroupMapping(group_id="G9999", quote="q", source_name="s"),  # unresolvable: skipped
    ])}
    result = build_objects(spec, proposals, attack_store, Allocations(tmp_path / "a.json"), CREATED, commit=False)
    rel = result.objects[-1]
    assert rel["source_ref"] == mobile_store.resolve_group("Confucius")["id"]
    assert rel["target_ref"] == result.software["id"] and len(result.objects) == 3
    assert [k for k in result.allocations if k.startswith("GX")] == []  # existing groups are never minted
    assert all(o["type"] != "intrusion-set" for o in result.objects)


def test_declined_run_mints_and_allocates_no_groups(spec, attack_store, tmp_path):
    s = group_spec(spec, {"new": NEW})
    proposals = {"mobile-attack": MappingProposal(
        domain="mobile-attack", declined=True, decline_rationale="no evidence")}
    alloc = Allocations(tmp_path / "a.json")
    result = build_objects(s, proposals, attack_store, alloc, CREATED, commit=True, run_id="r1")
    assert [o["type"] for o in result.objects] == ["malware"]
    assert alloc.lookup("GX0001") is None and list(result.allocations) == ["SX0001"]


def test_agent_technique_rel_without_evidence_cites_nothing(spec, mobile_store):
    """No evidence => no external refs (E004 fires); the pool is never cited wholesale."""
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    technique = mobile_store.lookup("T1430", "attack-pattern").obj
    rel = mint_technique_relationship(software, technique, mapping(sources=()), [LOOKOUT], CREATED)
    assert "external_references" not in rel
    assert "(Citation:" not in rel["description"]


def test_user_asserted_technique_rel_cites_the_intake_reference(spec, mobile_store):
    software = mint_software(spec, "SX0001", ["mobile-attack"], CREATED)
    technique = mobile_store.lookup("T1430", "attack-pattern").obj
    pool = [LOOKOUT, ExternalReference(source_name="mitre-mapper intake", description="user")]
    rel = mint_technique_relationship(
        software, technique, mapping(sources=(), user_asserted=True), pool, CREATED
    )
    assert [r["source_name"] for r in rel["external_references"]] == ["mitre-mapper intake"]
    assert "(Citation: mitre-mapper intake)" in rel["description"]


def test_group_mapping_with_source_outside_pool_does_not_crash(spec, attack_store, tmp_path):
    """Regression: source "Nope" is not in the pool; no empty ExternalReference, E004 reports it."""
    from mitre_mapper.lint import LintContext, lint

    gm = GroupMapping(group_id="G0142", quote="Confucius deployed Pegasus.", source_name="Nope")
    prop = MappingProposal(domain="mobile-attack", techniques=[mapping()], groups=[gm])
    alloc = Allocations(tmp_path / "a.json")
    result = build_objects(spec, {"mobile-attack": prop}, attack_store, alloc, CREATED, commit=False)
    rel = result.objects[-1]
    assert rel["target_ref"] == result.software["id"] and "external_references" not in rel
    findings = lint(
        LintContext(
            proposal=prop,
            domain="mobile-attack",
            store=attack_store.domain("mobile-attack"),
            objects=result.by_domain["mobile-attack"],
            allocations=alloc,
            spec=spec,
        )
    )
    assert "E004" in {f.rule_id for f in findings}
