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
