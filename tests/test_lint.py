import copy
import time

import pytest

from mitre_mapper.allocations import Allocations
from mitre_mapper.lint import RULES, LintContext, has_errors, lint
from mitre_mapper.mint import build_objects
from mitre_mapper.models import (
    EvidenceQuote,
    ExternalReference,
    IntakeSpec,
    MappingProposal,
    Severity,
    TechniqueMapping,
)

CREATED = "2026-10-03T12:34:56.000Z"
SPEC = IntakeSpec(
    name="Pegasus for iOS (thin)",
    type="malware",
    platforms=["iOS"],
    body="Spyware.",
    references=[ExternalReference(source_name="Lookout Pegasus", url="https://example.com/p.pdf")],
)


def proposal(*tids, **kw):
    return MappingProposal(
        domain="mobile-attack",
        techniques=[
            TechniqueMapping(
                technique_id=t,
                rationale="r",
                evidence=[EvidenceQuote(source_name="s", quote="q")],
            )
            for t in tids
        ],
        **kw,
    )


@pytest.fixture
def make_ctx(attack_store, mobile_store, tmp_path):
    def make(prop, mutate=None):
        alloc = Allocations(tmp_path / "allocations.json")
        built = build_objects(
            SPEC, {"mobile-attack": prop}, attack_store, alloc, CREATED, commit=False
        )
        objects = copy.deepcopy(built.by_domain["mobile-attack"])
        if mutate:
            mutate(objects)
        return LintContext(prop, "mobile-attack", mobile_store, objects, alloc)

    return make


def ids(findings):
    return sorted(f.rule_id for f in findings)


def test_registry_has_wave2_rules():
    assert sorted(RULES) == ["E001", "E002", "E008", "E009", "E010"]
    assert all(r.severity is Severity.ERROR for r in RULES.values())


def test_clean_real_proposal_has_no_findings(make_ctx):
    findings = lint(make_ctx(proposal("T1430", "T1404")))
    assert findings == [] and not has_errors(findings)


def test_e001_empty_proposal(make_ctx):
    findings = RULES["E001"].check(make_ctx(proposal()))
    assert ids(findings) == ["E001"]
    assert has_errors(findings)


def test_e001_declined_is_fine(make_ctx):
    declined = MappingProposal(
        domain="mobile-attack", declined=True, decline_rationale="no evidence"
    )
    assert lint(make_ctx(declined)) == []


def test_e002_cross_domain_id_not_found(make_ctx):
    [f] = RULES["E002"].check(make_ctx(proposal("T1430", "T1059.001")))  # enterprise id
    assert f.details == {"technique_id": "T1059.001", "domain": "mobile-attack", "reason": "not_found"}
    assert f.target == "T1059.001"


def test_e002_revoked_id_reports_successor(make_ctx):
    [f] = RULES["E002"].check(make_ctx(proposal("T1579")))
    assert f.details["reason"] == "revoked"
    assert f.details["successor_id"] == "T1634.001"
    assert f.details["successor_name"] == "Keychain"
    assert "T1634.001" in f.message


def test_e002_deprecated_without_successor(make_ctx, mobile_store):
    dead = next(
        mobile_store.attack_id(o)
        for o in mobile_store.objects("attack-pattern", include_inactive=True)
        if o.get("x_mitre_deprecated") and not o.get("revoked")
    )
    [f] = RULES["E002"].check(make_ctx(proposal(dead)))
    assert f.details["reason"] == "deprecated"


def test_e002_nonexistent_id(make_ctx):
    [f] = RULES["E002"].check(make_ctx(proposal("T9999")))
    assert f.details["reason"] == "not_found"


def test_e008_bad_ids_and_dangling_refs(make_ctx):
    def mutate(objs):
        objs[0]["id"] = "malware--not-a-uuid"
        objs[1]["target_ref"] = "attack-pattern--00000000-0000-4000-8000-000000000000"
        objs[1]["source_ref"] = "malware--11111111-1111-5111-8111-111111111111"  # uuid5 shape

    findings = RULES["E008"].check(make_ctx(proposal("T1430"), mutate))
    msgs = " | ".join(f.message for f in findings)
    assert ids(findings) == ["E008"] * 3
    assert "invalid STIX id" in msgs and "does not resolve" in msgs and "source_ref" in msgs


def test_e008_clean(make_ctx):
    assert RULES["E008"].check(make_ctx(proposal("T1430"))) == []


def test_e009_mitre_ref_must_be_first(make_ctx):
    def mutate(objs):
        refs = objs[0]["external_references"]
        refs.append(refs.pop(0))

    [f] = RULES["E009"].check(make_ctx(proposal("T1430"), mutate))
    assert f.rule_id == "E009" and f.target.startswith("malware--")


def test_e009_id_format_and_real_attack_id_rejected(make_ctx):
    def real_id(objs):
        objs[0]["external_references"][0]["external_id"] = "S0289"

    def wrong_source(objs):
        objs[0]["external_references"][0]["source_name"] = "mitre-ics-attack"

    assert ids(RULES["E009"].check(make_ctx(proposal("T1430"), real_id))) == ["E009"]
    assert ids(RULES["E009"].check(make_ctx(proposal("T1430"), wrong_source))) == ["E009"]


def test_e009_must_match_allocations(make_ctx):
    def mutate(objs):
        objs[0]["external_references"][0]["external_id"] = "SX0042"

    [f] = RULES["E009"].check(make_ctx(proposal("T1430"), mutate))
    assert f.details == {"external_id": "SX0042", "expected": "SX0001"}


def test_e010_round_trip_passes(make_ctx):
    assert RULES["E010"].check(make_ctx(proposal("T1430", "T1404", "T1636.002"))) == []


def test_e010_is_fast_on_mobile(make_ctx):
    ctx = make_ctx(proposal("T1430"))
    start = time.perf_counter()
    RULES["E010"].check(ctx)
    assert time.perf_counter() - start < 3


def test_e010_detects_collision_with_existing_object(make_ctx):
    def mutate(objs):
        objs[0]["external_references"][0]["external_id"] = "S0289"

    findings = RULES["E010"].check(make_ctx(proposal("T1430"), mutate))
    assert ids(findings) == ["E010"] and "already exists" in findings[0].message


def test_e010_reports_unparseable_objects(make_ctx):
    def mutate(objs):
        objs[0]["created"] = "garbage"

    findings = RULES["E010"].check(make_ctx(proposal("T1430"), mutate))
    assert ids(findings) == ["E010"]


def test_lint_aggregates_all_rules(make_ctx):
    findings = lint(make_ctx(proposal("T1059.001", "T1579")))
    assert set(ids(findings)) == {"E002"}
    assert has_errors(findings)


@pytest.mark.slow
def test_enterprise_round_trip_and_revoked(datasets_dir, tmp_path):
    from mitre_mapper.store import AttackStore

    store = AttackStore(datasets_dir)
    spec = IntakeSpec(name="Test Enterprise Tool", type="tool", platforms=["Windows"], body="x")
    prop = MappingProposal(
        domain="enterprise-attack",
        techniques=[
            TechniqueMapping(technique_id="T1059.001", rationale="r"),
            TechniqueMapping(technique_id="T1086", rationale="r"),  # revoked -> T1059.001
        ],
    )
    alloc = Allocations(tmp_path / "a.json")
    built = build_objects(spec, {"enterprise-attack": prop}, store, alloc, CREATED, commit=False)
    ctx = LintContext(
        prop, "enterprise-attack", store.domain("enterprise-attack"),
        built.by_domain["enterprise-attack"], alloc,
    )
    assert ids(lint(ctx)) == ["E002"]
    [f] = RULES["E002"].check(ctx)
    assert f.details["successor_id"] == "T1059.001"
