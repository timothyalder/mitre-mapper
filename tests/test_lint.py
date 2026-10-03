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

QUOTE = "collects location data"
REPORT_TEXT = "The Lookout report says Pegasus for iOS (thin) collects location data and SMS messages."
DEFAULT_EVIDENCE = {"Lookout Pegasus": REPORT_TEXT}  # real text for every technique quote below

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
                evidence=[EvidenceQuote(source_name="Lookout Pegasus", quote=QUOTE)],
            )
            for t in tids
        ],
        **kw,
    )


@pytest.fixture
def make_ctx(attack_store, mobile_store, tmp_path):
    def make(prop, mutate=None, spec=SPEC, evidence=None):
        alloc = Allocations(tmp_path / "allocations.json")
        built = build_objects(
            spec, {"mobile-attack": prop}, attack_store, alloc, CREATED, commit=False
        )
        objects = copy.deepcopy(built.by_domain["mobile-attack"])
        if mutate:
            mutate(objects)
        return LintContext(
            prop, "mobile-attack", mobile_store, objects, alloc, DEFAULT_EVIDENCE if evidence is None else evidence, spec
        )

    return make


def ids(findings):
    return sorted(f.rule_id for f in findings)


def test_registry_has_all_rules():
    assert sorted(RULES) == [
        *[f"E{i:03d}" for i in range(1, 13)],
        *[f"I{i:03d}" for i in range(1, 5)],
        *[f"W{i:03d}" for i in range(1, 6)],
    ]
    for rid, rule in RULES.items():
        assert rule.severity.value[0] == rid[0]


def test_clean_proposal_has_only_info_and_no_warnings(make_ctx):
    findings = lint(make_ctx(proposal("T1430", "T1404")))
    assert {f.severity for f in findings} <= {Severity.INFO}


def test_clean_real_proposal_has_no_errors(make_ctx):
    findings = lint(make_ctx(proposal("T1430", "T1404")))
    assert not has_errors(findings)
    assert [f.rule_id for f in findings if f.severity is not Severity.INFO] == []


def test_e001_empty_proposal(make_ctx):
    findings = RULES["E001"].check(make_ctx(proposal()))
    assert ids(findings) == ["E001"]
    assert has_errors(findings)


def test_e001_declined_is_fine(make_ctx):
    declined = MappingProposal(
        domain="mobile-attack", declined=True, decline_rationale="no evidence"
    )
    assert not has_errors(lint(make_ctx(declined)))
    assert ids(lint(make_ctx(declined))) == []  # I001-I003 skip declined proposals


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
    assert {f.rule_id for f in findings if f.severity is Severity.ERROR} == {"E002"}
    assert has_errors(findings)


@pytest.mark.slow
def test_enterprise_round_trip_and_revoked(datasets_dir, tmp_path):
    from mitre_mapper.store import AttackStore

    store = AttackStore(datasets_dir)
    ref = ExternalReference(source_name="Src", url="https://example.com")
    spec = IntakeSpec(
        name="Test Enterprise Tool", type="tool", platforms=["Windows"], body="x", references=[ref]
    )
    ev = [EvidenceQuote(source_name="Src", quote=QUOTE)]
    prop = MappingProposal(
        domain="enterprise-attack",
        techniques=[
            TechniqueMapping(technique_id="T1059.001", rationale="r", evidence=ev),
            TechniqueMapping(technique_id="T1086", rationale="r", evidence=ev),  # revoked -> T1059.001
        ],
    )
    alloc = Allocations(tmp_path / "a.json")
    built = build_objects(spec, {"enterprise-attack": prop}, store, alloc, CREATED, commit=False)
    ctx = LintContext(
        prop, "enterprise-attack", store.domain("enterprise-attack"),
        built.by_domain["enterprise-attack"], alloc, evidence={"Src": REPORT_TEXT}, spec=spec,
    )
    assert [f.rule_id for f in lint(ctx) if f.severity is Severity.ERROR] == ["E002", "E003"]
    [f] = RULES["E002"].check(ctx)
    assert f.details["successor_id"] == "T1059.001"


# --------------------------------------------------------------------------- Wave 3B rules


def test_e003_duplicate_technique_relationships(make_ctx):
    [f] = RULES["E003"].check(make_ctx(proposal("T1430", "T1430")))
    assert f.rule_id == "E003" and f.severity is Severity.ERROR
    assert f.details["count"] == 2 and f.details["target_attack_id"] == "T1430"
    assert f.details["relationship_type"] == "uses"
    assert f.details["requested_ids"] == ["T1430", "T1430"]


def test_e003_revoked_alias_duplicates_successor(make_ctx):
    [f] = RULES["E003"].check(make_ctx(proposal("T1634.001", "T1579")))  # T1579 -> T1634.001
    assert f.details["target_attack_id"] == "T1634.001"
    assert f.details["requested_ids"] == ["T1634.001", "T1579"]
    assert "successor" in f.message


def test_e003_clean(make_ctx):
    assert RULES["E003"].check(make_ctx(proposal("T1430", "T1404"))) == []


def test_e004_missing_description_and_refs(make_ctx):
    def mutate(objs):
        objs[1]["description"] = "  "
        objs[2]["external_references"] = []

    findings = RULES["E004"].check(make_ctx(proposal("T1430", "T1404"), mutate))
    assert ids(findings) == ["E004", "E004"]
    assert findings[0].details["has_description"] is False
    assert findings[1].details["n_external_references"] == 0


def test_e004_clean(make_ctx):
    assert RULES["E004"].check(make_ctx(proposal("T1430"))) == []


def test_e005_unresolved_citation(make_ctx):
    def mutate(objs):
        objs[1]["description"] += "(Citation: Ghost Source)"

    [f] = RULES["E005"].check(make_ctx(proposal("T1430"), mutate))
    assert f.details["missing"] == ["Ghost Source"]
    assert "Lookout Pegasus" in f.details["available"] or f.details["available"] == []


def test_e005_resolves_when_ref_present(make_ctx):
    p = TechniqueMapping(
        technique_id="T1430",
        rationale="r",
        evidence=[EvidenceQuote(source_name="Lookout Pegasus", quote=QUOTE)],
        user_asserted=False,
    )
    ctx = make_ctx(MappingProposal(domain="mobile-attack", techniques=[p]))
    assert "(Citation: Lookout Pegasus)" in ctx.objects[1]["description"]
    assert RULES["E005"].check(ctx) == []


def test_e006_clean_minted_objects(make_ctx):
    assert RULES["E006"].check(make_ctx(proposal("T1430"))) == []


def test_e006_missing_required_fields(make_ctx):
    def mutate(objs):
        del objs[0]["x_mitre_version"]
        del objs[1]["x_mitre_modified_by_ref"]

    findings = RULES["E006"].check(make_ctx(proposal("T1430"), mutate))
    assert ids(findings) == ["E006", "E006"]
    assert findings[0].details["missing"] == ["x_mitre_version"]
    assert findings[0].details["profile"] == "software:malware"
    assert findings[1].details["profile"] == "relationship:uses:software->attack-pattern"


def test_domain_baseline_mobile_profile(mobile_store):
    from mitre_mapper.lint import domain_baseline

    required = domain_baseline(mobile_store).profiles["software:malware"]
    assert {"x_mitre_version", "x_mitre_domains", "labels", "created_by_ref"} <= required
    # 79.8% of mobile malware carry platforms: below the 95% bar, so not required
    assert "x_mitre_platforms" not in required
    assert "revoked" not in required  # absent on all mobile software


def test_e007_domain_must_be_listed(make_ctx):
    def mutate(objs):
        objs[0]["x_mitre_domains"] = ["enterprise-attack"]

    [f] = RULES["E007"].check(make_ctx(proposal("T1430"), mutate))
    assert f.details == {"domain": "mobile-attack", "x_mitre_domains": ["enterprise-attack"]}


def test_e007_superset_is_fine(make_ctx):
    def mutate(objs):
        objs[0]["x_mitre_domains"] = ["enterprise-attack", "mobile-attack"]

    assert RULES["E007"].check(make_ctx(proposal("T1430"), mutate)) == []


def test_w001_platform_mismatch_and_match(make_ctx):
    android = SPEC.model_copy(update={"platforms": ["Android"]})
    [f] = RULES["W001"].check(make_ctx(proposal("T1634.001", "T1430"), spec=android))
    assert f.details["technique_id"] == "T1634.001"  # iOS-only technique
    assert f.details["technique_platforms"] == ["iOS"]
    assert RULES["W001"].check(make_ctx(proposal("T1634.001", "T1430"))) == []  # iOS software


def test_w001_skipped_in_ics(attack_store, tmp_path):
    ics = attack_store.domain("ics-attack")
    tid = ics.attack_id(ics.objects("attack-pattern")[0])
    ev = [EvidenceQuote(source_name="Lookout Pegasus", quote=QUOTE)]
    prop = MappingProposal(
        domain="ics-attack",
        techniques=[TechniqueMapping(technique_id=tid, rationale="r", evidence=ev)],
    )
    spec = SPEC.model_copy(update={"platforms": ["Windows"]})
    alloc = Allocations(tmp_path / "a.json")
    built = build_objects(spec, {"ics-attack": prop}, attack_store, alloc, CREATED, commit=False)
    ctx = LintContext(prop, "ics-attack", ics, built.by_domain["ics-attack"], alloc, spec=spec)
    assert RULES["W001"].check(ctx) == []


def test_w002_name_collision_names_existing_id(make_ctx):
    spec = SPEC.model_copy(update={"name": "pegasus FOR ios"})
    [f] = RULES["W002"].check(make_ctx(proposal("T1430"), spec=spec))
    assert f.severity is Severity.WARN
    assert f.details["attack_id"] == "S0289"
    assert "S0289" in f.message and "may be" in f.message


def test_w002_alias_collision(make_ctx, mobile_store):
    existing = next(
        o for o in mobile_store.objects("malware") if len(o.get("x_mitre_aliases", [])) > 1
    )
    alias = existing["x_mitre_aliases"][-1]
    spec = SPEC.model_copy(update={"aliases": [alias.upper()]})
    findings = RULES["W002"].check(make_ctx(proposal("T1430"), spec=spec))
    assert mobile_store.attack_id(existing) in {f.details["attack_id"] for f in findings}


def test_w002_clean(make_ctx):
    assert RULES["W002"].check(make_ctx(proposal("T1430"))) == []


def test_w003_parent_and_child(make_ctx):
    [f] = RULES["W003"].check(make_ctx(proposal("T1636", "T1636.002", "T1636.003")))
    assert f.details == {"parent": "T1636", "children": ["T1636.002", "T1636.003"]}
    assert RULES["W003"].check(make_ctx(proposal("T1636.002", "T1636.003"))) == []


def test_w004_tool_in_ics(attack_store, tmp_path):
    ics = attack_store.domain("ics-attack")
    tid = ics.attack_id(ics.objects("attack-pattern")[0])
    ev = [EvidenceQuote(source_name="Lookout Pegasus", quote=QUOTE)]
    prop = MappingProposal(
        domain="ics-attack",
        techniques=[TechniqueMapping(technique_id=tid, rationale="r", evidence=ev)],
    )
    alloc = Allocations(tmp_path / "a.json")
    assert not ics.objects("tool")  # the precedent being pinned
    for kind, expected in (("tool", ["W004"]), ("malware", [])):
        spec = SPEC.model_copy(update={"type": kind, "name": "Zzz Test Software"})
        built = build_objects(
            spec, {"ics-attack": prop}, attack_store, alloc, CREATED, commit=False
        )
        ctx = LintContext(prop, "ics-attack", ics, built.by_domain["ics-attack"], alloc, spec=spec)
        assert ids(RULES["W004"].check(ctx)) == expected
        assert RULES["E006"].check(ctx) == []  # ICS tool falls back to the pooled software profile


def test_w004_not_in_mobile(make_ctx):
    assert RULES["W004"].check(make_ctx(proposal("T1430"))) == []


def test_measured_medians_mobile_and_ics(mobile_store, attack_store):
    from mitre_mapper.lint import domain_baseline

    mobile = domain_baseline(mobile_store)
    assert (mobile.median_techniques, mobile.median_tactics, mobile.median_groups) == (11, 5, 0)
    assert mobile.n_software == 126
    ics = domain_baseline(attack_store.domain("ics-attack"))
    assert (ics.median_techniques, ics.median_tactics, ics.median_groups) == (5, 4, 1)
    assert ics.n_software == 23


def test_i001_i002_i003_inform_and_never_block(make_ctx):
    ctx = make_ctx(proposal("T1430", "T1404"))
    [i1] = RULES["I001"].check(ctx)
    assert i1.severity is Severity.INFO
    assert i1.details["count"] == 2 and i1.details["median"] == 11
    [i2] = RULES["I002"].check(ctx)
    assert i2.details["median"] == 5 and i2.details["count"] == len(i2.details["tactics"]) >= 1
    [i3] = RULES["I003"].check(ctx)
    assert i3.details["count"] == 0 and i3.details["median"] == 0
    assert not has_errors([i1, i2, i3])


def test_i004_user_asserted_counts(make_ctx):
    from mitre_mapper.models import GroupMapping

    p = MappingProposal(
        domain="mobile-attack",
        techniques=[
            TechniqueMapping(technique_id="T1430", rationale="r", user_asserted=True),
            TechniqueMapping(technique_id="T1404", rationale="r"),
        ],
    )
    [f] = RULES["I004"].check(make_ctx(p))
    assert f.severity is Severity.INFO
    assert f.details["counts"]["techniques"] == 1 and f.details["techniques"] == ["T1430"]
    assert RULES["I004"].check(make_ctx(proposal("T1430"))) == []
    assert GroupMapping  # imported for the group-asserted test in the groups section


@pytest.mark.slow
def test_enterprise_baseline_matches_plan_calibration(attack_store):
    from mitre_mapper.lint import domain_baseline

    base = domain_baseline(attack_store.domain("enterprise-attack"))
    assert base.n_software == 825
    assert (base.median_techniques, base.median_tactics, base.median_groups) == (11, 6, 1)
    # 97.3% of enterprise malware carry platforms -> required there (not in mobile)
    assert "x_mitre_platforms" in base.profiles["software:malware"]
    assert "x_mitre_platforms" not in base.profiles["software:tool"]  # 82.1%


# --------------------------------------------------------------------------- groups (E011, W005)

GROUP_SPEC = SPEC.model_copy(
    update={"references": [ExternalReference(source_name="Src", url="https://example.com/s")]}
)


@pytest.fixture
def mobile_group(mobile_store):
    group = next(
        g for g in mobile_store.objects("intrusion-set") if len(g.get("aliases", [])) > 1
    )
    return mobile_store.attack_id(group), group


def group_proposal(group_id, quote, source="Src", **kw):
    from mitre_mapper.models import GroupMapping

    return MappingProposal(
        domain="mobile-attack",
        techniques=[
            TechniqueMapping(
                technique_id="T1430",
                rationale="r",
                evidence=[EvidenceQuote(source_name="Src", quote=QUOTE)],
            )
        ],
        groups=[GroupMapping(group_id=group_id, quote=quote, source_name=source, **kw)],
    )


def test_e011_grounded_quote_passes_and_group_link_is_minted(make_ctx, mobile_group):
    gid, group = mobile_group
    alias = group["aliases"][-1]
    quote = f"{alias} deployed Pegasus for iOS (thin) against targets."
    ctx = make_ctx(
        group_proposal(gid, quote),
        spec=GROUP_SPEC,
        evidence={"Src": f"Intro.\n  {alias}  deployed\nPegasus for iOS (thin) against targets. Tail. " + REPORT_TEXT},
    )
    assert RULES["E011"].check(ctx) == []
    assert any(o["type"] == "relationship" and o["source_ref"] == group["id"] for o in ctx.objects)
    assert not has_errors(lint(ctx))


def test_e011_failure_details(make_ctx, mobile_group):
    gid, group = mobile_group
    name = group["name"]
    cases = {
        "not in evidence": (f"{name} used Pegasus for iOS (thin).", "completely different text"),
        "missing group": ("Pegasus for iOS (thin) was seen in the wild.",
                          "Pegasus for iOS (thin) was seen in the wild."),
        "missing software": (f"{name} was active.", f"{name} was active."),
    }
    for label, (quote, evidence) in cases.items():
        [f] = RULES["E011"].check(
            make_ctx(group_proposal(gid, quote), spec=GROUP_SPEC, evidence={"Src": evidence})
        )
        assert f.rule_id == "E011" and f.severity is Severity.ERROR, label
        assert f.details["group_id"] == gid and f.details["quote"] == quote, label
        assert f.details["evidence_sources"] == ["Src"], label
    assert "verbatim" in f.message or "software" in f.message


def test_e011_unknown_source_and_group(make_ctx, mobile_group):
    gid, _ = mobile_group
    [f] = RULES["E011"].check(make_ctx(group_proposal(gid, "q"), spec=GROUP_SPEC))
    assert "no fetched evidence" in f.details["reason"]
    [f] = RULES["E011"].check(
        make_ctx(group_proposal("G9999", "q"), spec=GROUP_SPEC, evidence={"Src": "q"})
    )
    assert "not an active group" in f.details["reason"]


def test_e011_skips_user_asserted(make_ctx, mobile_group):
    gid, _ = mobile_group
    ctx = make_ctx(group_proposal(gid, "", source="", user_asserted=True), spec=GROUP_SPEC)
    assert RULES["E011"].check(ctx) == []
    [i4] = RULES["I004"].check(ctx)
    assert i4.details["group_refs"] == [gid]
    [i3] = RULES["I003"].check(ctx)
    assert i3.details["user_asserted"] == [gid] and i3.details["agent_proposed"] == []


def new_group_spec(**group_kw):
    from mitre_mapper.models import IntakeGroup, NewGroup

    new = NewGroup(
        name=group_kw.pop("name", "Zzz Test Actor"),
        description="d",
        techniques=group_kw.pop("techniques", ["T1404"]),
        **group_kw,
    )
    # proposal() cites "Lookout Pegasus"; an agent technique with no pooled evidence now gets
    # no external reference (E004), so the spec must carry that source.
    return GROUP_SPEC.model_copy(
        update={
            "groups": [IntakeGroup(new=new)],
            "references": [*GROUP_SPEC.references, *SPEC.references],
        }
    )


def test_new_group_minted_objects_lint_clean(make_ctx):
    spec = new_group_spec()
    ctx = make_ctx(proposal("T1430"), spec=spec)
    assert {"intrusion-set"} <= {o["type"] for o in ctx.objects}
    findings = lint(ctx)
    assert not has_errors(findings), [f.message for f in findings if f.severity is Severity.ERROR]
    [i4] = RULES["I004"].check(ctx)
    assert i4.details["new_groups"] == ["Zzz Test Actor"]
    assert i4.details["new_group_techniques"] == ["T1404"]
    assert RULES["W005"].check(ctx) == []


def test_new_group_e009_wrong_gx_id(make_ctx):
    def mutate(objs):
        group = next(o for o in objs if o["type"] == "intrusion-set")
        group["external_references"][0]["external_id"] = "GX0099"

    [f] = RULES["E009"].check(make_ctx(proposal("T1430"), mutate, spec=new_group_spec()))
    assert f.details["external_id"] == "GX0099"


def test_w005_new_group_matches_existing_attack_group(make_ctx, mobile_group):
    gid, group = mobile_group
    alias = group["aliases"][-1]
    [f] = RULES["W005"].check(
        make_ctx(proposal("T1430"), spec=new_group_spec(name="Zzz Actor", aliases=[alias.lower()]))
    )
    assert f.severity is Severity.WARN
    assert f.details["kind"] == "matches_existing_group"
    assert f.details["existing_attack_id"] == gid and gid in f.message


def test_w005_conflicting_definition_in_allocations(make_ctx, tmp_path):
    from mitre_mapper.mint import group_stix_id

    first = new_group_spec()
    ctx = make_ctx(proposal("T1430"), spec=first)
    from mitre_mapper.groups import definition_sha256

    ctx.allocations.allocate(
        "group", group_stix_id("Zzz Test Actor"), "Zzz Test Actor", "run-1",
        definition_sha256=definition_sha256(first.groups[0].new),
    )
    assert RULES["W005"].check(ctx) == []  # same definition: fine
    changed = new_group_spec(aliases=["Zzz Other Name"])
    ctx2 = LintContext(ctx.proposal, ctx.domain, ctx.store, ctx.objects, ctx.allocations, spec=changed)
    [f] = RULES["W005"].check(ctx2)
    assert f.details["kind"] == "definition_conflict" and f.details["first_run"] == "run-1"
    assert f.details["attack_id"].startswith("GX")


def _e012(prop, evidence, spec=SPEC):
    ctx = LintContext(prop, "mobile-attack", None, [], None, evidence, spec)  # type: ignore[arg-type]
    return RULES["E012"].check(ctx)


def _tech(tid, source, quote, **kw):
    return TechniqueMapping(
        technique_id=tid, rationale="r", evidence=[EvidenceQuote(source_name=source, quote=quote)], **kw
    )


def test_e012_passes_for_verbatim_quotes_with_normalisation():
    prop = MappingProposal(domain="mobile-attack", techniques=[_tech("T1430", "Lookout Pegasus", "  COLLECTS\nlocation   data ")])
    assert _e012(prop, {"Lookout Pegasus": REPORT_TEXT}) == []


def test_e012_quote_not_found():
    prop = MappingProposal(
        domain="mobile-attack",
        techniques=[_tech("T1430", "Lookout Pegasus", "collects location data ... and SMS messages")],
    )
    [f] = _e012(prop, {"Lookout Pegasus": REPORT_TEXT})
    assert f.rule_id == "E012" and f.severity is Severity.ERROR and f.target == "T1430"
    assert f.details["technique_id"] == "T1430" and f.details["source_name"] == "Lookout Pegasus"
    assert f.details["reason"] == "quote_not_found"
    assert f.details["quote_prefix"].startswith("collects location data ...")


def test_e012_source_missing_when_no_fetched_text():
    prop = MappingProposal(domain="mobile-attack", techniques=[_tech("T1430", "Lookout Pegasus", "collects location data")])
    [f] = _e012(prop, {})
    assert f.details["reason"] == "source_missing"
    [g] = _e012(prop, {"Other": REPORT_TEXT})
    assert g.details["reason"] == "source_missing"


def test_e012_intake_prose_is_a_source_and_the_user_asserted_name_is_not():
    spec = SPEC.model_copy(update={"body": "Pegasus reads SMS messages and call logs."})
    ok = MappingProposal(domain="mobile-attack", techniques=[_tech("T1430", "mitre-mapper intake description", "reads sms messages")])
    assert _e012(ok, {}, spec) == []
    wrong = MappingProposal(domain="mobile-attack", techniques=[_tech("T1430", "mitre-mapper intake", "reads sms messages")])
    assert _e012(wrong, {}, spec)[0].details["reason"] == "source_missing"
    absent = MappingProposal(domain="mobile-attack", techniques=[_tech("T1430", "mitre-mapper intake description", "records audio")])
    assert _e012(absent, {}, spec)[0].details["reason"] == "quote_not_found"


def test_e012_exempts_user_asserted_and_checks_every_quote():
    asserted = TechniqueMapping(technique_id="T1404", rationale="r", user_asserted=True)
    two = TechniqueMapping(
        technique_id="T1430",
        rationale="r",
        evidence=[
            EvidenceQuote(source_name="Lookout Pegasus", quote="collects location data"),
            EvidenceQuote(source_name="Lookout Pegasus", quote="invented sentence"),
        ],
    )
    prop = MappingProposal(domain="mobile-attack", techniques=[asserted, two])
    [f] = _e012(prop, {"Lookout Pegasus": REPORT_TEXT})
    assert f.details["quote_prefix"] == "invented sentence"
