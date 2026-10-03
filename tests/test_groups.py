"""E011 quote check and W005 conflict helpers, pinned to real ATT&CK groups."""

import pytest

from mitre_mapper.allocations import Allocations
from mitre_mapper.groups import (
    check_group_quote,
    check_new_group_conflicts,
    definition_sha256,
    normalize_text,
)
from mitre_mapper.mint import group_stix_id
from mitre_mapper.models import GroupMapping, IntakeGroup, IntakeSpec, NewGroup

EVIDENCE = {
    "Blog": (
        "Researchers found that the Confucius\n  APT group deployed Pegasus   against targets in "
        "South Asia.  Chrysaor was not observed."
    )
}


def spec(**kw) -> IntakeSpec:
    return IntakeSpec(name="Pegasus for iOS", type="malware", aliases=["Pegasus"], **kw)


def mapping(quote, source="Blog", group="G0142", **kw) -> GroupMapping:
    return GroupMapping(group_id=group, quote=quote, source_name=source, **kw)


def test_quote_passes_whitespace_and_case_insensitive(mobile_store):
    check = check_group_quote(
        mapping("confucius apt group deployed pegasus against targets"), spec(), mobile_store, EVIDENCE
    )
    assert check.passed and check.reason == "ok" and check.group_id == "G0142"
    assert check.source_name == "Blog"
    assert check.software_aliases_matched == ["Pegasus"]
    assert check.group_aliases_matched == ["Confucius", "Confucius APT"]


def test_quote_fails_when_not_in_evidence(mobile_store):
    check = check_group_quote(
        mapping("Confucius deployed Pegasus in Antarctica"), spec(), mobile_store, EVIDENCE
    )
    assert not check.passed and "verbatim" in check.reason


def test_quote_fails_when_source_missing(mobile_store):
    check = check_group_quote(mapping("x", source="Nope"), spec(), mobile_store, EVIDENCE)
    assert not check.passed and "no fetched evidence" in check.reason


def test_quote_must_name_software_and_group(mobile_store):
    no_software = check_group_quote(
        mapping("Confucius APT group deployed"), spec(), mobile_store, EVIDENCE
    )
    assert not no_software.passed and "software" in no_software.reason
    assert no_software.group_aliases_matched
    no_group = check_group_quote(
        mapping("deployed Pegasus against targets in South Asia"), spec(), mobile_store, EVIDENCE
    )
    assert not no_group.passed and "Confucius" not in no_group.reason.split("name or alias of ")[0]
    assert "G0142" in no_group.reason and no_group.software_aliases_matched == ["Pegasus"]


def test_group_name_matches_whole_words_only(mobile_store):
    ev = {"Blog": "ConfuciusX deployed Pegasus"}
    check = check_group_quote(mapping("ConfuciusX deployed Pegasus"), spec(), mobile_store, ev)
    assert not check.passed and check.group_aliases_matched == []


def test_alias_of_group_counts(mobile_store):
    ev = {"Blog": "Octo Tempest used Pegasus for iOS in 2024."}
    check = check_group_quote(
        mapping("Octo Tempest used Pegasus for iOS", group="G1015"), spec(), mobile_store, ev
    )
    assert check.passed and check.group_aliases_matched == ["Octo Tempest"]
    assert check.software_aliases_matched == ["Pegasus for iOS", "Pegasus"]


def test_unknown_group_fails(mobile_store):
    check = check_group_quote(mapping("q", group="G9999"), spec(), mobile_store, EVIDENCE)
    assert not check.passed and "G9999" in check.reason


def test_user_asserted_is_not_checked(mobile_store):
    m = GroupMapping(group_id="G0142", user_asserted=True)
    check = check_group_quote(m, spec(), mobile_store, {})
    assert check.passed and "user-asserted" in check.reason


def test_typographic_quotes_are_flattened(mobile_store):
    ev = {"Blog": "Confucius’s toolkit includes “Pegasus”"}
    check = check_group_quote(
        mapping("Confucius's toolkit includes \"Pegasus\""), spec(), mobile_store, ev
    )
    assert check.passed
    assert normalize_text("A—B  C") == "a-b c"


# --- W005 ----------------------------------------------------------------------


def new_group(name="Example Actor", **kw) -> NewGroup:
    return NewGroup(name=name, description=kw.pop("description", "An actor."), **kw)


def spec_with(*groups: NewGroup) -> IntakeSpec:
    return spec(groups=[IntakeGroup(new=g) for g in groups])


def test_no_conflict_for_fresh_group(tmp_path, mobile_store):
    s = spec_with(new_group())
    assert check_new_group_conflicts(s, Allocations(tmp_path / "a.json"), mobile_store) == []
    assert check_new_group_conflicts(s, Allocations(tmp_path / "a.json"), None) == []


def test_definition_conflict_with_allocated_group(tmp_path):
    alloc = Allocations(tmp_path / "a.json")
    first = new_group(aliases=["EA"])
    alloc.allocate("group", group_stix_id(first.name), first.name, "run1",
                   definition_sha256=definition_sha256(first))
    assert check_new_group_conflicts(spec_with(first), alloc, None) == []  # same definition
    same_but_reordered = new_group(name="example  ACTOR", aliases=["EA"])
    assert check_new_group_conflicts(spec_with(same_but_reordered), alloc, None) == []
    changed = new_group(aliases=["EA"], description="A different description.")
    (conflict,) = check_new_group_conflicts(spec_with(changed), alloc, None)
    assert conflict["kind"] == "definition_conflict"
    assert conflict["attack_id"] == "GX0001" and conflict["first_run"] == "run1"


def test_legacy_allocation_without_hash_does_not_conflict(tmp_path):
    alloc = Allocations(tmp_path / "a.json")
    g = new_group()
    alloc.allocate("group", group_stix_id(g.name), g.name, "run1")
    assert check_new_group_conflicts(spec_with(g), alloc, None) == []


def test_conflict_within_one_intake(tmp_path):
    a, b = new_group(), new_group(description="other")
    (conflict,) = check_new_group_conflicts(spec_with(a, b), Allocations(tmp_path / "a.json"), None)
    assert conflict["kind"] == "definition_conflict" and "twice" in conflict["message"]


def test_new_group_matching_existing_attack_group(tmp_path, mobile_store):
    by_alias = new_group(name="My Actor", aliases=["octo tempest"])
    (found,) = check_new_group_conflicts(
        spec_with(by_alias), Allocations(tmp_path / "a.json"), mobile_store
    )
    assert found["kind"] == "matches_existing_group"
    assert found["existing_attack_id"] == "G1015" and "ref: G1015" in found["message"]
    assert found["matched"] == "octo tempest"


def test_definition_hash_is_stable_and_sensitive():
    g = new_group(aliases=["B", "A"], techniques=["T1430", "T1404"])
    same = new_group(name=" example actor", aliases=["a", "b", "Example Actor"], techniques=["T1404", "T1430"])
    assert definition_sha256(g) == definition_sha256(same)
    assert definition_sha256(g) != definition_sha256(new_group(aliases=["B", "A"], techniques=["T1430"]))


@pytest.mark.slow
def test_enterprise_vendor_names_pass_quote_check(attack_store):
    ent = attack_store.domain("enterprise-attack")
    cme = IntakeSpec(name="CrackMapExec", type="tool", aliases=["CME"])
    ev = {
        "CS": "CARBON SPIDER has used CrackMapExec to move laterally.",
        "Sym": "Chafer, also known as APT39, leveraged CrackMapExec.",
        "CISA": "IRON LIBERTY operators ran CME.",
        "MS": "Octo Tempest used CrackMapExec.",
    }
    cases = [
        ("G0046", "CS", "CARBON SPIDER has used CrackMapExec", "Carbon Spider"),
        ("G0087", "Sym", "Chafer, also known as APT39, leveraged CrackMapExec", "Chafer"),
        ("G0035", "CISA", "IRON LIBERTY operators ran CME", "IRON LIBERTY"),
        ("G1015", "MS", "Octo Tempest used CrackMapExec", "Octo Tempest"),
    ]
    for gid, src, quote, alias in cases:
        check = check_group_quote(
            GroupMapping(group_id=gid, quote=quote, source_name=src), cme, ent, ev
        )
        assert check.passed, (gid, check.reason)
        assert alias in check.group_aliases_matched


def test_group_quote_matches_across_pdf_hyphenation(mobile_store):
    # Issue #1: E011 shares E012's quote matching.
    evidence = {"Blog": "the Confucius APT group de-\nployed Pegasus against targets"}
    check = check_group_quote(mapping("Confucius APT group deployed Pegasus"), spec(), mobile_store, evidence)
    assert check.passed, check.reason


def test_normalize_text_unchanged_for_definition_hashes():
    # quote matching must not change normalize_text: group definition hashes depend on it
    assert normalize_text("State-\nSponsored  •  Actor") == "state- sponsored • actor"
