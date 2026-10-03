import pytest
from pydantic import TypeAdapter, ValidationError

from mitre_mapper.models import (
    FetchResult,
    IndexRecord,
    IntakeGroup,
    IntakeSpec,
    LintFinding,
    MappingProposal,
    ReviewRecord,
    RunRecord,
    Severity,
    Verdict,
)

PEGASUS = {
    "name": "Pegasus for iOS",
    "type": "malware",
    "aliases": ["Pegasus"],
    "platforms": ["iOS"],
    "domains": ["mobile-attack"],
    "references": [
        {
            "source_name": "Lookout Pegasus",
            "url": "https://example.com/pegasus.pdf",
            "description": "Lookout. (2016). Technical Analysis of Pegasus Spyware.",
        },
        {"source_name": "No URL ref"},
    ],
    "techniques": ["T1430", "T1636.002"],
    "groups": [
        {"ref": "G0142"},
        {
            "new": {
                "name": "Example Actor",
                "description": "d",
                "techniques": ["T1404"],
            }
        },
    ],
    "body": "Free text.",
}

RUN = {
    "run_id": "r1",
    "ts": "2026-10-03T00:00:00Z",
    "software_name": "X",
    "intake_sha256": "abc",
    "domains": ["mobile-attack"],
    "model": "m",
    "git_sha": "deadbeef",
    "prompt_sha256": "cafe",
    "tool_version": "0.1.0",
    "dataset_release": {"mobile-attack": "19.2"},
    "terminal_state": "minted",
}


def test_intake_round_trip():
    spec = IntakeSpec.model_validate(PEGASUS)
    again = IntakeSpec.model_validate(spec.model_dump(mode="json"))
    assert again == spec
    assert spec.groups[0].ref == "G0142"
    assert spec.groups[1].new.name == "Example Actor"


def test_intake_group_exactly_one():
    with pytest.raises(ValidationError):
        IntakeGroup()
    with pytest.raises(ValidationError):
        IntakeGroup(ref="G0001", new={"name": "n", "description": "d"})
    with pytest.raises(ValidationError):
        IntakeGroup(ref="G01")


def test_extra_field_rejected():
    with pytest.raises(ValidationError):
        IntakeSpec.model_validate({**PEGASUS, "sneaky": 1})
    with pytest.raises(ValidationError):
        MappingProposal.model_validate({"domain": "mobile-attack", "sneaky": 1})


@pytest.mark.parametrize("tid", ["T1430", "T1636.002"])
def test_technique_id_ok(tid):
    assert IntakeSpec.model_validate({**PEGASUS, "techniques": [tid]})


@pytest.mark.parametrize("tid", ["T143", "t1430", "T1430.1", "G0001", "T1430.0021"])
def test_technique_id_bad(tid):
    with pytest.raises(ValidationError):
        IntakeSpec.model_validate({**PEGASUS, "techniques": [tid]})


def test_decline_validator():
    ok = MappingProposal(
        domain="mobile-attack", declined=True, decline_rationale="not software"
    )
    assert ok.declined
    with pytest.raises(ValidationError):
        MappingProposal(domain="mobile-attack", declined=True)
    with pytest.raises(ValidationError):
        MappingProposal(
            domain="mobile-attack",
            declined=True,
            decline_rationale="x",
            techniques=[{"technique_id": "T1430", "rationale": "r"}],
        )


def test_empty_non_declined_proposal_parses():
    p = MappingProposal(domain="ics-attack")
    assert p.techniques == [] and not p.declined


def test_lint_finding_prefix_matches_severity():
    f = LintFinding(rule_id="E001", severity=Severity.ERROR, message="m")
    assert f.details == {}
    LintFinding(rule_id="W002", severity="WARN", message="m")
    LintFinding(rule_id="I004", severity="INFO", message="m")
    with pytest.raises(ValidationError):
        LintFinding(rule_id="E001", severity=Severity.WARN, message="m")
    with pytest.raises(ValidationError):
        LintFinding(rule_id="X001", severity=Severity.INFO, message="m")


def test_fetch_result_rules():
    assert FetchResult(source_name="s", ok=True, text="").ok
    assert FetchResult(source_name="s", ok=False, error="403").error == "403"
    with pytest.raises(ValidationError):
        FetchResult(source_name="s", ok=True)
    with pytest.raises(ValidationError):
        FetchResult(source_name="s", ok=False)
    with pytest.raises(ValidationError):
        FetchResult(source_name="s", ok=False, error="")


def test_run_record_requires_git_and_prompt_sha():
    rec = RunRecord.model_validate(RUN)
    assert rec.record == "run" and rec.tokens == {"in": 0, "out": 0}
    for key in ("git_sha", "prompt_sha256"):
        missing = {k: v for k, v in RUN.items() if k != key}
        with pytest.raises(ValidationError):
            RunRecord.model_validate(missing)
        with pytest.raises(ValidationError):
            RunRecord.model_validate({**RUN, key: ""})


def test_index_record_discriminator():
    ta = TypeAdapter(IndexRecord)
    assert isinstance(ta.validate_python({**RUN, "record": "run"}), RunRecord)
    rev = {"record": "review", "run_id": "r1", "ts": "t", "summary": {"n": 1}}
    assert isinstance(ta.validate_python(rev), ReviewRecord)
    assert isinstance(ta.validate_json(ta.dump_json(RunRecord.model_validate(RUN))), RunRecord)
    with pytest.raises(ValidationError):
        ta.validate_python({**RUN, "record": "nope"})


def test_verdict_failed_items():
    v = Verdict(
        approved=False,
        items=[
            {"name": "a", "passed": True, "rationale": "r"},
            {"name": "b", "passed": False, "rationale": "r"},
        ],
    )
    assert [i.name for i in v.failed_items] == ["b"]
