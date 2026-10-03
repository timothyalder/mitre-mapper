"""judge.py: prompt content, verdict parsing, approval rule, short-circuit, errors, replay."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fakes import ScriptedChatModel, verdict_msg
from mitre_mapper import judge as J
from mitre_mapper import tools as T
from mitre_mapper.intake import parse_intake
from mitre_mapper.models import IntakeSpec, MappingProposal
from mitre_mapper.runlog import ProviderError

FIXTURE = Path(__file__).parent / "fixtures" / "pegasus-ios.md"
SPEC = IntakeSpec(name="Pegasus for iOS", type="malware", aliases=["Pegasus"], body="spy things")


def proposal(**kw) -> MappingProposal:
    base = {
        "domain": "mobile-attack",
        "techniques": [
            {
                "technique_id": "T1430",
                "rationale": "AGENT_RATIONALE",
                "evidence": [{"source_name": "Rpt", "quote": "AGENT_QUOTE tracks location"}],
            },
            {"technique_id": "T1404", "rationale": "USER_PINNED_RATIONALE", "user_asserted": True},
        ],
        "groups": [
            {"group_id": "G0142", "quote": "USER_GROUP_QUOTE", "source_name": "x", "user_asserted": True}
        ],
    }
    base.update(kw)
    return MappingProposal.model_validate(base)


def test_user_asserted_items_never_reach_prompt():
    model = ScriptedChatModel(script=[verdict_msg()])
    J.judge(proposal(), SPEC, {"Rpt": "AGENT_QUOTE tracks location"}, model)
    text = "\n".join(str(m.content) for m in model.seen_messages[0])
    assert "T1430" in text and "AGENT_RATIONALE" in text
    assert "T1404" not in text and "USER_PINNED_RATIONALE" not in text
    assert "G0142" not in text and "USER_GROUP_QUOTE" not in text
    assert "Evidence text" in text and "AGENT_QUOTE tracks location" in text
    assert "evidence_grounding" in text  # rubric is the system prompt


def test_per_item_results_tokens_and_hash():
    model = ScriptedChatModel(script=[verdict_msg(("technique_specificity",), tokens=(123, 45))])
    r = J.judge(proposal(), SPEC, {}, model)
    assert [i.name for i in r.verdict.items] == list(J.RUBRIC_ITEMS)
    assert [i.name for i in r.verdict.failed_items] == ["technique_specificity"]
    assert r.verdict.approved is False
    assert (r.tokens_in, r.tokens_out) == (123, 45)
    assert len(r.prompt_sha256) == 64 and r.latency_s >= 0


def test_model_cannot_approve_over_failed_item():
    model = ScriptedChatModel(script=[verdict_msg(("omission_check",), approved=True)])
    assert J.judge(proposal(), SPEC, {}, model).verdict.approved is False


def test_all_pass_approves():
    model = ScriptedChatModel(script=[verdict_msg()])
    assert J.judge(proposal(), SPEC, {}, model).verdict.approved is True


def test_missing_item_counts_as_failed():
    rows = [{"name": n, "passed": True, "rationale": "ok"} for n in J.RUBRIC_ITEMS[:3]]
    model = ScriptedChatModel(script=[verdict_msg(items=rows, approved=True)])
    v = J.judge(proposal(), SPEC, {}, model).verdict
    assert v.approved is False
    assert [i.name for i in v.failed_items] == ["group_attribution"]


def test_no_agent_items_short_circuits():
    model = ScriptedChatModel(script=[])
    only_user = proposal(techniques=[proposal().techniques[1].model_dump()], groups=[
        proposal().groups[0].model_dump()])
    r = J.judge(only_user, SPEC, {}, model)
    assert r.verdict.approved and model.n_calls == 0
    assert (r.tokens_in, r.tokens_out) == (0, 0)


def test_declined_proposal_is_judged():
    model = ScriptedChatModel(script=[verdict_msg()])
    p = MappingProposal(domain="mobile-attack", declined=True, decline_rationale="no behaviour")
    J.judge(p, SPEC, {}, model)
    assert model.n_calls == 1


def test_provider_error_mapped():
    model = ScriptedChatModel(script=[RuntimeError("429 rate limited")])
    with pytest.raises(ProviderError, match="429 rate limited"):
        J.judge(proposal(), SPEC, {}, model)


def test_unparseable_output_is_judge_output_error_not_provider_error():
    from fakes import tool_call_msg

    model = ScriptedChatModel(script=[tool_call_msg("Verdict", {"nonsense": 1}, tokens=(7, 3))])
    with pytest.raises(J.JudgeOutputError, match="unparseable") as exc:
        J.judge(proposal(), SPEC, {}, model)
    assert not isinstance(exc.value, ProviderError)
    assert (exc.value.tokens_in, exc.value.tokens_out) == (7, 3) and exc.value.prompt_sha256


def test_long_evidence_truncated_and_flagged():
    big = "A" * (J.MAX_CHARS_PER_SOURCE + 500)
    model = ScriptedChatModel(script=[verdict_msg()])
    J.judge(proposal(), SPEC, {"Rpt": big}, model)
    text = str(model.seen_messages[0][1].content)
    assert "TRUNCATED" in text and f"of {len(big)} characters" in text
    assert big not in text


def test_replay_from_run_dir(tmp_path):
    run = tmp_path / "run1"
    (run / "mobile-attack").mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "intake.md").write_text(FIXTURE.read_text())
    (run / "mobile-attack" / "proposal_2.json").write_text(proposal().model_dump_json())
    (run / "evidence" / "rpt.txt").write_text("REPLAY_EVIDENCE_TEXT")
    model = ScriptedChatModel(script=[verdict_msg()])
    r = J.replay_judge(run, "mobile-attack", 2, model)
    assert r.verdict.approved
    text = str(model.seen_messages[0][1].content)
    assert "REPLAY_EVIDENCE_TEXT" in text and "T1430" in text and "T1404" not in text
    # explicit evidence dir overrides
    other = tmp_path / "frozen"
    other.mkdir()
    (other / "z.txt").write_text("FROZEN_TEXT")
    model2 = ScriptedChatModel(script=[verdict_msg()])
    J.replay_judge(run, "mobile-attack", 2, model2, evidence_dir=other)
    t2 = str(model2.seen_messages[0][1].content)
    assert "FROZEN_TEXT" in t2 and "REPLAY_EVIDENCE_TEXT" not in t2


def test_rubric_exists_and_is_not_agent_readable():
    assert J.RUBRIC_PATH.is_file()
    assert "judge-rubric.md" not in T.READABLE_REFERENCES
    assert J.RUBRIC_PATH.parent == T.REFERENCES_DIR
    out = T.read_reference.__wrapped__(None, None, "judge-rubric.md")  # denial precedes any ctx use
    assert "error" in out and "text" not in out
    for item in J.RUBRIC_ITEMS:
        assert item in J.load_rubric()
