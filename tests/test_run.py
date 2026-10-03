"""Gate tests for the thin slice: fake model + real mobile dataset (PLAN Wave 2)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mitre_mapper.models import Delta
from mitre_mapper.runlog import read_index
from mitre_mapper.run import map_software
from fakes import ScriptedChatModel, looping_search_model, proposal_msg, tool_call_msg

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
FIXTURE = ROOT / "tests" / "fixtures" / "pegasus-ios.md"
REF = "Test Fixture Reference"


def tech(tid: str, why: str = "Described in the intake prose.", **extra) -> dict:
    return {
        "technique_id": tid,
        "rationale": why,
        "evidence": [{"source_name": REF, "quote": "collects location data"}],
        **extra,
    }


def proposal(*techs: dict, **kw) -> dict:
    return {"domain": "mobile-attack", "techniques": list(techs), **kw}


GOOD = proposal(tech("T1430"), tech("T1429"), tech("T1409"))


@pytest.fixture
def env(tmp_path):
    alloc = tmp_path / "allocations.json"
    shutil.copy(DATASETS / "allocations.json", alloc)
    return {
        "runs_dir": tmp_path / "runs",
        "datasets_dir": DATASETS,
        "allocations_path": alloc,
        "tmp": tmp_path,
    }


def go(env, model, intake=FIXTURE, **kw):
    return map_software(
        intake,
        model=model,
        runs_dir=env["runs_dir"],
        datasets_dir=env["datasets_dir"],
        allocations_path=env["allocations_path"],
        **kw,
    )


def events(env, rec) -> list[dict]:
    path = env["runs_dir"] / rec.run_id / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def names(evs) -> list[str]:
    return [e["event"] for e in evs]


def test_pegasus_minted(env):
    model = ScriptedChatModel(
        script=[
            tool_call_msg("search_techniques", {"query": "location tracking spyware", "k": 5}),
            tool_call_msg("search_techniques", {"query": "zzzqqq nonsense", "k": 5}),
            tool_call_msg("get_technique", {"attack_id": "T1430"}),
            proposal_msg(GOOD),
        ]
    )
    rec = go(env, model)
    assert rec.terminal_state == "minted"
    assert rec.attempts == {"mobile-attack": 1}
    run_dir = env["runs_dir"] / rec.run_id
    delta = Delta.model_validate_json((run_dir / "delta.json").read_text())
    assert delta.target_domains == ["mobile-attack"]
    types = [o["type"] for o in delta.objects]
    assert types.count("malware") == 1 and types.count("relationship") == 3
    assert (run_dir / "run.md").exists()
    assert (run_dir / "mobile-attack" / "proposal_1.json").exists()
    assert (run_dir / "mobile-attack" / "lint_1.json").exists()
    assert [r.run_id for r in read_index(env["runs_dir"])] == [rec.run_id]
    evs = events(env, rec)
    assert {"search", "tool_call", "proposal_draft", "lint_result", "mint", "run_end"} <= set(names(evs))
    assert rec.zero_hit_queries == 1
    draft = next(e for e in evs if e["event"] == "proposal_draft")
    assert draft["technique_ids"] == ["T1409", "T1429", "T1430"]
    assert draft["rejected_candidates"] is not None
    assert any(e["event"] == "merge" and e.get("recursion_limit") for e in evs)
    # the real registry is untouched; the tmp copy got SX0001
    assert "SX0001" in json.loads(env["allocations_path"].read_text())["software"]
    assert json.loads((DATASETS / "allocations.json").read_text())["software"] == {}


def test_retry_with_set_diff(env):
    bad = proposal(tech("T1430"), tech("T1059"))  # T1059 is enterprise-only
    model = ScriptedChatModel(script=[proposal_msg(bad), proposal_msg(GOOD)])
    rec = go(env, model)
    assert rec.terminal_state == "minted"
    assert rec.attempts == {"mobile-attack": 2}
    assert "E002" in rec.error_rule_ids
    evs = events(env, rec)
    retry = next(e for e in evs if e["event"] == "retry")
    assert retry["attempt"] == 2
    assert retry["removed"] == ["T1059"]
    assert retry["added"] == ["T1409", "T1429"]
    # lint feedback reached the second model call
    second_call_text = " ".join(str(m.content) for m in model.seen_messages[1])
    assert "E002" in second_call_text


def test_lint_failed_after_exhausted_attempts(env):
    bad = proposal(tech("T1059"))
    rec = go(env, ScriptedChatModel(script=[proposal_msg(bad)] * 2), max_attempts=2)
    assert rec.terminal_state == "lint_failed"
    assert not (env["runs_dir"] / rec.run_id / "delta.json").exists()


def test_declined(env):
    decl = {"domain": "mobile-attack", "declined": True, "decline_rationale": "nothing supported"}
    rec = go(env, ScriptedChatModel(script=[proposal_msg(decl)]))
    assert rec.terminal_state == "declined"
    assert (env["runs_dir"] / rec.run_id / "run.md").exists()


def test_budget_kill(env):
    rec = go(env, looping_search_model(), max_model_calls=3)
    assert rec.terminal_state == "budget_exhausted"
    run_dir = env["runs_dir"] / rec.run_id
    assert (run_dir / "run.md").exists()
    assert read_index(env["runs_dir"])[0].terminal_state == "budget_exhausted"
    assert "budget_exhausted" in names(events(env, rec))
    assert rec.n_model_calls == 4


def test_provider_error(env):
    rec = go(env, ScriptedChatModel(script=[RuntimeError("429 rate limit exceeded: quota")]))
    assert rec.terminal_state == "provider_error"
    run_md = (env["runs_dir"] / rec.run_id / "run.md").read_text()
    assert "429 rate limit exceeded: quota" in run_md
    assert read_index(env["runs_dir"])[0].terminal_state == "provider_error"


def test_agent_cannot_self_assert(env):
    sneaky = proposal(
        tech("T1430", user_asserted=True), tech("T1429", user_asserted=True)
    )
    rec = go(env, ScriptedChatModel(script=[proposal_msg(sneaky)]))
    assert rec.terminal_state == "minted"
    saved = json.loads((env["runs_dir"] / rec.run_id / "mobile-attack" / "proposal_1.json").read_text())
    assert [t["user_asserted"] for t in saved["techniques"]] == [False, False]
    assert not any(e["event"] == "user_asserted" for e in events(env, rec))


def test_user_pinned_technique_is_flagged(env):
    intake = env["tmp"] / "pinned.md"
    intake.write_text(FIXTURE.read_text().replace("platforms: [iOS]", "platforms: [iOS]\ntechniques: [T1404]"))
    rec = go(env, ScriptedChatModel(script=[proposal_msg(GOOD)]), intake=intake)
    assert rec.terminal_state == "minted"
    evs = events(env, rec)
    ua = next(e for e in evs if e["event"] == "user_asserted")
    assert ua["techniques"] == ["T1404"]
    delta = Delta.model_validate_json((env["runs_dir"] / rec.run_id / "delta.json").read_text())
    assert sum(o["type"] == "relationship" for o in delta.objects) == 4


def test_invalid_intake(env):
    bad = env["tmp"] / "bad.md"
    bad.write_text("---\nname: X\ntype: vulnerability\n---\nbody")
    model = ScriptedChatModel(script=[])
    rec = go(env, model, intake=bad)
    assert rec.terminal_state == "error"
    assert model.n_calls == 0
    assert "intake_invalid" in names(events(env, rec))
    assert (env["runs_dir"] / rec.run_id / "run.md").exists()
    assert read_index(env["runs_dir"])[0].terminal_state == "error"


def test_missing_intake_file(env):
    rec = go(env, ScriptedChatModel(script=[]), intake=env["tmp"] / "nope.md")
    assert rec.terminal_state == "error"
