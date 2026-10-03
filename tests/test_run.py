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
        **{"fetch": False, "cache_dir": env["tmp"] / "cache", **kw},  # never touch the network
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
    assert rec.surface == "langchain"
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


# --------------------------------------------------------------------------- Wave 3: evidence, judge, groups

from fakes import verdict_msg  # noqa: E402
from mitre_mapper.fetch import slug  # noqa: E402

EVIDENCE_TEXT = (
    "Pegasus for iOS collects location data. Confucius deployed Pegasus against targets. "
    "A cluster called Foxtrot Panda also used Pegasus."
)


@pytest.fixture
def frozen(env):
    d = env["tmp"] / "evidence"
    d.mkdir()
    (d / f"{slug(REF)}.txt").write_text(EVIDENCE_TEXT)
    env["evidence_dir"] = d
    return d


def goj(env, model, judge_model=None, **kw):
    return go(env, model, judge_model=judge_model, evidence_dir=env.get("evidence_dir"), **kw)


def of(evs, name) -> list[dict]:
    return [e for e in evs if e["event"] == name]


def test_frozen_evidence_reaches_tools_lint_and_judge(env, frozen):
    model = ScriptedChatModel(
        script=[tool_call_msg("get_evidence", {"source_name": REF, "max_chars": 20}), proposal_msg(GOOD)]
    )
    judge = ScriptedChatModel(script=[verdict_msg()])
    rec = goj(env, model, judge)
    assert rec.terminal_state == "minted"
    evs = events(env, rec)
    fetch = of(evs, "reference_fetch")
    assert [(e["source_name"], e["ok"], e["chars"]) for e in fetch] == [(REF, True, len(EVIDENCE_TEXT))]
    run_dir = env["runs_dir"] / rec.run_id
    assert (run_dir / "evidence" / f"{slug(REF)}.txt").read_text() == EVIDENCE_TEXT
    call = next(e for e in of(evs, "tool_call") if e["tool"] == "get_evidence")
    assert call["summary"]["returned_chars"] == 20
    tool_msgs = [m for m in model.seen_messages[1] if m.type == "tool"]
    assert EVIDENCE_TEXT[:20] in str(tool_msgs[0].content)
    assert "Confucius deployed Pegasus" in " ".join(str(m.content) for m in judge.seen_messages[0])


def test_fetch_disabled_is_logged_not_fatal(env):
    rec = go(env, ScriptedChatModel(script=[proposal_msg(GOOD)]))
    assert rec.terminal_state == "minted" and rec.fetch_failures == 1
    (ev,) = of(events(env, rec), "reference_fetch_failed")
    assert ev["error"] == "fetch disabled"


def test_judge_sequence_called_once_per_lint_clean_proposal(env, frozen):
    """Acceptance #11: lint-error -> clean -> judge-reject -> clean -> approve = 2 judge calls."""
    bad = proposal(tech("T1430"), tech("T1059"))  # T1059 is enterprise-only: E002
    model = ScriptedChatModel(script=[proposal_msg(bad), proposal_msg(GOOD), proposal_msg(GOOD)])
    judge = ScriptedChatModel(
        script=[verdict_msg(("technique_specificity",)), verdict_msg()]
    )
    rec = goj(env, model, judge)
    assert rec.terminal_state == "minted" and rec.attempts == {"mobile-attack": 3}
    assert judge.n_calls == 2
    evs = events(env, rec)
    verdicts = of(evs, "judge_verdict")
    assert [(v["attempt"], v["approved"]) for v in verdicts] == [(2, False), (3, True)]
    assert len(verdicts[0]["prompt_sha256"]) == 64
    assert {i["name"]: i["passed"] for i in verdicts[0]["items"]}["technique_specificity"] is False
    run_dir = env["runs_dir"] / rec.run_id / "mobile-attack"
    assert not (run_dir / "verdict_1.json").exists()
    assert json.loads((run_dir / "verdict_2.json").read_text())["approved"] is False
    assert (run_dir / "verdict_3.json").exists()
    # judge never ran on the lint-failed attempt: events interleave lint(1) lint(2) judge(2) lint(3) judge(3)
    seq = [(e["event"], e.get("attempt")) for e in evs if e["event"] in ("lint_result", "judge_verdict")]
    assert seq == [("lint_result", 1), ("lint_result", 2), ("judge_verdict", 2), ("lint_result", 3), ("judge_verdict", 3),
                   ("lint_result", "final")]
    retries = of(evs, "retry")
    assert [r["reason"] for r in retries] == ["lint_errors: E002", "judge_rejected: technique_specificity"]
    assert rec.judge_fail_items == ["technique_specificity"]
    # feedback from the failed rubric item reached the agent's third call
    assert "technique_specificity rationale" in " ".join(str(m.content) for m in model.seen_messages[2])
    # judge tokens count against the budget: 3 agent calls (15 tokens each) + 2 judge calls (120 each)
    assert rec.n_model_calls == 5 and rec.tokens == {"in": 3 * 10 + 2 * 100, "out": 3 * 5 + 2 * 20}
    md = (env["runs_dir"] / rec.run_id / "run.md").read_text()
    assert "## Attempts" in md and "mobile-attack #1: lint ERROR E002" in md
    assert "mobile-attack #2: lint clean; judge failed technique_specificity" in md
    assert "mobile-attack #3: lint clean; judge approved" in md


def test_judge_rejection_on_last_attempt_is_terminal(env, frozen):
    model = ScriptedChatModel(script=[proposal_msg(GOOD)] * 2)
    judge = ScriptedChatModel(script=[verdict_msg(("evidence_grounding",))] * 2)
    rec = goj(env, model, judge, max_attempts=2)
    assert rec.terminal_state == "judge_rejected"
    assert not (env["runs_dir"] / rec.run_id / "delta.json").exists()
    assert rec.judge_fail_items == ["evidence_grounding"]


def test_lint_failure_after_a_judge_rejection_is_lint_failed(env, frozen):
    bad = proposal(tech("T1059"))
    model = ScriptedChatModel(script=[proposal_msg(GOOD), proposal_msg(bad)])
    judge = ScriptedChatModel(script=[verdict_msg(("omission_check",))])
    rec = goj(env, model, judge, max_attempts=2)
    assert rec.terminal_state == "lint_failed"


def test_unparseable_judge_output_is_a_failed_attempt(env, frozen):
    from fakes import tool_call_msg as tc

    model = ScriptedChatModel(script=[proposal_msg(GOOD), proposal_msg(GOOD)])
    judge = ScriptedChatModel(script=[tc("Verdict", {"nonsense": 1}), verdict_msg()])
    rec = goj(env, model, judge)
    assert rec.terminal_state == "minted" and rec.attempts == {"mobile-attack": 2}
    v1, v2 = of(events(env, rec), "judge_verdict")
    assert v1["approved"] is False
    assert [(i["name"], i["passed"]) for i in v1["items"]] == [("judge_output_invalid", False)]
    assert v2["approved"] is True
    assert [r["reason"] for r in of(events(env, rec), "retry")] == ["judge_output_invalid"]
    assert rec.judge_fail_items == ["judge_output_invalid"]


def test_judge_provider_error_finalizes_provider_error(env, frozen):
    model = ScriptedChatModel(script=[proposal_msg(GOOD)])
    judge = ScriptedChatModel(script=[RuntimeError("401 bad judge key")])
    rec = goj(env, model, judge)
    assert rec.terminal_state == "provider_error"
    assert "401 bad judge key" in (env["runs_dir"] / rec.run_id / "run.md").read_text()


def test_judge_budget_applies(env, frozen):
    model = ScriptedChatModel(script=[proposal_msg(GOOD)])
    judge = ScriptedChatModel(script=[verdict_msg()])
    rec = goj(env, model, judge, max_model_calls=1)
    assert rec.terminal_state == "budget_exhausted"
    assert of(events(env, rec), "judge_verdict")  # the verdict was logged before the budget fired


def test_no_judge_model_is_logged_once_and_skips(env, frozen):
    rec = goj(env, ScriptedChatModel(script=[proposal_msg(GOOD)]))
    evs = events(env, rec)
    assert rec.terminal_state == "minted" and not of(evs, "judge_verdict")
    (cfg,) = [e for e in of(evs, "merge") if e.get("kind") == "judge_config"]
    assert cfg["judge"] is None and rec.judge_model is None


def test_mint_event_carries_the_final_mapping_and_run_md_renders_it(env, frozen):
    rec = goj(env, ScriptedChatModel(script=[proposal_msg(GOOD)]))
    (mint,) = of(events(env, rec), "mint")
    techs = mint["techniques"]["mobile-attack"]
    assert [t["id"] for t in techs] == ["T1430", "T1429", "T1409"]
    assert techs[0]["name"] == "Location Tracking"
    assert techs[0]["user_asserted"] is False and techs[0]["sources"] == [REF]
    assert mint["groups"] == {"mobile-attack": []}
    md = (env["runs_dir"] / rec.run_id / "run.md").read_text()
    assert "## Mapping" in md and f"- T1430 Location Tracking -- {REF}" in md


GROUP_INTAKE_EXTRA = """groups:
  - ref: G0142
  - new:
      name: Zzz Test Actor
      aliases: [ZTA]
      description: A user-defined actor.
      techniques: [T1404]
"""


def group_intake(env, extra=GROUP_INTAKE_EXTRA, techniques=""):
    intake = env["tmp"] / "groups.md"
    intake.write_text(
        FIXTURE.read_text().replace("platforms: [iOS]", "platforms: [iOS]\n" + techniques + extra)
    )
    return intake


def test_user_asserted_groups_are_minted_and_logged(env, frozen):
    rec = goj(env, ScriptedChatModel(script=[proposal_msg(GOOD)]), intake=group_intake(env))
    assert rec.terminal_state == "minted"
    evs = events(env, rec)
    ua = {(e["kind"]): e for e in of(evs, "user_asserted")}
    assert ua["group_ref"]["group_id"] == "G0142" and ua["group_ref"]["domain"] == "mobile-attack"
    assert ua["new_group"]["name"] == "Zzz Test Actor" and "deferred" not in json.dumps(ua["new_group"])
    delta = Delta.model_validate_json((env["runs_dir"] / rec.run_id / "delta.json").read_text())
    sets = [o for o in delta.objects if o["type"] == "intrusion-set"]
    assert [o["name"] for o in sets] == ["Zzz Test Actor"]
    assert "GX0001" in delta.allocations
    (mint,) = of(evs, "mint")
    groups = {g["id"]: g for g in mint["groups"]["mobile-attack"]}
    assert groups["G0142"]["kind"] == "existing" and groups["G0142"]["user_asserted"] is True
    assert groups["GX0001"] == {"id": "GX0001", "name": "Zzz Test Actor", "user_asserted": True, "kind": "new"}
    md = (env["runs_dir"] / rec.run_id / "run.md").read_text()
    assert "- group GX0001 Zzz Test Actor (new, user-asserted)" in md


def test_judge_never_sees_user_asserted_items(env, frozen):
    judge = ScriptedChatModel(script=[verdict_msg()])
    rec = goj(
        env, ScriptedChatModel(script=[proposal_msg(GOOD)]), judge,
        intake=group_intake(env, techniques="techniques: [T1404]\n"),
    )
    assert rec.terminal_state == "minted"
    text = " ".join(str(m.content) for m in judge.seen_messages[0])
    assert "Asserted by the user" not in text and "T1404" not in text and "G0142" not in text


def test_declined_agent_with_pinned_technique_or_new_group_is_not_declined(env, frozen):
    decl = {"domain": "mobile-attack", "declined": True, "decline_rationale": "nothing supported"}
    rec = goj(
        env, ScriptedChatModel(script=[proposal_msg(decl)]),
        intake=group_intake(env, extra="", techniques="techniques: [T1404]\n"),
    )
    assert rec.terminal_state == "minted"
    # a new group alone keeps the domain live; the software then has no technique, so E001 reports it
    rec2 = goj(env, ScriptedChatModel(script=[proposal_msg(decl)]), intake=group_intake(env))
    assert rec2.terminal_state == "lint_failed" and "E001" in rec2.error_rule_ids
    assert any(e["kind"] == "new_group" for e in of(events(env, rec2), "user_asserted"))


def test_group_quote_check_and_unmatched_actor_events(env, frozen):
    good_group = {"group_id": "G0142", "quote": "Confucius deployed Pegasus", "source_name": REF}
    bad_group = {"group_id": "G0142", "quote": "Confucius is behind Pegasus", "source_name": REF}
    unmatched = {"actor": "Foxtrot Panda", "quote": "A cluster called Foxtrot Panda", "source_name": REF}
    model = ScriptedChatModel(
        script=[
            proposal_msg({**GOOD, "groups": [bad_group]}),
            proposal_msg({**GOOD, "groups": [good_group], "unmatched_actors": [unmatched]}),
        ]
    )
    rec = goj(env, model)
    assert rec.terminal_state == "minted" and "E011" in rec.error_rule_ids
    evs = events(env, rec)
    c1, c2 = of(evs, "group_quote_check")
    assert (c1["attempt"], c1["passed"], c1["group_id"], c1["source"]) == (1, False, "G0142", REF)
    assert "verbatim" in c1["reason"]
    assert (c2["attempt"], c2["passed"]) == (2, True)
    assert "Pegasus" in c2["software_aliases_matched"] and "Confucius" in c2["group_aliases_matched"]
    (um,) = of(evs, "unmatched_actor")
    assert (um["actor"], um["source_name"], um["domain"]) == ("Foxtrot Panda", REF, "mobile-attack")
    assert rec.unmatched_actors == 1
    md = (env["runs_dir"] / rec.run_id / "run.md").read_text()
    assert "group quote check failures" in md and "Foxtrot Panda" in md
    assert "- group G0142 Confucius (existing)" in md


def test_agent_group_with_unknown_source_does_not_crash(env, frozen):
    nope = {"group_id": "G0142", "quote": "Confucius deployed Pegasus", "source_name": "Nope"}
    rec = goj(env, ScriptedChatModel(script=[proposal_msg({**GOOD, "groups": [nope]})] * 2), max_attempts=2)
    assert rec.terminal_state == "lint_failed"
    assert {"E004", "E011"} <= set(rec.error_rule_ids)


def test_agent_technique_without_evidence_gets_e004_not_the_pool(env, frozen):
    no_ev = proposal({"technique_id": "T1430", "rationale": "tracks location", "evidence": []}, tech("T1429"), tech("T1409"))
    model = ScriptedChatModel(script=[proposal_msg(no_ev), proposal_msg(GOOD)])
    rec = goj(env, model)
    assert rec.terminal_state == "minted" and rec.attempts == {"mobile-attack": 2}
    assert "E004" in rec.error_rule_ids
