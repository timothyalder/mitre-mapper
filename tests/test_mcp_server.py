"""MCP server: driven in-process through the FastMCP client (no network, tmp runs/allocations)."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from fakes import ScriptedChatModel, proposal_msg
from mitre_mapper.mcp_server import McpService, create_server
from mitre_mapper.models import Delta
from mitre_mapper.run import map_software
from mitre_mapper.runlog import RunLog, read_index

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
FIXTURE = ROOT / "tests" / "fixtures" / "pegasus-ios.md"
REF = "Test Fixture Reference"
PROSE = "mitre-mapper intake description"  # the intake prose, as an evidence source


def tech(tid: str, **extra: Any) -> dict:
    return {
        "technique_id": tid,
        "rationale": "Described in the intake prose.",
        "evidence": [{"source_name": PROSE, "quote": "collects location data"}],
        **extra,
    }


GOOD = {"domain": "mobile-attack", "techniques": [tech("T1430"), tech("T1429"), tech("T1409")]}
BAD = {"domain": "mobile-attack", "techniques": [tech("T1430"), tech("T1059")]}  # T1059 is enterprise-only


@pytest.fixture
def env(tmp_path):
    alloc = tmp_path / "allocations.json"
    shutil.copy(DATASETS / "allocations.json", alloc)
    return {"runs": tmp_path / "runs", "alloc": alloc, "tmp": tmp_path}


@pytest.fixture
def server(env):
    return create_server(env["runs"], DATASETS, env["alloc"], idle_close_s=1800)


def call(server, _tool: str, /, **args: Any) -> dict[str, Any]:
    async def go() -> dict[str, Any]:
        async with Client(server) as c:
            return (await c.call_tool(_tool, args)).data

    return asyncio.run(go())


def events(env, run_id) -> list[dict]:
    return [json.loads(l) for l in (env["runs"] / run_id / "events.jsonl").read_text().splitlines()]


def names(evs) -> list[str]:
    return [e["event"] for e in evs]


def start(server, intake=FIXTURE) -> dict[str, Any]:
    out = call(server, "start_run", intake_path=str(intake), fetch=False)
    assert "run_id" in out, out
    return out


def test_tool_list(server):
    async def go():
        async with Client(server) as c:
            return {t.name for t in await c.list_tools()}

    assert asyncio.run(go()) == {
        "start_run", "search_techniques", "get_technique", "search_groups", "get_group",
        "search_software", "get_software", "get_software_techniques", "get_evidence",
        "read_reference", "lint_proposal", "submit_proposal", "mint_delta", "end_run",
    }


def test_full_flow_minted_and_logged_like_langchain(server, env):
    s = start(server)
    rid = s["run_id"]
    assert s["domains"] == ["mobile-attack"] and s["max_attempts"] == 3
    hits = call(server, "search_techniques", run_id=rid, query="location tracking", k=5)
    assert hits["results"]
    call(server, "search_techniques", run_id=rid, query="zzzqqq nonsense")
    first = call(server, "submit_proposal", run_id=rid, proposal=BAD)
    assert first["has_errors"] and first["attempt"] == 1 and first["attempts_left"] == 2
    assert "E002" in {e["rule_id"] for e in first["errors"]}
    second = call(server, "submit_proposal", run_id=rid, proposal=GOOD)
    assert not second["has_errors"] and second["attempt"] == 2
    out = call(server, "mint_delta", run_id=rid)
    assert out["terminal_state"] == "minted" and out["software_id"] == "SX0001"

    (row,) = read_index(env["runs"])
    assert row.run_id == rid and row.surface == "mcp" and row.judge_model is None
    assert row.terminal_state == "minted" and row.attempts == {"mobile-attack": 2}
    assert "E002" in row.error_rule_ids and row.zero_hit_queries == 1
    run_dir = env["runs"] / rid
    for f in ("run.md", "delta.json", "prompt.txt", "intake.md", "mobile-attack/proposal_1.json",
              "mobile-attack/lint_2.json", "mobile-attack/lint_final.json"):
        assert (run_dir / f).exists(), f
    evs = events(env, rid)
    assert evs[0]["event"] == "run_start" and evs[0]["surface"] == "mcp"
    assert names(evs)[-1] == "run_end" and evs[-1]["terminal_state"] == "minted"
    assert evs[-2]["event"] == "tool_call" and evs[-2]["tool"] == "mint_delta"  # logged before run_end
    retry = next(e for e in evs if e["event"] == "retry")
    assert retry["attempt"] == 2 and retry["removed"] == ["T1059"] and retry["added"] == ["T1409", "T1429"]
    draft1 = next(e for e in evs if e["event"] == "proposal_draft")
    assert draft1["rejected_candidates"]  # searched ids the proposal did not cite

    # the LangChain path yields the same delta shape and the same Mapping section
    alloc2 = env["tmp"] / "alloc2.json"
    shutil.copy(DATASETS / "allocations.json", alloc2)
    lc = map_software(
        FIXTURE, model=ScriptedChatModel(script=[proposal_msg(GOOD)]), runs_dir=env["tmp"] / "runs2",
        datasets_dir=DATASETS, allocations_path=alloc2, fetch=False, cache_dir=env["tmp"] / "cache",
    )
    assert lc.surface == "langchain" and lc.terminal_state == "minted"
    d_mcp = Delta.model_validate_json((run_dir / "delta.json").read_text())
    d_lc = Delta.model_validate_json((env["tmp"] / "runs2" / lc.run_id / "delta.json").read_text())

    def shape(d: Delta) -> list:
        mask = {"created", "modified"}
        return sorted(
            (json.dumps({k: v for k, v in o.items() if k not in mask}, sort_keys=True) for o in d.objects)
        )

    assert shape(d_mcp) == shape(d_lc)
    assert d_mcp.allocations == d_lc.allocations and d_mcp.target_domains == d_lc.target_domains
    assert set(d_mcp.model_dump()) == set(d_lc.model_dump())

    def mapping(path: Path) -> str:
        md = path.read_text()
        return md[md.index("## Mapping"): md.index("## Attempts")] if "## Attempts" in md else md[md.index("## Mapping"):]

    assert mapping(run_dir / "run.md") == mapping(env["tmp"] / "runs2" / lc.run_id / "run.md")
    lc_evs = [json.loads(l) for l in (env["tmp"] / "runs2" / lc.run_id / "events.jsonl").read_text().splitlines()]
    shared = {"user_asserted", "mint", "allocation", "domain_resolved", "unmatched_actor"}
    assert [e["event"] for e in evs if e["event"] in shared] == [e["event"] for e in lc_evs if e["event"] in shared]


def test_mint_refuses_while_latest_has_errors_and_stays_open(server, env):
    rid = start(server)["run_id"]
    refused = call(server, "mint_delta", run_id=rid)
    assert "refused" in refused["error"] and refused["blocking"] == {"mobile-attack": "no proposal submitted"}
    call(server, "submit_proposal", run_id=rid, proposal=BAD)
    refused = call(server, "mint_delta", run_id=rid)
    assert "lint ERRORs" in refused["blocking"]["mobile-attack"]
    assert read_index(env["runs"]) == []  # still open
    assert not (env["runs"] / rid / "delta.json").exists()
    assert json.loads(env["alloc"].read_text())["software"] == {}
    # the agent can recover
    assert not call(server, "submit_proposal", run_id=rid, proposal=GOOD)["has_errors"]
    assert call(server, "mint_delta", run_id=rid)["terminal_state"] == "minted"
    tool_calls = [e for e in events(env, rid) if e["event"] == "tool_call" and e["tool"] == "mint_delta"]
    assert [e["ok"] for e in tool_calls] == [False, False, True]


def test_attempts_exhausted_closes_lint_failed(env):
    server = create_server(env["runs"], DATASETS, env["alloc"], max_attempts=2)
    rid = start(server)["run_id"]
    call(server, "submit_proposal", run_id=rid, proposal=BAD)
    last = call(server, "submit_proposal", run_id=rid, proposal=BAD)
    assert last["attempts_left"] == 0
    (row,) = read_index(env["runs"])
    assert row.terminal_state == "lint_failed" and row.attempts == {"mobile-attack": 2}
    evs = events(env, rid)
    assert any(e["event"] == "merge" and e.get("kind") == "attempt_budget" for e in evs)
    assert "closed" in call(server, "submit_proposal", run_id=rid, proposal=GOOD)["error"]


def test_invalid_proposal_shape_counts_an_attempt(server, env):
    rid = start(server)["run_id"]
    out = call(server, "submit_proposal", run_id=rid, proposal={"domain": "mobile-attack", "techniques": [{"nope": 1}]})
    assert out["has_errors"] and "not a valid MappingProposal" in out["error"] and out["attempt"] == 1
    evs = events(env, rid)
    retry = next(e for e in evs if e["event"] == "retry")
    assert retry["reason"].startswith("no_structured_output") and retry["attempt"] == 1
    assert (env["runs"] / rid / "mobile-attack" / "proposal_1_invalid.json").exists()


def test_agent_cannot_assert_user_items(server, env):
    rid = start(server)["run_id"]
    prop = {**GOOD, "techniques": [tech("T1430", user_asserted=True), tech("T1429", user_asserted=True)]}
    call(server, "submit_proposal", run_id=rid, proposal=prop)
    saved = json.loads((env["runs"] / rid / "mobile-attack" / "proposal_1.json").read_text())
    assert [t["user_asserted"] for t in saved["techniques"]] == [False, False]


def test_user_asserted_items_are_added_by_the_tool(server, env):
    intake = env["tmp"] / "intake.md"
    intake.write_text(FIXTURE.read_text().replace("platforms: [iOS]", "platforms: [iOS]\ntechniques: [T1404]"))
    s = start(server, intake)
    assert s["pinned_by_user"]["techniques"] == ["T1404"]
    rid = s["run_id"]
    call(server, "submit_proposal", run_id=rid, proposal=GOOD)
    out = call(server, "mint_delta", run_id=rid)
    assert out["terminal_state"] == "minted"
    ids = {t["id"]: t["user_asserted"] for t in out["techniques"]["mobile-attack"]}
    assert ids["T1404"] is True and ids["T1430"] is False
    assert any(e["event"] == "user_asserted" and e["kind"] == "intake" for e in events(env, rid))


def test_final_lint_error_refuses_and_closes(server, env):
    intake = env["tmp"] / "intake.md"
    intake.write_text(FIXTURE.read_text().replace("platforms: [iOS]", "platforms: [iOS]\ntechniques: [T1059]"))
    rid = start(server, intake)["run_id"]
    call(server, "submit_proposal", run_id=rid, proposal=GOOD)
    out = call(server, "mint_delta", run_id=rid)
    assert "refused" in out["error"] and out["terminal_state"] == "lint_failed"
    (row,) = read_index(env["runs"])
    assert row.terminal_state == "lint_failed"
    assert not (env["runs"] / rid / "delta.json").exists()
    assert json.loads(env["alloc"].read_text())["software"] == {}


def test_decline_via_proposal_then_mint(server, env):
    rid = start(server)["run_id"]
    decl = {"domain": "mobile-attack", "declined": True, "decline_rationale": "nothing supported"}
    assert not call(server, "submit_proposal", run_id=rid, proposal=decl)["has_errors"]
    assert call(server, "mint_delta", run_id=rid)["terminal_state"] == "declined"
    assert read_index(env["runs"])[0].terminal_state == "declined"


@pytest.mark.parametrize(("state", "expected_error"), [("declined", None), ("error", "gave up")])
def test_end_run(server, env, state, expected_error):
    rid = start(server)["run_id"]
    out = call(server, "end_run", run_id=rid, reason="gave up", terminal_state=state)
    assert out["terminal_state"] == state
    evs = events(env, rid)
    assert evs[-1]["event"] == "run_end" and evs[-1]["error"] == expected_error
    assert any(e["event"] == "merge" and e.get("kind") == "end_run" and e["reason"] == "gave up" for e in evs)
    assert (env["runs"] / rid / "run.md").exists()
    assert read_index(env["runs"])[0].surface == "mcp"


def test_end_run_rejects_bad_state(server, env):
    rid = start(server)["run_id"]
    out = call(server, "end_run", run_id=rid, reason="x", terminal_state="minted")
    assert "error" in out and read_index(env["runs"]) == []


def test_invalid_intake_closes_the_run(server, env):
    out = call(server, "start_run", intake_path=str(env["tmp"] / "missing.md"), fetch=False)
    assert out["terminal_state"] == "error" and out["run_id"]
    (row,) = read_index(env["runs"])
    assert row.terminal_state == "error" and row.surface == "mcp"
    assert "intake_invalid" in names(events(env, out["run_id"]))


def test_unknown_run_and_domain_errors(server):
    assert "unknown run_id" in call(server, "search_techniques", run_id="nope", query="x")["error"]
    rid = start(server)["run_id"]
    assert "not part of this run" in call(server, "search_techniques", run_id=rid, query="x", domain="ics-attack")["error"]
    assert "error" in call(server, "read_reference", run_id=rid, name="judge-rubric.md")


def test_read_tools_log_like_langchain(server, env):
    rid = start(server)["run_id"]
    assert call(server, "get_technique", run_id=rid, attack_id="T1579")["id"] == "T1634.001"  # revoked redirect
    call(server, "get_software_techniques", run_id=rid, attack_id="S0316")
    evs = events(env, rid)
    assert any(e["event"] == "revoked_redirect" for e in evs)
    assert [e["tool"] for e in evs if e["event"] == "tool_call"] == ["get_technique", "get_software_techniques"]
    assert (env["runs"] / rid / "calls" / "0001.json").exists()


# ----------------------------------------------------------------- abandoned detection


def _age(path: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(path / "events.jsonl", (t, t))


def test_abandoned_only_idle_mcp_runs(env):
    svc = McpService(env["runs"], DATASETS, env["alloc"], idle_close_s=1800)
    idle = svc.start_run(str(FIXTURE), fetch=False)["run_id"]
    fresh = svc.start_run(str(FIXTURE), fetch=False)["run_id"]
    lc = RunLog.start(env["runs"], software_name="lc", intake_text_or_path="x", model="m", judge_model=None, prompt_text="p")
    _age(env["runs"] / idle, 3600)
    _age(env["runs"] / lc.run_id, 3600)  # an old LangChain run is not ours to close

    # a new server process starts: it does not own `idle`, so closes it; leaves fresh and the langchain run
    svc2 = McpService(env["runs"], DATASETS, env["alloc"], idle_close_s=1800)
    assert svc2.closed_at_start == [idle]
    rows = {r.run_id: r for r in read_index(env["runs"])}
    assert set(rows) == {idle} and rows[idle].terminal_state == "abandoned" and rows[idle].surface == "mcp"
    last = events(env, idle)[-1]
    assert last["event"] == "run_end" and last["terminal_state"] == "abandoned"
    assert (env["runs"] / idle / "run.md").exists()
    assert not (env["runs"] / fresh / "run.md").exists() and not (env["runs"] / lc.run_id / "run.md").exists()


def test_close_stale_never_closes_runs_this_process_owns(env):
    svc = McpService(env["runs"], DATASETS, env["alloc"], idle_close_s=1800)
    rid = svc.start_run(str(FIXTURE), fetch=False)["run_id"]
    _age(env["runs"] / rid, 3600)
    assert svc.close_stale() == []
    assert read_index(env["runs"]) == []


def _pinned_intake(env) -> Path:
    intake = env["tmp"] / "pinned.md"
    intake.write_text(
        FIXTURE.read_text().replace("platforms: [iOS]", "platforms: [iOS]\ntechniques: [T1404]\ngroups:\n  - ref: G0142")
    )
    return intake


def test_start_run_pinned_by_user_lists_groups_and_new_groups(server, env):
    intake = env["tmp"] / "pinned2.md"
    intake.write_text(
        FIXTURE.read_text().replace(
            "platforms: [iOS]",
            "platforms: [iOS]\ngroups:\n  - ref: G0142\n  - new:\n      name: Zzz Test Actor\n      description: d\n",
        )
    )
    pinned = start(server, intake)["pinned_by_user"]
    assert pinned["existing_groups"] == ["G0142"] and pinned["new_groups"] == ["Zzz Test Actor"]


def test_agent_duplicates_of_user_asserted_items_are_dropped_not_e003(server, env):
    from mitre_mapper.fetch import slug

    ev = env["tmp"] / "ev"
    ev.mkdir()
    (ev / f"{slug(REF)}.txt").write_text("Confucius deployed Pegasus for iOS against targets.")
    out = call(server, "start_run", intake_path=str(_pinned_intake(env)), fetch=False, evidence_dir=str(ev))
    rid = out["run_id"]
    prop = {
        **GOOD,
        "techniques": [tech("T1404"), tech("T1430")],
        "groups": [{"group_id": "G0142", "quote": "Confucius deployed Pegasus for iOS", "source_name": REF}],
    }
    assert not call(server, "submit_proposal", run_id=rid, proposal=prop)["has_errors"]
    res = call(server, "mint_delta", run_id=rid)
    assert res["terminal_state"] == "minted", res
    techs = {t["id"]: t["user_asserted"] for t in res["techniques"]["mobile-attack"]}
    assert techs == {"T1404": True, "T1430": False}
    assert [g["user_asserted"] for g in res["groups"]["mobile-attack"]] == [True]
    (dd,) = [e for e in events(env, rid) if e["event"] == "merge" and e.get("kind") == "dedupe_user_asserted"]
    assert dd["technique_ids"] == ["T1404"] and dd["group_ids"] == ["G0142"] and dd["domain"] == "mobile-attack"
    assert not any(e["event"] == "lint_result" and e.get("phase") == "final" and
                   any(f["severity"] == "ERROR" for f in e["findings"]) for e in events(env, rid))
