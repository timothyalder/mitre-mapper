"""session.py core: shared by run.py and the MCP server."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

import pytest

from mitre_mapper import session as S
from mitre_mapper import tools as T
from mitre_mapper.models import MappingProposal
from mitre_mapper.runlog import read_index

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
FIXTURE = ROOT / "tests" / "fixtures" / "pegasus-ios.md"
REF = "Test Fixture Reference"
PROSE = "mitre-mapper intake description"  # the intake prose, as an evidence source


def tech(tid):
    return {"technique_id": tid, "rationale": "r", "evidence": [{"source_name": PROSE, "quote": "collects location data"}]}


@pytest.fixture
def sess(tmp_path):
    alloc = tmp_path / "alloc.json"
    shutil.copy(DATASETS / "allocations.json", alloc)
    session, log = S.start_session(
        FIXTURE, runs_dir=tmp_path / "runs", datasets_dir=DATASETS, allocations_path=alloc,
        fetch=False, cache_dir=tmp_path / "cache",
    )
    assert session is not None
    return session


def evs(session):
    return [json.loads(l) for l in session.log.events_path.read_text().splitlines()]


def test_start_session_header_and_events(sess):
    h = evs(sess)
    assert h[0]["event"] == "run_start" and h[0]["surface"] == "mcp" and h[0]["judge_model"] is None
    assert [e["event"] for e in h[1:3]] == ["domain_resolved", "reference_fetch_failed"] or h[1]["event"] == "domain_resolved"
    assert any(e["event"] == "merge" and e["kind"] == "judge_config" and e["judge"] is None for e in h)
    assert len(h[0]["prompt_sha256"]) == 64 and h[0]["git_sha"]


def test_process_proposal_forces_unasserted_and_logs(sess):
    ctx = sess.context()
    ctx.returned_ids.extend(["T1430", "T1999"])
    raw = MappingProposal.model_validate({"domain": "mobile-attack", "techniques": [{**tech("T1430"), "user_asserted": True}]})
    res = S.process_proposal(ctx, raw, attempt=1, prev=None, retry_reason=None, created=sess.created)
    assert res.proposal.techniques[0].user_asserted is False and not res.has_errors
    draft = next(e for e in evs(sess) if e["event"] == "proposal_draft")
    assert draft["rejected_candidates"] == ["T1999"]
    assert (sess.log.run_dir / "mobile-attack" / "lint_1.json").exists()


def test_session_tools_need_a_session(sess):
    ctx = T.ToolContext(log=sess.log, store=sess.store, domain="mobile-attack", spec=sess.spec)
    out = T.mint_delta(ctx)
    assert "needs an MCP session" in out["error"]
    assert not sess.log.finalized


def test_context_rejects_closed_runs(sess):
    sess.log.finalize("error", error="x")
    with pytest.raises(S.SessionError):
        sess.context()
    assert read_index(sess.log.runs_dir)[0].surface == "mcp"


def test_stdio_entry_point_serves_all_tools(tmp_path):
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "mitre_mapper.mcp_server", "--runs-dir", str(tmp_path / "runs"), "--datasets-dir", str(DATASETS)],
    )

    async def go():
        async with Client(transport) as c:
            tools = {t.name for t in await c.list_tools()}
            r = await c.call_tool("start_run", {"intake_path": str(tmp_path / "nope.md")})
            return tools, r.data

    tools, started = asyncio.run(go())
    assert {"start_run", "submit_proposal", "mint_delta", "end_run"} <= tools
    assert started["terminal_state"] == "error"
    assert read_index(tmp_path / "runs")[0].surface == "mcp"


def test_render_helpers_share_pinned_items_and_previous_proposal(sess):
    spec = sess.spec.model_copy(update={"techniques": ["T1404"]})
    pinned = S.pinned_items(spec)
    assert pinned["techniques"] == ["T1404"] and pinned["existing_groups"] == [] and pinned["new_groups"] == []
    assert "T1404" in S.render_pinned(spec) and S.render_pinned(sess.spec) is None
    prev = MappingProposal.model_validate({
        "domain": "mobile-attack",
        "techniques": [tech("T1430"), {**tech("T1404"), "user_asserted": True}],
    })
    msg = S.render_retry_message("FEEDBACK", prev)
    assert msg.startswith("FEEDBACK") and '"technique_id":"T1430"' in msg and "T1404" not in msg
    assert S.render_retry_message("FEEDBACK", None) == "FEEDBACK"
