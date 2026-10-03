"""tools.py: compact dicts, one logging wrapper, never raises."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitre_mapper import tools as T
from mitre_mapper.intake import parse_intake
from mitre_mapper.runlog import RunLog

FIXTURE = Path(__file__).parent / "fixtures" / "pegasus-ios.md"


@pytest.fixture
def ctx(tmp_path, attack_store):
    log = RunLog.start(
        tmp_path / "runs",
        software_name="t",
        intake_text_or_path=FIXTURE,
        model="m",
        judge_model=None,
        prompt_text="p",
    )
    return T.ToolContext(
        log=log,
        store=attack_store,
        domain="mobile-attack",
        spec=parse_intake(FIXTURE),
        evidence={"Src": "some evidence text"},
    )


def events(ctx, name):
    return [
        e
        for e in map(json.loads, ctx.log.events_path.read_text().splitlines())
        if e["event"] == name
    ]


def test_search_logs_search_and_tool_call(ctx):
    out = T.search_techniques(ctx, query="location tracking", k=5)
    assert out["results"] and {"id", "name", "description", "tactics", "platforms"} <= set(out["results"][0])
    (search,) = events(ctx, "search")
    (call,) = events(ctx, "tool_call")
    assert search["query"] == "location tracking" and search["k"] == 5
    assert search["returned_ids"] == [r["id"] for r in out["results"]]
    assert search["call_id"] == call["call_id"] and call["ok"] and len(call["sha256"]) == 64
    assert (ctx.log.run_dir / "calls" / f"{call['call_id']:04d}.json").exists()
    assert ctx.returned_ids == search["returned_ids"]


def test_zero_hit_search(ctx):
    out = T.search_techniques(ctx, query="zzzqqqxxx")
    assert out["results"] == []
    assert events(ctx, "search")[0]["returned_ids"] == []


def test_get_technique_and_errors_never_raise(ctx):
    ok = T.get_technique(ctx, attack_id="T1430")
    assert ok["id"] == "T1430" and ok["tactics"]
    err = T.get_technique(ctx, attack_id="T1059")  # enterprise-only
    assert "error" in err
    assert [e["ok"] for e in events(ctx, "tool_call")] == [True, False]
    assert "error" in T.get_technique(ctx, attack_id="T1430", bogus=1)  # bad args


def test_revoked_redirect(ctx):
    out = T.get_technique(ctx, attack_id="T1579")  # revoked Keychain -> T1634.001
    assert out["id"] == "T1634.001" and out["redirected_from"] == "T1579"
    (rr,) = events(ctx, "revoked_redirect")
    assert (rr["from_id"], rr["to_id"]) == ("T1579", "T1634.001")


def test_get_software_and_techniques(ctx):
    sw = T.get_software(ctx, attack_id="S0316")
    assert sw["id"] == "S0316"
    techs = T.get_software_techniques(ctx, attack_id="S0316")
    assert techs["techniques"]


def test_get_evidence(ctx):
    assert T.get_evidence(ctx, source_name="Src")["text"] == "some evidence text"
    miss = T.get_evidence(ctx, source_name="Nope")
    assert "error" in miss and miss["available"] == ["Src"]


def test_read_reference_allowlist(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(T, "REFERENCES_DIR", tmp_path)
    (tmp_path / "linter-rules.md").write_text("rules")
    (tmp_path / "judge-rubric.md").write_text("SECRET")
    assert T.read_reference(ctx, name="linter-rules.md")["text"] == "rules"
    assert "error" in T.read_reference(ctx, name="stix-shapes.md")  # allowed but missing
    denied = T.read_reference(ctx, name="judge-rubric.md")
    assert "error" in denied and "SECRET" not in json.dumps(denied)
    assert "error" in T.read_reference(ctx, name="../../pyproject.toml")
