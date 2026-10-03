"""report.build_report on a synthetic multi-run index (events, reviews, eval scores)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mitre_mapper.cli import app
from mitre_mapper.models import Review, RunRecord
from mitre_mapper.report import ReportError, build_report, events_loader_for, render_text
from mitre_mapper.review import record_review
from mitre_mapper.runlog import append_index, read_index

runner = CliRunner()


def _rec(i: int, state: str, psha: str, gsha: str, **kw) -> RunRecord:
    return RunRecord(
        run_id=f"2026010{i}T000000Z-sw{i}-aaaaaa",
        ts=f"2026-01-0{i}T00:00:00.000Z",
        software_name=f"sw{i}",
        intake_sha256="x",
        domains=["mobile-attack"],
        model="m",
        git_sha=gsha,
        prompt_sha256=psha,
        tool_version="0",
        dataset_release={},
        terminal_state=state,
        **kw,
    )


def _write_events(runs: Path, rec: RunRecord, events: list[dict]) -> None:
    d = runs / rec.run_id
    d.mkdir(parents=True)
    with (d / "events.jsonl").open("w") as fh:
        for n, ev in enumerate(events):
            fh.write(json.dumps({"ts": rec.ts, "seq": n, **ev}) + "\n")


def _lint(rule: str, sev: str, msg: str, attempt: int = 1) -> dict:
    return {
        "event": "lint_result",
        "domain": "mobile-attack",
        "attempt": attempt,
        "findings": [{"rule_id": rule, "severity": sev, "message": msg, "target": "T1"}],
    }


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    r = tmp_path / "runs"
    A, B = "a" * 64, "b" * 64
    recs = [
        _rec(1, "lint_failed", A, "g1" * 20, error_rule_ids=["E012"], eval_case="c1",
             eval_scores={"recall": {"exact": 0.2}, "n": 3}),
        _rec(2, "minted", A, "g1" * 20, warn_rule_ids=["W001"], surface="mcp"),
        _rec(3, "minted", B, "g2" * 20 + "-dirty", eval_case="c1", eval_scores={"recall": {"exact": 0.6}, "n": 3}),
    ]
    _write_events(r, recs[0], [
        _lint("E012", "ERROR", "quote not found"), _lint("E012", "ERROR", "quote not found 2", 2),
        {"event": "search", "tool": "search_techniques", "query": "zzz", "k": 5, "returned_ids": []},
        {"event": "search", "tool": "search_techniques", "query": "zzz", "k": 5, "returned_ids": []},
        {"event": "search", "tool": "search_techniques", "query": "ok", "k": 5, "returned_ids": ["T1"]},
        {"event": "reference_fetch_failed", "source_name": "S", "url": "http://x", "error": "HTTP 403"},
        {"event": "reference_fetch", "source_name": "S2", "url": "http://y", "ok": True},
        {"event": "unmatched_actor", "actor": "APT-X", "quote": "APT-X used it", "source_name": "S2"},
        {"event": "judge_verdict", "domain": "d", "attempt": 1, "approved": False,
         "items": [{"name": "evidence_grounding", "passed": False, "rationale": "weak"},
                   {"name": "omission_check", "passed": True, "rationale": ""}]},
        {"event": "retry", "reason": "lint_errors: E012"},
        {"event": "group_quote_check", "passed": False, "reason": "no alias", "group_id": "G1"},
    ])
    _write_events(r, recs[1], [_lint("W001", "WARN", "platform"), {"event": "judge_verdict", "approved": True,
        "items": [{"name": "evidence_grounding", "passed": True, "rationale": ""}]},
        {"event": "mint", "software_id": "SX0001", "n_objects": 3, "domains": ["mobile-attack"],
         "techniques": {"mobile-attack": [{"id": "T1430", "name": "Loc", "user_asserted": False, "sources": ["s"]},
                                          {"id": "T1409", "name": "Stored", "user_asserted": False, "sources": ["s"]}]},
         "groups": {}}])
    # run 3 has no events.jsonl: archived / missing
    for rec in recs:
        append_index(r, rec)
    record_review(r, recs[1].run_id, Review(run_id=recs[1].run_id, ts="2026-01-09T00:00:00.000Z",
        techniques={"T1430": "accepted", "T1409": "rejected"}, missed_techniques=["T1404"]))
    return r


def test_report_sections(runs: Path) -> None:
    rep = build_report(read_index(runs), events_loader_for(runs))
    assert rep["schema_version"] == 1
    assert rep["window"]["n_runs"] == 3 and rep["window"]["runs_without_events"] == 1
    assert rep["terminal_states"] == {"lint_failed": 1, "minted": 2}
    assert rep["terminal_state_detail"][0]["state"] == "lint_failed"
    e012 = rep["rules"]["error"][0]
    assert e012["rule_id"] == "E012" and e012["n_findings"] == 2 and e012["n_runs"] == 1
    assert e012["share_of_runs"] == round(1 / 3, 3)
    assert e012["run_ids"] == [read_index(runs)[0].run_id]
    assert e012["examples"][0]["message"] == "quote not found"
    assert rep["rules"]["warn"][0]["rule_id"] == "W001"
    ji = {j["item"]: j for j in rep["judge_items"]}
    assert ji["evidence_grounding"]["n_failed"] == 1 and ji["evidence_grounding"]["n_verdicts"] == 2
    assert ji["evidence_grounding"]["fail_rate"] == 0.5
    assert rep["judge"] == {"n_verdicts": 2, "n_rejected": 1, "reject_rate": 0.5}
    s = rep["searches"]
    assert (s["n_searches"], s["n_zero_hit"]) == (3, 2) and s["top_zero_hit_queries"] == [{"query": "zzz", "count": 2}]
    assert s["example_queries"][0]["query"] == "zzz"
    f = rep["fetch"]
    assert (f["n_references"], f["n_failures"], f["failure_rate"]) == (2, 1, 0.5)
    assert f["by_error"] == [{"error": "HTTP 403", "count": 1}] and f["examples"][0]["url"] == "http://x"
    assert rep["unmatched_actors"][0]["actor"] == "APT-X"
    assert rep["unmatched_actors"][0]["example_quote"] == "APT-X used it"
    assert rep["group_quote_checks"]["n_failed"] == 1
    assert rep["retries"]["by_reason"][0]["reason"] == "lint_errors: E012"
    assert rep["by_surface"] == {"langchain": {"n_runs": 2, "terminal_states": {"lint_failed": 1, "minted": 1}},
                                 "mcp": {"n_runs": 1, "terminal_states": {"minted": 1}}}
    json.dumps(rep)  # serialisable


def test_report_reviews_and_eval_and_cohorts(runs: Path) -> None:
    rep = build_report(read_index(runs), events_loader_for(runs))
    rv = rep["reviews"]
    assert rv["n_reviewed"] == 1 and rv["precision"] == 0.5 and rv["recall"] == 0.5
    assert rv["most_rejected"][0]["id"] == "T1409" and rv["most_missed"][0]["id"] == "T1404"
    assert [e["scores"]["recall"]["exact"] for e in rep["eval"]["c1"]] == [0.2, 0.6]
    c = rep["cohorts"]
    assert [(x["prompt_sha256"][:1], x["n_runs"]) for x in c] == [("a", 2), ("b", 1)]
    assert c[1]["git_sha"].endswith("-dirty")
    assert c[0]["metrics"]["minted_rate"] == 0.5 and c[0]["metrics"]["lint_error_run_share"] == 0.5
    assert c[0]["metrics"]["eval.c1.recall.exact"] == 0.2
    diff = rep["cohort_comparison"][0]["diff"]
    assert diff["eval.c1.recall.exact"] == 0.4 and diff["minted_rate"] == 0.5


def test_window_since_and_last(runs: Path) -> None:
    rows = read_index(runs)
    ld = events_loader_for(runs)
    assert build_report(rows, ld, last=1)["window"]["first_run_id"] == rows[2].run_id
    assert build_report(rows, ld, since="2026-01-02")["window"]["n_runs"] == 2
    assert build_report(rows, ld, since=rows[1].run_id)["window"]["first_run_id"] == rows[1].run_id
    assert build_report(rows, ld, since="2027-01-01")["window"]["n_runs"] == 0
    with pytest.raises(ReportError):
        build_report(rows, ld, since="not-a-date")


def test_caps(tmp_path: Path) -> None:
    rows = []
    for i in range(1, 10):
        rec = _rec(i, "lint_failed", "a" * 64, "g" * 40, error_rule_ids=["E001"])
        rows.append(rec)
        _write_events(tmp_path, rec, [_lint("E001", "ERROR", "m")] * 8)
    rep = build_report(rows, events_loader_for(tmp_path))
    import mitre_mapper.report as m
    r = rep["rules"]["error"][0]
    assert r["n_runs"] == 9 and r["n_findings"] == 72
    assert len(r["run_ids"]) <= m.RUN_CAP and len(r["examples"]) == m.EXAMPLE_CAP


def test_render_text_and_empty(runs: Path) -> None:
    rep = build_report(read_index(runs), events_loader_for(runs))
    txt = render_text(rep)
    assert "E012" in txt and "zero-hit searches: 2/3" in txt and "APT-X" in txt and "reviews: 1 runs" in txt
    assert render_text(build_report([], None)) == "runs: 0"


def test_cli_report_json_and_since(runs: Path) -> None:
    res = runner.invoke(app, ["report", "--json", "--runs-dir", str(runs)])
    assert res.exit_code == 0 and json.loads(res.output)["window"]["n_runs"] == 3
    res = runner.invoke(app, ["report", "--since", "2026-01-03", "--runs-dir", str(runs)])
    assert res.exit_code == 0 and "runs: 1" in res.output
    assert runner.invoke(app, ["report", "--since", "bogus", "--runs-dir", str(runs)]).exit_code == 2


def test_unscored_eval_runs_do_not_drag_cohort_means(tmp_path):
    # Issue #2: provider_error rows (old ones recorded zeros without a `scored` flag) are skipped.
    from mitre_mapper.report import build_report

    P, G = "p" * 64, "g" * 40
    rows = [
        _rec(1, "minted", P, G, eval_case="c1", eval_scores={"scored": True, "technique": {"exact": {"f1": 0.6}}}),
        _rec(2, "provider_error", P, G, eval_case="c1", eval_scores={"technique": {"exact": {"f1": 0}}}),  # legacy zero
        _rec(3, "provider_error", P, G, eval_case="c1",
             eval_scores={"scored": False, "reason": "provider_error", "error": "limit"}),
    ]
    m = build_report(rows, lambda run_id: [])["cohorts"][0]["metrics"]
    assert m["eval.c1.technique.exact.f1"] == 0.6
    assert m["eval.c1.n_scored"] == 1 and m["eval.c1.n_unscored"] == 2
