"""Tests for the run log core."""

from __future__ import annotations

import json
import multiprocessing
import re
import subprocess
import warnings
from pathlib import Path
from typing import Any

import pytest

from mitre_mapper import runlog
from mitre_mapper.models import ReviewRecord, RunRecord
from mitre_mapper.runlog import (
    EVENTS,
    Budget,
    BudgetExhausted,
    ProviderError,
    RunLog,
    append_index,
    close_abandoned,
    read_index,
    run_context,
)

REAL_MANIFEST = Path(__file__).resolve().parents[1] / "datasets" / "MANIFEST.json"
MOBILE = "mobile-attack"


def kwargs(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "software_name": "Pegasus for iOS",
        "intake_text_or_path": "---\nname: Pegasus for iOS\n---\nprose\n",
        "model": "fake:model",
        "judge_model": "fake:judge",
        "prompt_text": "You are a mapper.\n",
        "domains": (MOBILE,),
        "manifest_path": REAL_MANIFEST,
    }
    base.update(over)
    return base


def events_of(run_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in (run_dir / "events.jsonl").read_text().splitlines()]


def only_row(runs: Path) -> RunRecord:
    rows = read_index(runs)
    assert len(rows) == 1
    # every line validates as a RunRecord
    for line in (runs / "index.jsonl").read_text().splitlines():
        RunRecord.model_validate_json(line)
    return rows[0]


def test_events_constant_matches_plan() -> None:
    assert len(EVENTS) == 23
    assert {"run_start", "run_end", "error", "group_quote_check"} <= EVENTS


def test_start_writes_header_files_and_events(tmp_path: Path) -> None:
    log = RunLog.start(tmp_path, **kwargs())
    assert re.fullmatch(r"\d{8}T\d{6}Z-pegasus-for-ios-[0-9a-f]{6}", log.run_id)
    assert (log.run_dir / "prompt.txt").read_text() == "You are a mapper.\n"
    assert (log.run_dir / "intake.md").read_text().startswith("---")
    log.event("search", query="x", k=5, returned_ids=["T1"])
    evs = events_of(log.run_dir)
    assert [e["event"] for e in evs] == ["run_start", "search"]
    assert [e["seq"] for e in evs] == [0, 1]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", evs[0]["ts"])
    assert evs[0]["dataset_release"][MOBILE] == "19.2"
    assert len(evs[0]["prompt_sha256"]) == 64 and evs[0]["git_sha"]
    with pytest.raises(ValueError):
        log.event("not_an_event")
    with pytest.raises(ValueError):
        log.event("search", seq=3)


def test_intake_from_path_and_pydantic_event(tmp_path: Path) -> None:
    intake = tmp_path / "in.md"
    intake.write_text("hello")
    log = RunLog.start(tmp_path / "runs", **kwargs(intake_text_or_path=intake))
    assert (log.run_dir / "intake.md").read_text() == "hello"
    log.event("merge", rec=ReviewRecord(run_id="a", ts="t", summary={}))
    assert events_of(log.run_dir)[-1]["rec"]["record"] == "review"


def test_artifacts_and_calls(tmp_path: Path) -> None:
    log = RunLog.start(tmp_path, **kwargs())
    p = log.write_artifact(f"{MOBILE}/proposal_1.json", {"a": 1})
    assert json.loads(p.read_text()) == {"a": 1}
    with pytest.raises(ValueError):
        log.write_artifact("../escape.json", {})
    n1, h1 = log.write_call("search_techniques", {"q": "x"})
    n2, h2 = log.write_call("search_techniques", {"q": "y"})
    assert (n1, n2) == (1, 2) and h1 != h2 and len(h1) == 64
    assert json.loads((log.run_dir / "calls" / "0001.json").read_text())["payload"] == {"q": "x"}


def test_finalize_idempotent_writes_everything(tmp_path: Path) -> None:
    log = RunLog.start(tmp_path, **kwargs())
    log.model_call(10, 5, 0.5)
    rec = log.finalize("declined")
    assert rec is not None
    assert log.finalize("minted") is None
    evs = events_of(log.run_dir)
    ends = [e for e in evs if e["event"] == "run_end"]
    assert len(ends) == 1 and ends[0]["terminal_state"] == "declined"
    assert ends[0]["tokens"] == {"in": 10, "out": 5}
    row = only_row(tmp_path)
    assert row.terminal_state == "declined" and row.n_model_calls == 1
    assert row.tokens == {"in": 10, "out": 5}
    assert row.dataset_release == {
        "enterprise-attack": "19.2",
        "mobile-attack": "19.2",
        "ics-attack": "19.2",
    }
    md = (log.run_dir / "run.md").read_text()
    assert "Pegasus for iOS" in md and "declined" in md and log.run_id in md
    with pytest.raises(ValueError):
        RunLog.start(tmp_path, **kwargs()).finalize("bogus")


def test_index_counters_derived_from_events(tmp_path: Path) -> None:
    log = RunLog.start(tmp_path, **kwargs(domains=()))
    log.event("domain_resolved", domains=[MOBILE, "enterprise-attack"])
    log.event("search", query="a", k=5, returned_ids=["T1"])
    log.event("search", query="b", k=5, returned_ids=[])
    log.event("search", query="c", k=5)
    log.event("reference_fetch_failed", source_name="Lookout", url="u", error="403")
    log.event("reference_fetch_failed", source_name="Other", url=None, error="timeout")
    log.event("proposal_draft", domain=MOBILE, attempt=1)
    log.event(
        "lint_result",
        domain=MOBILE,
        attempt=1,
        findings=[
            {"rule_id": "E002", "severity": "ERROR"},
            {"rule_id": "W001", "severity": "WARN"},
            {"rule_id": "I001", "severity": "INFO"},
        ],
    )
    log.event("proposal_draft", domain=MOBILE, attempt=2)
    log.event(
        "lint_result",
        domain=MOBILE,
        attempt=2,
        findings=[{"rule_id": "E002", "severity": "ERROR"}],
    )
    log.event("proposal_draft", domain="enterprise-attack", attempt=1)
    log.event(
        "judge_verdict",
        domain=MOBILE,
        attempt=2,
        items=[
            {"name": "evidence_grounding", "passed": False},
            {"name": "omission_check", "passed": True},
        ],
    )
    log.event("unmatched_actor", actor="Octo", quote="Octo did it")
    log.finalize("judge_rejected")
    row = only_row(tmp_path)
    assert row.domains == [MOBILE, "enterprise-attack"]
    assert row.attempts == {MOBILE: 2, "enterprise-attack": 1}
    assert row.error_rule_ids == ["E002"]
    assert row.warn_rule_ids == ["W001"]
    assert row.judge_fail_items == ["evidence_grounding"]
    assert row.zero_hit_queries == 2
    assert row.fetch_failures == 2
    assert row.unmatched_actors == 1
    md = (log.run_dir / "run.md").read_text()
    assert "Octo" in md and "Octo did it" in md and "403" in md and "evidence_grounding" in md


def test_budget_exhausted_in_context(tmp_path: Path) -> None:
    with run_context(tmp_path, **kwargs(budget=Budget(max_model_calls=2))) as log:
        for _ in range(5):
            log.model_call(1, 1, 0.1)
    row = only_row(tmp_path)
    assert row.terminal_state == "budget_exhausted" and row.n_model_calls == 3
    names = [e["event"] for e in events_of(tmp_path / row.run_id)]
    assert names[-2:] == ["budget_exhausted", "run_end"]


def test_token_budget() -> None:
    b = Budget(max_model_calls=100, max_tokens=10)
    b.record_model_call(5, 4, 0.1)
    with pytest.raises(BudgetExhausted):
        b.record_model_call(1, 1, 0.1)


def test_provider_error_in_context(tmp_path: Path) -> None:
    with run_context(tmp_path, **kwargs()):
        raise ProviderError("429 rate limited")
    row = only_row(tmp_path)
    assert row.terminal_state == "provider_error"
    evs = events_of(tmp_path / row.run_id)
    assert any(e["event"] == "provider_error" and "429" in e["message"] for e in evs)
    assert "429 rate limited" in (tmp_path / row.run_id / "run.md").read_text()


def test_other_exception_reraised_and_logged(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="boom"):
        with run_context(tmp_path, **kwargs()):
            raise ValueError("boom")
    row = only_row(tmp_path)
    assert row.terminal_state == "error"
    err = next(e for e in events_of(tmp_path / row.run_id) if e["event"] == "error")
    assert err["type"] == "ValueError" and err["message"] == "boom" and "traceback" in err


def test_keyboard_interrupt_finalizes(tmp_path: Path) -> None:
    with pytest.raises(KeyboardInterrupt):
        with run_context(tmp_path, **kwargs()):
            raise KeyboardInterrupt
    assert only_row(tmp_path).terminal_state == "error"


def test_body_without_finalize(tmp_path: Path) -> None:
    with run_context(tmp_path, **kwargs()):
        pass
    row = only_row(tmp_path)
    assert row.terminal_state == "error"
    assert "without terminal state" in (tmp_path / row.run_id / "run.md").read_text()


def test_body_finalize_respected(tmp_path: Path) -> None:
    with run_context(tmp_path, **kwargs()) as log:
        log.finalize("minted")
    assert only_row(tmp_path).terminal_state == "minted"


def _worker(runs: str, i: int) -> None:
    for j in range(10):
        append_index(
            runs,
            RunRecord(
                run_id=f"r{i}-{j}",
                ts="t",
                software_name="x" * 5000,  # long line to stress atomicity
                intake_sha256="a",
                domains=[],
                model="m",
                git_sha="g",
                prompt_sha256="p",
                tool_version="v",
                dataset_release={},
                terminal_state="minted",
            ),
        )


def test_concurrent_appends(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_worker, args=(str(tmp_path), i)) for i in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    lines = (tmp_path / "index.jsonl").read_text().splitlines()
    assert len(lines) == 40
    for line in lines:
        RunRecord.model_validate_json(line)


def test_read_index_joins_review_and_tolerates_corruption(tmp_path: Path) -> None:
    with run_context(tmp_path, **kwargs()) as log:
        log.finalize("minted")
    append_index(tmp_path, ReviewRecord(run_id="other", ts="t", summary={"x": 0}))
    append_index(tmp_path, ReviewRecord(run_id=log.run_id, ts="t1", summary={"p": 0.5}))
    append_index(tmp_path, ReviewRecord(run_id=log.run_id, ts="t2", summary={"p": 0.9}))
    with (tmp_path / "index.jsonl").open("a") as fh:
        fh.write('{"record": "run", "run_id": \n')
        fh.write("garbage\n")
    with pytest.warns(UserWarning, match="corrupt"):
        rows = read_index(tmp_path)
    assert len(rows) == 1 and rows[0].review == {"p": 0.9}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert read_index(tmp_path / "missing") == []


def test_close_abandoned(tmp_path: Path) -> None:
    abandoned = RunLog.start(tmp_path, **kwargs())
    abandoned.model_call(7, 3, 0.2)
    abandoned.event("proposal_draft", domain=MOBILE, attempt=1)
    done = RunLog.start(tmp_path, **kwargs(software_name="Other"))
    done.finalize("minted")
    (tmp_path / "not-a-run").mkdir()

    assert close_abandoned(tmp_path) == [abandoned.run_id]
    assert close_abandoned(tmp_path) == []
    rows = {r.run_id: r for r in read_index(tmp_path)}
    r = rows[abandoned.run_id]
    assert r.terminal_state == "abandoned" and r.attempts == {MOBILE: 1}
    assert r.n_model_calls == 1 and r.tokens == {"in": 7, "out": 3}
    assert r.git_sha == abandoned.header["git_sha"]
    assert rows[done.run_id].terminal_state == "minted"
    evs = events_of(abandoned.run_dir)
    assert evs[-1]["event"] == "run_end" and evs[-1]["seq"] == len(evs) - 1


def test_git_unavailable_does_not_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", boom)
    log = RunLog.start(tmp_path, **kwargs())
    assert log.header["git_sha"] == "unknown"
    log.finalize("minted")
    assert only_row(tmp_path).git_sha == "unknown"


def test_missing_manifest_gives_empty_release(tmp_path: Path) -> None:
    log = RunLog.start(tmp_path, **kwargs(manifest_path=tmp_path / "nope.json"))
    log.finalize("minted")
    assert only_row(tmp_path).dataset_release == {}


def test_dirty_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(args: Any, cwd: Path) -> str:
        return {"status": " M x\n", "rev-parse": "abc123\n"}[args[0]]

    monkeypatch.setattr(runlog, "_git", fake)
    assert runlog._git_sha() == "abc123-dirty"
    _ = runlog.RunLog  # keep import used


def test_run_md_renders_mapping_and_attempts_from_events(tmp_path):
    log = RunLog.start(
        tmp_path, software_name="S", intake_text_or_path="x", model="m", judge_model="j", prompt_text="p"
    )
    log.event("domain_resolved", domains=["mobile-attack"])
    for att in (1, 2):
        log.event("proposal_draft", domain="mobile-attack", attempt=att)
    log.event(
        "lint_result", domain="mobile-attack", attempt=1,
        findings=[{"rule_id": "E004", "severity": "ERROR"}, {"rule_id": "I001", "severity": "INFO"}],
    )
    log.event("lint_result", domain="mobile-attack", attempt=2, findings=[])
    log.event("group_quote_check", domain="mobile-attack", attempt=1, group_id="G0142", passed=False, reason="not verbatim")
    log.event(
        "judge_verdict", domain="mobile-attack", attempt=2, approved=False, prompt_sha256="a" * 64,
        items=[{"name": "omission_check", "passed": False, "rationale": "r"},
               {"name": "evidence_grounding", "passed": True, "rationale": "r"}],
    )
    log.event(
        "mint", software_id="x", n_objects=3, domains=["mobile-attack"],
        techniques={"mobile-attack": [
            {"id": "T1430", "name": "Location Tracking", "user_asserted": False, "sources": ["Rpt A", "Rpt B"]},
            {"id": "T1404", "name": "Exploit", "user_asserted": True, "sources": ["mitre-mapper intake"]},
        ]},
        groups={"mobile-attack": [{"id": "GX0001", "name": "Actor", "user_asserted": True, "kind": "new"}]},
    )
    log.finalize("minted")
    md = (log.run_dir / "run.md").read_text()
    assert "## Mapping\n### mobile-attack\n- T1430 Location Tracking -- Rpt A, Rpt B" in md
    assert "- T1404 Exploit -- user-asserted" in md
    assert "- group GX0001 Actor (new, user-asserted)" in md
    assert "- mobile-attack #1: lint ERROR E004" in md
    assert "- mobile-attack #2: lint clean; judge failed omission_check" in md
    assert "G0142: not verbatim" in md
    assert len(md.splitlines()) < 40  # stays compact


def test_run_md_without_mint_has_no_mapping_section(tmp_path):
    log = RunLog.start(tmp_path, software_name="S", intake_text_or_path="x", model="m", judge_model=None, prompt_text="p")
    log.finalize("declined")
    md = (log.run_dir / "run.md").read_text()
    assert "## Mapping" not in md and "## Attempts" not in md
