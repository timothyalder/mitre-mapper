from __future__ import annotations

import json
import os
import tarfile
import time
from pathlib import Path

from typer.testing import CliRunner

from mitre_mapper.archive import archive_runs
from mitre_mapper.cli import app
from mitre_mapper.runlog import RunLog, read_index

runner = CliRunner()


def _run(runs: Path, mint: bool = True, state: str = "minted") -> str:
    log = RunLog.start(runs, software_name="Demo", intake_text_or_path="hi", model="m",
                       judge_model=None, prompt_text="p")
    if mint:
        log.event("mint", software_id="SX0001", n_objects=1, domains=["mobile-attack"],
                  techniques={"mobile-attack": [
                      {"id": "T1430", "name": "Loc", "user_asserted": False, "sources": ["s"]},
                      {"id": "T1404", "name": "Pinned", "user_asserted": True, "sources": []}]},
                  groups={"mobile-attack": [{"id": "G0001", "name": "G", "user_asserted": False, "kind": "existing"}]})
    log.write_artifact("mobile-attack/proposal_1.json", {"a": 1})
    log.finalize(state)
    return log.run_id


def test_review_file_and_report(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    rid = _run(runs)
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"techniques": {"T1430": "accepted"}, "groups": {"G0001": "rejected"},
                             "missed_techniques": ["T1636"], "notes": "n"}))
    res = runner.invoke(app, ["review", rid, "--file", str(f), "--runs-dir", str(runs)])
    assert res.exit_code == 0, res.output
    assert json.loads((runs / rid / "review.json").read_text())["notes"] == "n"
    rv = read_index(runs)[0].review
    assert rv["precision"] == 0.5 and rv["recall"] == 0.5 and rv["rejected_groups"] == ["G0001"]
    rep = runner.invoke(app, ["report", "--json", "--runs-dir", str(runs)])
    assert json.loads(rep.output)["reviews"]["n_reviewed"] == 1


def test_review_interactive(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    rid = _run(runs)
    # T1430 yes, T1404 (user-asserted) yes, G0001 no; missed techs, missed groups, notes
    res = runner.invoke(app, ["review", rid, "--runs-dir", str(runs)], input="y\ny\nn\nT1636, T1421\n\nlooks ok\n")
    assert res.exit_code == 0, res.output
    rv = read_index(runs)[0].review
    assert rv["n_techniques_accepted"] == 1 and rv["n_groups_rejected"] == 1
    assert rv["missed_techniques"] == ["T1421", "T1636"] and rv["notes"] == "looks ok"


def test_review_without_mint_and_unknown_run(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    rid = _run(runs, mint=False, state="lint_failed")
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"missed_techniques": ["T1430"]}))
    res = runner.invoke(app, ["review", rid, "--file", str(f), "--runs-dir", str(runs)])
    assert res.exit_code == 0
    rv = read_index(runs)[0].review
    assert rv["has_mint"] is False and rv["recall"] == 0.0 and rv["precision"] is None
    assert runner.invoke(app, ["review", "nope", "--file", str(f), "--runs-dir", str(runs)]).exit_code == 2


def test_archive(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    old, new = _run(runs), _run(runs)
    # make `old` old: rename folder to an old stamp (index rows stay; archive keys on folder name)
    old_dir = runs / old
    renamed = runs / ("20200101T000000Z-" + old.split("-", 1)[1])
    old_dir.rename(renamed)
    (renamed / "review.json").write_text("{}")
    (renamed / "delta.json").write_text("{}")
    res = archive_runs(runs, older_than_days=30, dry_run=True)
    assert res.run_ids == [renamed.name] and (renamed / "events.jsonl").exists()
    res = archive_runs(runs, older_than_days=30)
    assert res.archive and res.archive.exists()
    with tarfile.open(res.archive) as tar:
        names = tar.getnames()
    assert f"{renamed.name}/events.jsonl" in names and f"{renamed.name}/mobile-attack/proposal_1.json" in names
    assert not any(n.endswith(("run.md", "review.json", "delta.json")) for n in names)
    assert sorted(p.name for p in renamed.iterdir()) == ["delta.json", "review.json", "run.md"]
    assert (runs / new / "events.jsonl").exists()  # recent run untouched
    assert (runs / "index.jsonl").exists()
    # archived run still reports (without events)
    rep = runner.invoke(app, ["report", "--runs-dir", str(runs)])
    assert rep.exit_code == 0
    cli = runner.invoke(app, ["runs", "archive", "--runs-dir", str(runs)])
    assert cli.exit_code == 0 and "nothing to archive" in cli.output


def test_archive_skips_unfinished(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    log = RunLog.start(runs, software_name="Live", intake_text_or_path="x", model="m",
                       judge_model=None, prompt_text="p")
    ts = time.time() - 90 * 86400
    os.utime(log.events_path, (ts, ts))
    assert archive_runs(runs, older_than_days=0).run_ids == []
