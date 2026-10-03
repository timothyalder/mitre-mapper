from __future__ import annotations

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from fakes import ScriptedChatModel, proposal_msg
from mitre_mapper.cli import app
from mitre_mapper.run import map_software

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "pegasus-ios.md"
runner = CliRunner()

GOOD = {
    "domain": "mobile-attack",
    "techniques": [
        {"technique_id": t, "rationale": "described", "evidence": []} for t in ("T1430", "T1429", "T1409")
    ],
}


def test_report_prints_run(tmp_path):
    alloc = tmp_path / "allocations.json"
    shutil.copy(ROOT / "datasets" / "allocations.json", alloc)
    rec = map_software(
        FIXTURE,
        model=ScriptedChatModel(script=[proposal_msg(GOOD)]),
        runs_dir=tmp_path / "runs",
        datasets_dir=ROOT / "datasets",
        allocations_path=alloc,
    )
    assert rec.terminal_state == "minted"
    res = runner.invoke(app, ["report", "--runs-dir", str(tmp_path / "runs")])
    assert res.exit_code == 0, res.output
    assert "minted=1" in res.output and rec.run_id in res.output
    assert rec.prompt_sha256[:12] in res.output
    js = runner.invoke(app, ["report", "--json", "--last", "1", "--runs-dir", str(tmp_path / "runs")])
    assert json.loads(js.output)["terminal_states"] == {"minted": 1}


def test_report_empty(tmp_path):
    res = runner.invoke(app, ["report", "--runs-dir", str(tmp_path)])
    assert res.exit_code == 0 and "runs: 0" in res.output


def test_map_requires_model(tmp_path, monkeypatch):
    monkeypatch.delenv("MITRE_MAPPER_MODEL", raising=False)
    res = runner.invoke(app, ["map", str(FIXTURE), "--runs-dir", str(tmp_path)])
    assert res.exit_code == 2


def test_map_command_prints_summary(tmp_path, monkeypatch):
    """Drive `map` with a scripted model injected through init_chat_model."""
    alloc = tmp_path / "ds"
    shutil.copytree(ROOT / "datasets", alloc, ignore=shutil.ignore_patterns("enterprise*", "ics*"))
    model = ScriptedChatModel(script=[proposal_msg(GOOD)])
    monkeypatch.setattr("mitre_mapper.agent.init_chat_model", lambda name: model)
    res = runner.invoke(
        app,
        ["map", str(FIXTURE), "--model", "fake:x", "--runs-dir", str(tmp_path / "runs"), "--datasets-dir", str(alloc)],
    )
    assert res.exit_code == 0, res.output
    assert "terminal_state: minted" in res.output and "run.md:" in res.output
