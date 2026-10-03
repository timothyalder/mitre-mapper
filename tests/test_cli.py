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
        {
            "technique_id": t,
            "rationale": "described",
            "evidence": [{"source_name": "mitre-mapper intake description", "quote": "collects location data"}],
        }
        for t in ("T1430", "T1429", "T1409")
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
        fetch=False,
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
    res = runner.invoke(app, ["map", str(FIXTURE), "--runs-dir", str(tmp_path), "--no-fetch"])
    assert res.exit_code == 2


def test_map_command_prints_summary(tmp_path, monkeypatch):
    """Drive `map` with a scripted model injected through init_chat_model."""
    alloc = tmp_path / "ds"
    shutil.copytree(ROOT / "datasets", alloc, ignore=shutil.ignore_patterns("enterprise*", "ics*"))
    model = ScriptedChatModel(script=[proposal_msg(GOOD)])
    monkeypatch.setattr("mitre_mapper.agent.init_chat_model", lambda name: model)
    res = runner.invoke(
        app,
        [
            "map", str(FIXTURE), "--model", "fake:x", "--runs-dir", str(tmp_path / "runs"),
            "--datasets-dir", str(alloc), "--no-fetch",
        ],
    )
    assert res.exit_code == 0, res.output
    assert "terminal_state: minted" in res.output and "run.md:" in res.output


def test_map_passes_evidence_and_fetch_options(tmp_path, monkeypatch):
    seen = {}

    def fake_map(intake, **kw):
        seen.update(kw)
        raise SystemExit(0)

    monkeypatch.setattr("mitre_mapper.run.map_software", fake_map)
    monkeypatch.setenv("MITRE_MAPPER_JUDGE_MODEL", "judge:env")
    ev = tmp_path / "ev"
    runner.invoke(
        app,
        ["map", str(FIXTURE), "--model", "m", "--no-fetch", "--no-cache", "--evidence-dir", str(ev),
         "--fetch-timeout", "3.5", "--runs-dir", str(tmp_path)],
    )
    assert seen["fetch"] is False and seen["use_cache"] is False
    assert seen["evidence_dir"] == ev and seen["fetch_timeout"] == 3.5
    assert seen["judge_model"] == "judge:env"
    seen.clear()
    runner.invoke(app, ["map", str(FIXTURE), "--model", "m", "--runs-dir", str(tmp_path)])
    assert seen["fetch"] is True and seen["use_cache"] is True and seen["evidence_dir"] is None


def test_judge_command_replays_a_recorded_attempt(tmp_path, monkeypatch):
    from fakes import verdict_msg

    alloc = tmp_path / "allocations.json"
    shutil.copy(ROOT / "datasets" / "allocations.json", alloc)
    runs = tmp_path / "runs"
    rec = map_software(
        FIXTURE,
        model=ScriptedChatModel(script=[proposal_msg(GOOD)]),
        runs_dir=runs,
        datasets_dir=ROOT / "datasets",
        allocations_path=alloc,
        fetch=False,
    )
    judge_model = ScriptedChatModel(script=[verdict_msg(("omission_check",))])
    monkeypatch.setattr("langchain.chat_models.init_chat_model", lambda name: judge_model)
    res = runner.invoke(
        app,
        ["judge", "--run", rec.run_id, "--domain", "mobile-attack", "--attempt", "1", "--model", "fake:j",
         "--runs-dir", str(runs)],
    )
    assert res.exit_code == 0, res.output
    assert "approved: False" in res.output
    assert "[FAIL] omission_check" in res.output and "[PASS] evidence_grounding" in res.output
    assert "prompt_sha256:" in res.output
    missing = runner.invoke(
        app, ["judge", "--run", rec.run_id, "--domain", "mobile-attack", "--attempt", "9", "--model", "m",
              "--runs-dir", str(runs)],
    )
    assert missing.exit_code == 2
    monkeypatch.delenv("MITRE_MAPPER_JUDGE_MODEL", raising=False)
    nomodel = runner.invoke(
        app, ["judge", "--run", rec.run_id, "--domain", "mobile-attack", "--attempt", "1", "--runs-dir", str(runs)]
    )
    assert nomodel.exit_code == 2


# --- Wave 4A: datasets / materialize / delta doctor ---------------------------------


def _delta_env(tmp_path):
    from mitre_mapper.store import AttackStore
    from test_delta import make_run

    ds = tmp_path / "ds"
    ds.mkdir()
    shutil.copy(Path(__file__).resolve().parents[1] / "datasets" / "mobile-attack.json", ds / "mobile-attack.json")
    shutil.copy(Path(__file__).resolve().parents[1] / "datasets" / "MANIFEST.json", ds / "MANIFEST.json")
    run_dir = make_run(tmp_path, AttackStore(ds), "Alpha Spy")
    shutil.copy(tmp_path / "allocations.json", ds / "allocations.json")
    return ds, run_dir


def test_datasets_status_command():
    res = CliRunner().invoke(app, ["datasets", "status", "--datasets-dir", str(Path(__file__).resolve().parents[1] / "datasets")])
    assert res.exit_code == 0, res.output
    assert "pinned ATT&CK release: 19.2" in res.output and "mobile-attack: 19.2 ok" in res.output


def test_datasets_status_command_fails_on_problem(tmp_path):
    shutil.copy(Path(__file__).resolve().parents[1] / "datasets" / "MANIFEST.json", tmp_path / "MANIFEST.json")
    res = CliRunner().invoke(app, ["datasets", "status", "--datasets-dir", str(tmp_path)])
    assert res.exit_code == 1 and "PROBLEM" in res.output


def test_datasets_update_noop_when_already_on_target(tmp_path, monkeypatch):
    shutil.copy(Path(__file__).resolve().parents[1] / "datasets" / "MANIFEST.json", tmp_path / "MANIFEST.json")
    res = CliRunner().invoke(app, ["datasets", "update", "--to", "19.2", "--datasets-dir", str(tmp_path)])
    assert res.exit_code == 0 and "nothing to do" in res.output


def test_delta_doctor_and_materialize_commands(tmp_path):
    ds, run_dir = _delta_env(tmp_path)
    runs = str(run_dir.parent)
    r = CliRunner()
    res = r.invoke(app, ["delta", "doctor", "--all", "--runs-dir", runs, "--datasets-dir", str(ds), "--json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)[0]["ok"] is True
    res = r.invoke(app, ["delta", "doctor", run_dir.name, "--runs-dir", runs, "--datasets-dir", str(ds)])
    assert res.exit_code == 0 and f"{run_dir.name}: ok" in res.output
    assert r.invoke(app, ["delta", "doctor"]).exit_code == 2  # neither id nor --all
    out = tmp_path / "out"
    res = r.invoke(
        app,
        ["materialize", run_dir.name, "--domain", "mobile-attack", "--out", str(out), "--runs-dir", runs, "--datasets-dir", str(ds)],
    )
    assert res.exit_code == 0, res.output
    assert (out / "mobile-attack.json").is_file() and "mobile-attack:" in res.output


def test_materialize_command_reports_errors(tmp_path):
    ds, run_dir = _delta_env(tmp_path)
    res = CliRunner().invoke(
        app,
        ["materialize", run_dir.name, "--domain", "ics-attack", "--out", str(tmp_path / "o"),
         "--runs-dir", str(run_dir.parent), "--datasets-dir", str(ds)],
    )
    assert res.exit_code == 1 and "not targeted" in res.output
