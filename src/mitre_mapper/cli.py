"""typer CLI: ``map`` and a minimal Wave 2 ``report``.

No LangChain imports at module level: ``map`` imports :mod:`mitre_mapper.run` lazily so
``report`` stays instant and acceptance criterion 13 holds.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

import typer

from mitre_mapper.models import RunRecord
from mitre_mapper.runlog import read_index

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Map software to MITRE ATT&CK.")


@dataclass
class Config:
    """Defaults per PLAN 3.11. Typer options override; no pydantic-settings."""

    model: str | None = field(default_factory=lambda: os.environ.get("MITRE_MAPPER_MODEL"))
    judge_model: str | None = field(
        default_factory=lambda: os.environ.get("MITRE_MAPPER_JUDGE_MODEL")
    )
    datasets_dir: Path = Path("datasets")
    runs_dir: Path = Path("runs")
    max_attempts: int = 3
    max_model_calls: int = 60
    fetch: bool = True  # used from Wave 3A
    fetch_timeout: float = 20.0
    evidence_dir: Path | None = None


@app.command("map")
def map_cmd(
    intake: Annotated[Path, typer.Argument(help="Intake markdown file.")],
    model: Annotated[str | None, typer.Option(help="Model string (env MITRE_MAPPER_MODEL).")] = None,
    judge_model: Annotated[str | None, typer.Option(help="Judge model (env MITRE_MAPPER_JUDGE_MODEL).")] = None,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
    max_attempts: Annotated[int, typer.Option()] = 3,
    max_model_calls: Annotated[int, typer.Option()] = 60,
) -> None:
    """Map INTAKE to ATT&CK objects; prints run id, terminal state and run.md path."""
    cfg = Config()
    chosen = model or cfg.model
    if not chosen:
        typer.echo("error: pass --model or set MITRE_MAPPER_MODEL", err=True)
        raise typer.Exit(2)
    from mitre_mapper.run import map_software  # lazy: pulls in langchain

    record = map_software(
        intake,
        model=chosen,
        judge_model=judge_model or cfg.judge_model,
        runs_dir=runs_dir,
        datasets_dir=datasets_dir,
        max_attempts=max_attempts,
        max_model_calls=max_model_calls,
    )
    typer.echo(f"run_id: {record.run_id}")
    typer.echo(f"terminal_state: {record.terminal_state}")
    typer.echo(f"run.md: {Path(runs_dir) / record.run_id / 'run.md'}")
    if record.terminal_state not in ("minted", "declined"):
        raise typer.Exit(1)


def build_report(rows: list[RunRecord]) -> dict[str, Any]:
    """Minimal cross-run aggregation (full version: Wave 5B)."""
    states = Counter(r.terminal_state for r in rows)
    err = Counter(rid for r in rows for rid in r.error_rule_ids)
    warn = Counter(rid for r in rows for rid in r.warn_rule_ids)
    judge = Counter(i for r in rows for i in r.judge_fail_items)
    groups: dict[str, dict[str, Any]] = {}
    for r in rows:
        g = groups.setdefault(r.prompt_sha256[:12], {"runs": 0, "minted": 0})
        g["runs"] += 1
        g["minted"] += r.terminal_state == "minted"
    return {
        "n_runs": len(rows),
        "terminal_states": dict(states),
        "error_rules": err.most_common(),
        "warn_rules": warn.most_common(),
        "judge_fail_items": judge.most_common(),
        "zero_hit_queries": sum(r.zero_hit_queries for r in rows),
        "fetch_failures": sum(r.fetch_failures for r in rows),
        "unmatched_actors": sum(r.unmatched_actors for r in rows),
        "by_prompt_sha256": groups,
    }


@app.command("report")
def report_cmd(
    last: Annotated[int | None, typer.Option("--last", help="Only the last N runs.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
) -> None:
    """Cross-run summary from runs/index.jsonl."""
    rows = read_index(runs_dir)
    if last is not None:
        rows = rows[-last:]
    rep = build_report(rows)
    if as_json:
        typer.echo(json.dumps(rep, indent=2))
        return
    typer.echo(f"runs: {rep['n_runs']}")
    typer.echo("terminal states: " + (", ".join(f"{k}={v}" for k, v in rep["terminal_states"].items()) or "none"))
    for label, key in (("ERROR rules", "error_rules"), ("WARN rules", "warn_rules"), ("judge fail items", "judge_fail_items")):
        typer.echo(f"{label}: " + (", ".join(f"{k}x{v}" for k, v in rep[key]) or "none"))
    typer.echo(f"zero-hit queries: {rep['zero_hit_queries']}")
    typer.echo(f"fetch failures: {rep['fetch_failures']}")
    typer.echo(f"unmatched actors: {rep['unmatched_actors']}")
    typer.echo("by prompt_sha256:")
    for sha, g in rep["by_prompt_sha256"].items():
        typer.echo(f"  {sha}: {g['runs']} runs, {g['minted']} minted")
    for r in rows:
        typer.echo(f"  - {r.run_id}  {r.software_name}  {r.terminal_state}")


if __name__ == "__main__":
    app()
