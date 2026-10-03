"""typer CLI: ``map``, ``judge`` (replay) and a minimal ``report``.

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
    fetch: bool = True
    fetch_timeout: float = 20.0
    evidence_dir: Path | None = None  # frozen mode: read evidence only from here
    use_cache: bool = True
    cache_dir: Path | None = None  # default: <repo>/.cache/fetch


@app.command("map")
def map_cmd(
    intake: Annotated[Path, typer.Argument(help="Intake markdown file.")],
    model: Annotated[str | None, typer.Option(help="Model string (env MITRE_MAPPER_MODEL).")] = None,
    judge_model: Annotated[str | None, typer.Option(help="Judge model (env MITRE_MAPPER_JUDGE_MODEL).")] = None,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
    max_attempts: Annotated[int, typer.Option()] = 3,
    max_model_calls: Annotated[int, typer.Option()] = 60,
    no_fetch: Annotated[bool, typer.Option("--no-fetch", help="Do not fetch references.")] = False,
    evidence_dir: Annotated[
        Path | None,
        typer.Option(help="Frozen evidence dir (<slug(source_name)>.txt); never touches the network."),
    ] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Ignore the fetch cache.")] = False,
    fetch_timeout: Annotated[float, typer.Option(help="Per-reference fetch timeout (s).")] = 20.0,
    cache_dir: Annotated[Path | None, typer.Option(help="Fetch cache dir.")] = None,
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
        fetch=cfg.fetch and not no_fetch,
        evidence_dir=evidence_dir or cfg.evidence_dir,
        use_cache=cfg.use_cache and not no_cache,
        fetch_timeout=fetch_timeout,
        cache_dir=cache_dir or cfg.cache_dir,
    )
    typer.echo(f"run_id: {record.run_id}")
    typer.echo(f"terminal_state: {record.terminal_state}")
    typer.echo(f"run.md: {Path(runs_dir) / record.run_id / 'run.md'}")
    if record.terminal_state not in ("minted", "declined"):
        raise typer.Exit(1)


@app.command("judge")
def judge_cmd(
    run: Annotated[str, typer.Option("--run", help="Run id under --runs-dir.")],
    domain: Annotated[str, typer.Option(help="Domain, e.g. mobile-attack.")],
    attempt: Annotated[int, typer.Option(help="Attempt number (proposal_<n>.json).")],
    model: Annotated[str | None, typer.Option(help="Judge model (env MITRE_MAPPER_JUDGE_MODEL).")] = None,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    evidence_dir: Annotated[Path | None, typer.Option(help="Override <run>/evidence.")] = None,
) -> None:
    """Re-run the judge on a recorded proposal; prints per-item results."""
    chosen = model or Config().judge_model
    if not chosen:
        typer.echo("error: pass --model or set MITRE_MAPPER_JUDGE_MODEL", err=True)
        raise typer.Exit(2)
    run_dir = Path(runs_dir) / run
    if not (run_dir / domain / f"proposal_{attempt}.json").is_file():
        typer.echo(f"error: {run_dir / domain / f'proposal_{attempt}.json'} not found", err=True)
        raise typer.Exit(2)
    from mitre_mapper.judge import JudgeOutputError, replay_judge  # lazy: pulls in langchain
    from mitre_mapper.runlog import ProviderError

    try:
        res = replay_judge(run_dir, domain, attempt, chosen, evidence_dir=evidence_dir)
    except (JudgeOutputError, ProviderError) as exc:
        typer.echo(f"judge failed: {getattr(exc, 'message', None) or exc}", err=True)
        raise typer.Exit(1) from exc
    v = res.verdict
    typer.echo(f"approved: {v.approved}")
    for item in v.items:
        typer.echo(f"  [{'PASS' if item.passed else 'FAIL'}] {item.name}: {item.rationale}")
    typer.echo(f"tokens in/out: {res.tokens_in}/{res.tokens_out}; latency: {res.latency_s:.2f}s")
    typer.echo(f"prompt_sha256: {res.prompt_sha256}")


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


datasets_app = typer.Typer(no_args_is_help=True, help="Pinned ATT&CK datasets.")
delta_app = typer.Typer(no_args_is_help=True, help="Inspect deltas.")
app.add_typer(datasets_app, name="datasets")
app.add_typer(delta_app, name="delta")


@datasets_app.command("status")
def datasets_status_cmd(
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
) -> None:
    """Manifest vs files on disk (existence, sha256, object count)."""
    from mitre_mapper import datasets

    bad = False
    release = datasets.read_manifest(datasets_dir)["attack_release"]
    typer.echo(f"pinned ATT&CK release: {release}")
    for st in datasets.status(datasets_dir):
        typer.echo(f"  {st.domain}: {st.release} {'ok' if st.ok else 'PROBLEM: ' + '; '.join(st.problems)}")
        bad |= not st.ok
    if bad:
        raise typer.Exit(1)


@datasets_app.command("update")
def datasets_update_cmd(
    to: Annotated[str | None, typer.Option("--to", help="Target release (default: newest upstream).")] = None,
    force: Annotated[bool, typer.Option("--force", help="Re-download even if already on that release.")] = False,
    no_diff: Annotated[bool, typer.Option("--no-diff", help="Skip diff_stix (slow: ~40 s for enterprise).")] = False,
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
) -> None:
    """Download a release, write a diff_stix changelog, swap files, update MANIFEST, run delta doctor."""
    from mitre_mapper import datasets

    try:
        res = datasets.update(datasets_dir, to, run_diff=not no_diff, force=force, runs_dir=runs_dir)
    except datasets.DatasetError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    if res.noop:
        typer.echo(f"already on {res.to_release}; nothing to do (use --force to re-download)")
        return
    typer.echo(f"updated {res.from_release} -> {res.to_release}: {', '.join(res.updated_domains)}")
    for kind, path in res.changelog.items():
        typer.echo(f"changelog {kind}: {path}")
    typer.echo(f"delta doctor: {len(res.doctor)} delta(s), {'clean' if res.doctor_ok else 'PROBLEMS'}")
    for rep in res.doctor:
        for f in rep.findings:
            typer.echo(f"  {rep.run_id} {f.code} {f.severity}: {f.message}")
    if not res.doctor_ok:
        raise typer.Exit(1)


@app.command("materialize")
def materialize_cmd(
    run_ids: Annotated[list[str], typer.Argument(help="Run ids whose delta.json to combine.")],
    domain: Annotated[list[str] | None, typer.Option("--domain", help="Only this domain (repeatable).")] = None,
    out: Annotated[Path, typer.Option("--out", help="Output dir for patched bundles.")] = Path(".cache/materialized"),
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
) -> None:
    """Combine deltas into patched bundles and verify them through MitreAttackData."""
    from mitre_mapper import delta

    try:
        written = delta.materialize(
            [Path(runs_dir) / r for r in run_ids], domains=domain, out_dir=out, datasets_dir=datasets_dir
        )
    except delta.DeltaError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    for dom, path in written.items():
        typer.echo(f"{dom}: {path}")


@delta_app.command("doctor")
def delta_doctor_cmd(
    run_id: Annotated[str | None, typer.Argument(help="Run id (omit with --all).")] = None,
    all_runs: Annotated[bool, typer.Option("--all", help="Every runs/*/delta.json.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
) -> None:
    """Check deltas against the current datasets, allocations and upstream software/groups."""
    from mitre_mapper import delta

    if bool(run_id) == all_runs:
        typer.echo("error: give exactly one of RUN_ID or --all", err=True)
        raise typer.Exit(2)
    try:
        reports = (
            delta.doctor_all(runs_dir, datasets_dir)
            if all_runs
            else [delta.doctor(Path(runs_dir) / str(run_id), datasets_dir)]
        )
    except delta.DeltaError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    if as_json:
        typer.echo(json.dumps([r.model_dump() for r in reports], indent=2))
    else:
        typer.echo(f"{len(reports)} delta(s) checked")
        for rep in reports:
            typer.echo(f"{rep.run_id}: {'ok' if rep.ok else 'PROBLEMS'}{' (retire recommended)' if rep.retire else ''}")
            for f in rep.findings:
                typer.echo(f"  {f.code} {f.severity}: {f.message}")
    if not all(r.ok for r in reports):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
