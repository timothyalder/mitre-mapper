"""typer CLI: ``map``, ``judge`` (replay) and a minimal ``report``.

No LangChain imports at module level: ``map`` imports :mod:`mitre_mapper.run` lazily so
``report`` stays instant and acceptance criterion 13 holds.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

import typer

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


@app.command("report")
def report_cmd(
    last: Annotated[int | None, typer.Option("--last", help="Only the last N runs.")] = None,
    since: Annotated[
        str | None, typer.Option("--since", help="ISO date (YYYY-MM-DD) or a run_id (inclusive).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON (schema: report.py docstring).")] = False,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
) -> None:
    """Cross-run summary from runs/index.jsonl + events: what is the tool tripping on?"""
    from mitre_mapper.report import ReportError, build_report, events_loader_for, render_text

    try:
        rep = build_report(
            read_index(runs_dir), events_loader_for(runs_dir), last=last, since=since
        )
    except ReportError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(json.dumps(rep, indent=2) if as_json else render_text(rep))


@app.command("review")
def review_cmd(
    run_id: Annotated[str, typer.Argument(help="Run id under --runs-dir.")],
    file: Annotated[
        Path | None, typer.Option("--file", help="Non-interactive: a review JSON (models.Review).")
    ] = None,
    reviewer: Annotated[str | None, typer.Option(help="Reviewer name.")] = None,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
) -> None:
    """Record your verdict on a run: accept/reject each mapped item, list misses, add notes."""
    from mitre_mapper import review as rv
    from mitre_mapper.models import Review

    run_dir = Path(runs_dir) / run_id
    try:
        if file is not None:
            rev = rv.load_review_file(file, run_id)
            if reviewer and not rev.reviewer:
                rev = rev.model_copy(update={"reviewer": reviewer})
        else:
            if not (run_dir / "events.jsonl").is_file():
                raise rv.ReviewError(f"no such run: {run_dir}")
            mapping = rv.load_mapping(run_dir)
            if not mapping.has_mint:
                typer.echo("note: this run has no mint event; every item you list is recorded as missed")
            techniques: dict[str, Any] = {}
            groups: dict[str, Any] = {}
            for kind, items, into in (
                ("technique", mapping.techniques, techniques),
                ("group", mapping.groups, groups),
            ):
                for it in items:
                    tag = " (user-asserted)" if it.user_asserted else ""
                    ok = typer.confirm(f"Accept {kind} {it.id} {it.name}{tag}?", default=True)
                    into[it.id] = "accepted" if ok else "rejected"
            missed_t = typer.prompt("Missed technique ids (comma-separated)", default="", show_default=False)
            missed_g = typer.prompt("Missed group ids (comma-separated)", default="", show_default=False)
            notes = typer.prompt("Notes", default="", show_default=False)
            split = lambda text: [x.strip() for x in text.split(",") if x.strip()]  # noqa: E731
            rev = Review(
                run_id=run_id,
                ts=rv._now_ts(),
                reviewer=reviewer,
                techniques=techniques,
                groups=groups,
                missed_techniques=split(missed_t),
                missed_groups=split(missed_g),
                notes=notes,
            )
        summary = rv.record_review(runs_dir, run_id, rev)
    except rv.ReviewError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"wrote {run_dir / 'review.json'} and appended a review record to {runs_dir / 'index.jsonl'}")
    typer.echo(f"precision: {summary['precision']}  recall: {summary['recall']}")


runs_app = typer.Typer(no_args_is_help=True, help="Manage run folders.")
app.add_typer(runs_app, name="runs")


@runs_app.command("archive")
def runs_archive_cmd(
    older_than: Annotated[float, typer.Option("--older-than", help="Days; archive finished runs older than this.")] = 30,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    out: Annotated[Path | None, typer.Option("--out", help="Archive dir (default <runs-dir>/archive).")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="List what would be archived.")] = False,
) -> None:
    """tar.gz old run folders (run.md/review.json/delta.json stay in place); verifies before deleting."""
    from mitre_mapper.archive import ArchiveError, archive_runs

    try:
        res = archive_runs(runs_dir, older_than_days=older_than, out_dir=out, dry_run=dry_run)
    except ArchiveError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    if not res.run_ids:
        typer.echo("nothing to archive")
        return
    verb = "would archive" if dry_run else "archived"
    typer.echo(f"{verb} {len(res.run_ids)} run(s), {res.n_files} files, {res.bytes_freed} bytes")
    for rid in res.run_ids:
        typer.echo(f"  {rid}")
    if res.archive:
        typer.echo(f"archive: {res.archive}")


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


# --------------------------------------------------------------------------- eval (PLAN section 4)

eval_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="Score the mapper on the eval cases (offline: frozen evidence, held-out store). "
    "`eval freeze` is the only networked step.",
)
app.add_typer(eval_app, name="eval")


@eval_app.callback()
def eval_cmd(
    ctx: typer.Context,
    case: Annotated[list[str] | None, typer.Option("--case", help="Case name (repeatable); default all.")] = None,
    model: Annotated[str | None, typer.Option(help="Mapper model (env MITRE_MAPPER_MODEL).")] = None,
    judge_model: Annotated[
        str | None, typer.Option(help="Judge model: also scores unjustified additions (env MITRE_MAPPER_JUDGE_MODEL).")
    ] = None,
    include_reviews: Annotated[
        bool, typer.Option("--include-reviews", help="Also score reviewed runs (review.json) as extra cases.")
    ] = False,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs"),
    datasets_dir: Annotated[Path, typer.Option()] = Path("datasets"),
    max_attempts: Annotated[int, typer.Option()] = 3,
    max_model_calls: Annotated[int, typer.Option()] = 60,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the scores as JSON.")] = False,
) -> None:
    """Run the eval cases with NO network and print recall, additions, group recall and baselines."""
    if ctx.invoked_subcommand is not None:
        return
    from mitre_mapper import evaluate

    cfg = Config()
    chosen = model or cfg.model
    if not chosen:
        typer.echo("error: pass --model or set MITRE_MAPPER_MODEL", err=True)
        raise typer.Exit(2)
    judge = judge_model or cfg.judge_model
    try:
        cases = evaluate.load_cases(case or None)
        for c in cases:  # preflight: fail before spending a single model call
            evaluate.verify_lock(c)
    except evaluate.EvalError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    for c in cases:
        warning = evaluate.draft_warning(c)
        if warning:
            typer.echo("*" * 78, err=True)
            typer.echo(warning, err=True)
            typer.echo("*" * 78, err=True)
    from mitre_mapper.run import map_software  # lazy: pulls in langchain

    scoring = evaluate.load_score_module()
    support_judge = scoring.build_support_judge(judge) if judge else None
    model_only = scoring.build_model_only(chosen)
    results = []
    for c in cases:
        res = evaluate.run_case(
            c, model=chosen, judge_model=judge, runs_dir=runs_dir, datasets_dir=datasets_dir,
            mapper=map_software, support_judge=support_judge, model_only=model_only,
            max_attempts=max_attempts, max_model_calls=max_model_calls,
        )
        results.append(res)
        if not as_json:
            typer.echo(evaluate.render_case(res))
    extra = evaluate.score_reviews(runs_dir, datasets_dir) if include_reviews else []
    if as_json:
        typer.echo(json.dumps({r.name: r.scores for r in [*results, *extra]}, indent=2))
    else:
        for r in extra:
            typer.echo(evaluate.render_case(r))
        gaps = evaluate.render_gaps(evaluate.rich_vs_thin(results))
        if gaps:
            typer.echo(gaps)
    if any(r.scores is None for r in results):
        raise typer.Exit(1)


@eval_app.command("freeze")
def eval_freeze_cmd(
    case: Annotated[list[str] | None, typer.Option("--case", help="Case name (repeatable); default all.")] = None,
    update: Annotated[bool, typer.Option("--update", help="Accept changed content (hash drift).")] = False,
    timeout: Annotated[float, typer.Option(help="Per-reference fetch timeout (s).")] = 30.0,
) -> None:
    """Fetch every case's references (NETWORK) into evals/fixtures/<case>/evidence and write the lock."""
    from mitre_mapper import evaluate

    try:
        cases = evaluate.load_cases(case or None)
    except evaluate.EvalError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    failed = False
    for c in cases:
        try:
            res = evaluate.freeze_case(c, update=update, timeout=timeout)
        except evaluate.EvalError as exc:
            typer.echo(f"error: {exc}", err=True)
            failed = True
            continue
        typer.echo(f"{c.case_name}: {len(res.entries)} reference(s)")
        for e in res.entries:
            status = f"ok {e['chars']} chars, {e['license']}" if e["ok"] else f"FAILED ({e['error']})"
            typer.echo(f"  {e['source_name']}: {status}")
        for w in res.warnings:
            typer.echo(f"  warning: {w}", err=True)
        if res.drift:
            failed = True
            typer.echo("  HASH DRIFT; nothing written (use --update to accept):", err=True)
            for d in res.drift:
                typer.echo(f"    {d}", err=True)
        elif res.written:
            typer.echo(f"  wrote {c.lock_path}")
    if failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
