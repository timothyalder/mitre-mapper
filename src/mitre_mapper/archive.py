"""``runs archive``: tar.gz finished run folders older than N days, then free the space.

Safety: the archive is written to a temp name, re-opened and every member's size checked
against the source file, then renamed; only then are the archived files deleted. Files that
are committed or needed later stay in place and are *not* archived: ``run.md``,
``review.json``, ``delta.json`` (``materialize`` / ``delta doctor`` read it). Runs without a
``run_end`` event (still live) are never touched. ``runs/index.jsonl`` is never touched.
"""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

__all__ = ["KEEP_IN_PLACE", "ArchiveError", "ArchiveResult", "archive_runs"]

KEEP_IN_PLACE = frozenset({"run.md", "review.json", "delta.json"})


class ArchiveError(Exception):
    """Archive could not be written or verified (nothing was deleted)."""


@dataclass
class ArchiveResult:
    archive: Path | None = None
    run_ids: list[str] = field(default_factory=list)
    n_files: int = 0
    bytes_freed: int = 0
    dry_run: bool = False


def _run_time(run_dir: Path) -> datetime:
    try:
        return datetime.strptime(run_dir.name[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return datetime.fromtimestamp((run_dir / "events.jsonl").stat().st_mtime, UTC)


def _finished(run_dir: Path) -> bool:
    try:
        with (run_dir / "events.jsonl").open(encoding="utf-8") as fh:
            return any('"run_end"' in line and json.loads(line).get("event") == "run_end" for line in fh)
    except (OSError, ValueError):
        return False


def archive_runs(
    runs_dir: Path | str,
    *,
    older_than_days: float = 30,
    out_dir: Path | str | None = None,
    now: datetime | None = None,
    dry_run: bool = False,
) -> ArchiveResult:
    """Archive finished runs older than ``older_than_days`` into one ``.tar.gz``."""
    runs = Path(runs_dir)
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=older_than_days)
    out = Path(out_dir) if out_dir else runs / "archive"
    selected: list[tuple[Path, list[Path]]] = []
    for d in sorted(p for p in runs.iterdir() if p.is_dir()) if runs.is_dir() else []:
        if not (d / "events.jsonl").is_file() or not _finished(d) or _run_time(d) > cutoff:
            continue
        files = [
            f for f in sorted(d.rglob("*")) if f.is_file() and f.relative_to(d).as_posix() not in KEEP_IN_PLACE
        ]
        if files:
            selected.append((d, files))
    res = ArchiveResult(
        run_ids=[d.name for d, _ in selected],
        n_files=sum(len(f) for _, f in selected),
        bytes_freed=sum(f.stat().st_size for _, fs in selected for f in fs),
        dry_run=dry_run,
    )
    if dry_run or not selected:
        return res
    out.mkdir(parents=True, exist_ok=True)
    final = out / f"runs-{now.strftime('%Y%m%dT%H%M%SZ')}.tar.gz"
    n = 0
    while final.exists():
        n += 1
        final = out / f"runs-{now.strftime('%Y%m%dT%H%M%SZ')}-{n}.tar.gz"
    tmp = final.with_name(final.name + ".tmp")
    try:
        with tarfile.open(tmp, "w:gz") as tar:
            for d, files in selected:
                for f in files:
                    tar.add(f, arcname=f"{d.name}/{f.relative_to(d).as_posix()}", recursive=False)
        expected = {f"{d.name}/{f.relative_to(d).as_posix()}": f.stat().st_size for d, fs in selected for f in fs}
        with tarfile.open(tmp, "r:gz") as tar:
            got = {m.name: m.size for m in tar.getmembers() if m.isfile()}
        if got != expected:
            raise ArchiveError("archive verification failed: members differ from sources")
        tmp.replace(final)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    for d, files in selected:
        for f in files:
            f.unlink()
        for sub in sorted((p for p in d.rglob("*") if p.is_dir()), reverse=True):
            try:
                sub.rmdir()
            except OSError:
                pass
    res.archive = final
    return res
