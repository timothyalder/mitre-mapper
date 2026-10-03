"""Pinned ATT&CK releases: status, update (with ``diff_stix`` changelog) and the manifest.

``datasets/MANIFEST.json`` pins one ATT&CK release (STIX 2.0, from ``mitre/cti`` at tag
``ATT&CK-v<version>``; see docs/adr/0001). The list of releases comes from
``attack-stix-data/index.json``. An update downloads into a staging dir, verifies it, runs
``diff_stix`` old -> new, swaps the files, rewrites the manifest, then runs ``delta.doctor_all``.
Nothing here touches the network unless a caller passes (or lets us build) an httpx client.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from . import delta as delta_mod

DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
RELEASE_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
_TAG_URL = "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json"
# index.json collection names -> domain
_COLLECTION_DOMAIN = {
    "Enterprise ATT&CK": "enterprise-attack",
    "Mobile ATT&CK": "mobile-attack",
    "ICS ATT&CK": "ics-attack",
}
_MIN_KEEP = 0.5  # a new bundle with fewer than half the old objects is rejected


class DatasetError(RuntimeError):
    """An update could not be completed; the datasets directory is left as it was."""


def version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version.lstrip("v").split("."))
    except ValueError as exc:
        raise DatasetError(f"not a release version: {version!r}") from exc


def _is_release(version: str) -> bool:
    """Stable releases only: upstream also lists ``11.2-beta`` style entries."""
    return all(p.isdigit() for p in version.split("."))


def tag_url(domain: str, version: str) -> str:
    return _TAG_URL.format(version=version, domain=domain)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def read_manifest(datasets_dir: Path) -> dict[str, Any]:
    return json.loads((Path(datasets_dir) / "MANIFEST.json").read_text(encoding="utf-8"))


def _write_json_atomic(path: Path, data: Any) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------- releases


def release_index(client: httpx.Client) -> dict[str, list[str]]:
    """``{domain: [version, ...]}`` newest first, from upstream ``index.json``."""
    resp = client.get(RELEASE_INDEX_URL)
    resp.raise_for_status()
    out: dict[str, list[str]] = {}
    for coll in resp.json()["collections"]:
        domain = _COLLECTION_DOMAIN.get(coll["name"])
        if domain:
            out[domain] = sorted({v["version"] for v in coll["versions"] if _is_release(v["version"])}, key=version_key, reverse=True)
    return out


def latest_release(index: dict[str, list[str]], domains: Iterable[str]) -> str:
    """Newest version published for *every* requested domain."""
    sets = [set(index.get(d, [])) for d in domains]
    common = set.intersection(*sets) if sets else set()
    if not common:
        raise DatasetError(f"no release is published for all of {list(domains)}")
    return max(common, key=version_key)


# --------------------------------------------------------------------------- status


@dataclass
class DomainStatus:
    domain: str
    release: str | None
    file_exists: bool
    sha256_ok: bool
    n_objects_ok: bool
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def status(datasets_dir: Path) -> list[DomainStatus]:
    """Compare each manifest domain with the file on disk (existence, sha256, object count)."""
    datasets_dir = Path(datasets_dir)
    manifest = read_manifest(datasets_dir)
    out: list[DomainStatus] = []
    for domain, entry in manifest["domains"].items():
        path = datasets_dir / f"{domain}.json"
        st = DomainStatus(domain, entry.get("attack_release"), path.is_file(), False, False)
        if not st.file_exists:
            st.problems.append(f"{path.name} is missing")
        else:
            st.sha256_ok = sha256_file(path) == entry["sha256"]
            if not st.sha256_ok:
                st.problems.append("sha256 differs from MANIFEST")
            n = len(json.loads(path.read_text(encoding="utf-8"))["objects"])
            st.n_objects_ok = n == entry["n_objects"]
            if not st.n_objects_ok:
                st.problems.append(f"{n} objects on disk, MANIFEST says {entry['n_objects']}")
        out.append(st)
    return out


# --------------------------------------------------------------------------- update


@dataclass
class UpdateResult:
    from_release: str | None
    to_release: str
    noop: bool = False
    updated_domains: list[str] = field(default_factory=list)
    changelog: dict[str, Path] = field(default_factory=dict)  # "json"/"md" -> path
    doctor: list[delta_mod.DoctorReport] = field(default_factory=list)

    @property
    def doctor_ok(self) -> bool:
        return all(r.ok for r in self.doctor)


def _verify_bundle(domain: str, path: Path, old_n: int | None) -> int:
    """Parse the downloaded bundle and sanity-check it; returns the object count."""
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise DatasetError(f"{domain}: download is not JSON ({exc})") from exc
    objs = bundle.get("objects") if isinstance(bundle, dict) else None
    if bundle.get("type") != "bundle" or not objs:
        raise DatasetError(f"{domain}: download is not a STIX bundle with objects")
    if bundle.get("spec_version") == "2.1" or any(o.get("spec_version") == "2.1" for o in objs[:200]):
        raise DatasetError(f"{domain}: STIX 2.1 content; this tool pins STIX 2.0 (docs/adr/0001)")
    if not any(o.get("type") == "attack-pattern" for o in objs):
        raise DatasetError(f"{domain}: bundle has no attack-pattern objects")
    if old_n and len(objs) < old_n * _MIN_KEEP:
        raise DatasetError(f"{domain}: {len(objs)} objects vs {old_n} before; refusing")
    return len(objs)


def run_diff_stix(
    old_dir: Path, new_dir: Path, domains: list[str], json_file: Path, markdown_file: Path
) -> None:
    """``diff_stix`` (mitreattack-python 6.2.1 ``get_new_changelog_md``) in-process.

    ``layers=None`` is essential: the library default writes three layer files to the cwd.
    """
    from mitreattack.diffStix.changelog_helper import get_new_changelog_md

    json_file.parent.mkdir(parents=True, exist_ok=True)
    get_new_changelog_md(
        domains=domains,
        layers=None,
        old=str(old_dir),
        new=str(new_dir),
        include_contributors=False,
        markdown_file=str(markdown_file),
        json_file=str(json_file),
    )


def update(
    datasets_dir: Path,
    to: str | None = None,
    *,
    client: httpx.Client | None = None,
    run_diff: bool = True,
    force: bool = False,
    domains: list[str] | None = None,
    runs_dir: Path | None = None,
    changelog_dir: Path | None = None,
) -> UpdateResult:
    """Move the pinned datasets to release ``to`` (default: newest upstream).

    A same-version update is a no-op unless ``force``. ``domains`` restricts the update to a
    subset of the manifest's domains (used by tests); the default is all of them.
    """
    datasets_dir = Path(datasets_dir)
    runs_dir = Path(runs_dir) if runs_dir is not None else datasets_dir.parent / "runs"
    changelog_dir = Path(changelog_dir) if changelog_dir is not None else datasets_dir / "changelogs"
    manifest = read_manifest(datasets_dir)
    chosen = list(domains) if domains else list(manifest["domains"])
    unknown = [d for d in chosen if d not in manifest["domains"]]
    if unknown:
        raise DatasetError(f"not in MANIFEST: {unknown}")
    old_release = manifest["attack_release"]

    own_client = client is None
    http = client or httpx.Client(follow_redirects=True, timeout=120.0)
    try:
        target = (to or latest_release(release_index(http), chosen)).lstrip("v")
        version_key(target)  # reject junk before touching anything
        if target == old_release and not force:
            return UpdateResult(old_release, target, noop=True)

        staging = Path(tempfile.mkdtemp(dir=datasets_dir, prefix=".update-"))
        try:
            counts: dict[str, int] = {}
            for domain in chosen:
                dest = staging / f"{domain}.json"
                url = tag_url(domain, target)
                with http.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        raise DatasetError(f"{domain}: GET {url} returned {resp.status_code}")
                    with open(dest, "wb") as fh:
                        for chunk in resp.iter_bytes():
                            fh.write(chunk)
                counts[domain] = _verify_bundle(domain, dest, manifest["domains"][domain].get("n_objects"))

            result = UpdateResult(old_release, target, updated_domains=chosen)
            have_old = all((datasets_dir / f"{d}.json").is_file() for d in chosen)
            if run_diff and have_old:
                stem = f"{old_release}→{target}"
                paths = {"json": changelog_dir / f"{stem}.json", "md": changelog_dir / f"{stem}.md"}
                run_diff_stix(datasets_dir, staging, chosen, paths["json"], paths["md"])
                result.changelog = paths

            _swap(datasets_dir, staging, chosen)
            for domain in chosen:
                manifest["domains"][domain] = {
                    **manifest["domains"][domain],
                    "attack_release": target,
                    "source_url": tag_url(domain, target),
                    "sha256": sha256_file(datasets_dir / f"{domain}.json"),
                    "spec_version": "2.0",
                    "fetched_at": _now(),
                    "n_objects": counts[domain],
                }
            if set(chosen) == set(manifest["domains"]):
                manifest["attack_release"] = target
            _write_json_atomic(datasets_dir / "MANIFEST.json", manifest)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    finally:
        if own_client:
            http.close()

    result.doctor = delta_mod.doctor_all(runs_dir, datasets_dir)
    return result


def _swap(datasets_dir: Path, staging: Path, domains: list[str]) -> None:
    """Replace each bundle atomically; on failure restore the ones already replaced."""
    backups: dict[str, Path] = {}
    try:
        for domain in domains:
            target = datasets_dir / f"{domain}.json"
            if target.exists():
                backups[domain] = staging / f"{domain}.json.bak"
                shutil.copy2(target, backups[domain])
            os.replace(staging / f"{domain}.json", target)
    except BaseException:
        for domain, bak in backups.items():
            shutil.copy2(bak, datasets_dir / f"{domain}.json")
        raise
