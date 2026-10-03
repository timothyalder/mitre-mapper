"""datasets status/update (Wave 4A). Mocked transport serves the local files; no network."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import httpx
import pytest

from mitre_mapper import datasets
from mitre_mapper.datasets import DatasetError, latest_release, release_index, tag_url, update, version_key

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
INDEX = {
    "collections": [
        {"name": "Enterprise ATT&CK", "versions": [{"version": v} for v in ("19.2", "19.10", "18.1")]},
        {"name": "Mobile ATT&CK", "versions": [{"version": v} for v in ("19.2", "19.10", "18.1", "11.2-beta")]},
        {"name": "ICS ATT&CK", "versions": [{"version": v} for v in ("19.1", "18.1")]},
        {"name": "Pre-ATT&CK", "versions": [{"version": "1.0"}]},
    ]
}


def make_client(serve: dict[str, Path | bytes], seen: list[str] | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if seen is not None:
            seen.append(url)
        if url == datasets.RELEASE_INDEX_URL:
            return httpx.Response(200, json=INDEX)
        body = serve.get(url)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body.read_bytes() if isinstance(body, Path) else body)

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


@pytest.fixture
def mobile_ds(tmp_path) -> Path:
    """tmp datasets dir: copied mobile bundle + MANIFEST pretending mobile is on 19.1."""
    d = tmp_path / "datasets"
    d.mkdir()
    shutil.copy(DATASETS / "mobile-attack.json", d / "mobile-attack.json")
    manifest = json.loads((DATASETS / "MANIFEST.json").read_text())
    manifest["attack_release"] = "19.1"
    manifest["domains"]["mobile-attack"]["attack_release"] = "19.1"
    (d / "MANIFEST.json").write_text(json.dumps(manifest))
    (d / "allocations.json").write_text('{"schema_version": 1, "software": {}, "groups": {}}')
    return d


def test_version_ordering_is_numeric():
    assert sorted(["19.2", "19.10", "9.0"], key=version_key) == ["9.0", "19.2", "19.10"]


def test_release_index_and_latest_common_release():
    idx = release_index(make_client({}))
    assert idx["mobile-attack"][0] == "19.10" and "pre-attack" not in idx
    assert "11.2-beta" not in idx["mobile-attack"]
    assert latest_release(idx, ["mobile-attack", "enterprise-attack"]) == "19.10"
    assert latest_release(idx, list(datasets.DOMAINS)) == "18.1"  # ICS lags
    with pytest.raises(DatasetError):
        latest_release(idx, ["pre-attack"])


def test_tag_url_matches_manifest_pin():
    manifest = json.loads((DATASETS / "MANIFEST.json").read_text())
    for domain, entry in manifest["domains"].items():
        assert tag_url(domain, entry["attack_release"]) == entry["source_url"]


def test_status_of_the_real_datasets_is_clean():
    assert all(s.ok for s in datasets.status(DATASETS))


def test_status_reports_missing_and_tampered(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    shutil.copy(DATASETS / "MANIFEST.json", d / "MANIFEST.json")
    (d / "mobile-attack.json").write_text('{"objects": []}')
    by = {s.domain: s for s in datasets.status(d)}
    assert by["enterprise-attack"].problems == ["enterprise-attack.json is missing"]
    assert not by["mobile-attack"].sha256_ok and not by["mobile-attack"].n_objects_ok


def test_same_version_update_is_a_noop_unless_forced(tmp_path):
    d = tmp_path / "datasets"
    d.mkdir()
    shutil.copy(DATASETS / "MANIFEST.json", d / "MANIFEST.json")
    seen: list[str] = []
    res = update(d, "19.2", client=make_client({}, seen))
    assert res.noop and seen == []
    res = update(d, "v19.2", client=make_client({}, seen))  # leading v tolerated
    assert res.noop


def test_update_writes_changelog_swaps_and_updates_manifest(mobile_ds, tmp_path):
    before = (mobile_ds / "mobile-attack.json").read_bytes()
    url = tag_url("mobile-attack", "19.2")
    seen: list[str] = []
    res = update(
        mobile_ds,
        "19.2",
        client=make_client({url: DATASETS / "mobile-attack.json"}, seen),
        domains=["mobile-attack"],
        runs_dir=tmp_path / "runs",
    )
    assert seen == [url] and not res.noop
    assert (res.from_release, res.to_release) == ("19.1", "19.2")
    assert res.changelog["json"].name == "19.1→19.2.json" and res.changelog["json"].is_file()
    assert res.changelog["md"].is_file() and res.changelog["json"].parent == mobile_ds / "changelogs"
    assert json.loads(res.changelog["json"].read_text())  # parses
    assert (mobile_ds / "mobile-attack.json").read_bytes() == before  # identical content swapped in
    m = json.loads((mobile_ds / "MANIFEST.json").read_text())
    entry = m["domains"]["mobile-attack"]
    assert entry["attack_release"] == "19.2" and entry["source_url"] == url
    assert entry["sha256"] == datasets.sha256_file(DATASETS / "mobile-attack.json")
    assert entry["n_objects"] == 2634 and entry["fetched_at"].endswith("Z")
    assert m["attack_release"] == "19.1"  # partial update keeps the pin of the other domains
    assert res.doctor == [] and res.doctor_ok
    assert not [p for p in mobile_ds.iterdir() if p.name.startswith(".update-")]


def test_force_same_version_redownloads(mobile_ds, tmp_path):
    m = json.loads((mobile_ds / "MANIFEST.json").read_text())
    m["attack_release"] = "19.2"
    (mobile_ds / "MANIFEST.json").write_text(json.dumps(m))
    url = tag_url("mobile-attack", "19.2")
    res = update(
        mobile_ds, "19.2", client=make_client({url: DATASETS / "mobile-attack.json"}),
        domains=["mobile-attack"], force=True, run_diff=False, runs_dir=tmp_path / "runs",
    )
    assert not res.noop and res.changelog == {}


@pytest.mark.parametrize(
    "body, message",
    [
        (None, "404"),
        (b"not json", "not JSON"),
        (b'{"type": "bundle", "objects": []}', "not a STIX bundle"),
        (b'{"type": "bundle", "spec_version": "2.1", "objects": [{"type": "x"}]}', "STIX 2.1"),
        (b'{"type": "bundle", "objects": [{"type": "malware"}]}', "no attack-pattern"),
    ],
)
def test_bad_download_is_rejected_and_datasets_untouched(mobile_ds, tmp_path, body, message):
    before = (mobile_ds / "mobile-attack.json").read_bytes()
    manifest = (mobile_ds / "MANIFEST.json").read_bytes()
    serve = {} if body is None else {tag_url("mobile-attack", "19.2"): body}
    with pytest.raises(DatasetError, match=message):
        update(mobile_ds, "19.2", client=make_client(serve), domains=["mobile-attack"], runs_dir=tmp_path / "r")
    assert (mobile_ds / "mobile-attack.json").read_bytes() == before
    assert (mobile_ds / "MANIFEST.json").read_bytes() == manifest
    assert not [p for p in mobile_ds.iterdir() if p.name.startswith(".update-")]


def test_shrunken_bundle_is_rejected(mobile_ds, tmp_path):
    full = json.loads((DATASETS / "mobile-attack.json").read_text())
    full["objects"] = full["objects"][:100] + [o for o in full["objects"] if o["type"] == "attack-pattern"][:1]
    with pytest.raises(DatasetError, match="refusing"):
        update(
            mobile_ds, "19.2", client=make_client({tag_url("mobile-attack", "19.2"): json.dumps(full).encode()}),
            domains=["mobile-attack"], runs_dir=tmp_path / "r",
        )


def test_swap_failure_restores_files(mobile_ds, monkeypatch):
    staging = mobile_ds / ".update-x"
    staging.mkdir()
    (staging / "mobile-attack.json").write_text("new")
    before = (mobile_ds / "mobile-attack.json").read_bytes()
    real = datasets.os.replace

    def boom(src, dst):
        real(src, dst)
        raise OSError("disk")

    monkeypatch.setattr(datasets.os, "replace", boom)
    with pytest.raises(OSError):
        datasets._swap(mobile_ds, staging, ["mobile-attack"])
    assert (mobile_ds / "mobile-attack.json").read_bytes() == before
