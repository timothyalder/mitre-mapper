"""Reference fetching: URL or file -> plain-text evidence. Never raises (PLAN D7).

Failures come back as ``FetchResult(ok=False, error=...)``. Frozen mode
(``evidence_dir``) reads only ``<evidence_dir>/<slug(source_name)>.txt`` and never
touches the network (PLAN D17).
"""

from __future__ import annotations

import hashlib
import io
import json
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx

from mitre_mapper.models import ExternalReference, FetchResult
from mitre_mapper.runlog import RunLog

__all__ = ["fetch_reference", "gather_evidence", "slug"]

USER_AGENT = "mitre-mapper/0.1 (+https://github.com/timothyalder/mitre-mapper; evidence fetcher)"
_TEXT_TYPES = ("application/json", "application/xml", "application/xhtml+xml")


class _FetchError(Exception):
    """Expected, human-readable fetch failure."""


def slug(source_name: str) -> str:
    """Stable, filesystem-safe name for a source (used for evidence files)."""
    s = re.sub(r"[^a-z0-9]+", "-", source_name.lower()).strip("-")[:80].strip("-")
    return s or "source"


# --- raw bytes: scheme -> (bytes, content_type) ---------------------------------


def _read_http(url: str, timeout: float, client: httpx.Client | None) -> tuple[bytes, str]:
    own = client is None
    c = client or httpx.Client()
    try:
        resp = c.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=timeout, follow_redirects=True
        )
        resp.raise_for_status()
    finally:
        if own:
            c.close()
    return resp.content, resp.headers.get("content-type", "").split(";")[0].strip().lower()


def _read_file(url: str, timeout: float, client: httpx.Client | None) -> tuple[bytes, str]:
    parsed = urlparse(url)
    path = unquote(parsed.path) if parsed.scheme == "file" else url
    p = Path(path).expanduser()
    if not p.is_file():
        raise _FetchError(f"file not found: {p}")
    ctype = {".pdf": "application/pdf", ".html": "text/html", ".htm": "text/html"}.get(
        p.suffix.lower(), "text/plain"
    )
    return p.read_bytes(), ctype


_READERS: dict[str, Callable[[str, float, httpx.Client | None], tuple[bytes, str]]] = {
    "http": _read_http,
    "https": _read_http,
    "file": _read_file,
    "": _read_file,
}


# --- extraction ------------------------------------------------------------------


def _extract(data: bytes, ctype: str) -> tuple[str, str]:
    """Return ``(text, effective_content_type)``; raise _FetchError if unusable."""
    head = data[:1024].lstrip().lower()
    if ctype == "application/pdf" or data.startswith(b"%PDF"):
        import pypdf

        reader = pypdf.PdfReader(io.BytesIO(data))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        ctype = "application/pdf"
    elif ctype in ("text/html", "application/xhtml+xml") or head.startswith(
        (b"<!doctype html", b"<html")
    ):
        import trafilatura

        text = trafilatura.extract(data.decode("utf-8", errors="replace")) or ""
        ctype = "text/html"
    elif ctype.startswith("text/") or ctype in _TEXT_TYPES or not ctype:
        text = data.decode("utf-8", errors="replace")
        ctype = ctype or "text/plain"
    else:
        raise _FetchError(f"unsupported content type: {ctype}")
    text = text.strip()
    if not text:
        raise _FetchError("no extractable text")
    return text, ctype


# --- cache -------------------------------------------------------------------------


def _cache_paths(cache_dir: Path, url: str) -> tuple[Path, Path]:
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{key}.txt", cache_dir / f"{key}.json"


def _cache_get(cache_dir: Path, url: str) -> tuple[str, str] | None:
    txt, meta = _cache_paths(cache_dir, url)
    try:
        ctype = json.loads(meta.read_text(encoding="utf-8")).get("content_type", "text/plain")
        return txt.read_text(encoding="utf-8"), ctype
    except (OSError, ValueError, AttributeError):
        return None


def _cache_put(cache_dir: Path, url: str, text: str, ctype: str) -> None:
    txt, meta = _cache_paths(cache_dir, url)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        txt.write_text(text, encoding="utf-8")
        meta.write_text(json.dumps({"url": url, "content_type": ctype}), encoding="utf-8")
    except OSError:
        pass  # a cache write failure must not lose the fetched evidence


# --- public API ----------------------------------------------------------------------


def _result(
    ref: ExternalReference,
    text: str,
    ctype: str,
    max_chars: int,
    cache_path: Path | None = None,
) -> FetchResult:
    n = len(text)
    return FetchResult(
        source_name=ref.source_name,
        url=ref.url,
        ok=True,
        text=text[:max_chars],
        content_type=ctype,
        original_length=n,
        truncated=n > max_chars,
        cache_path=str(cache_path) if cache_path else None,
    )


def _fetch(
    ref: ExternalReference,
    cache_dir: Path,
    evidence_dir: Path | None,
    use_cache: bool,
    timeout: float,
    max_chars: int,
    client: httpx.Client | None,
) -> tuple[FetchResult, bool]:
    """Fetch one reference; return ``(result, served_from_cache)``. May raise."""
    if evidence_dir is not None:
        path = evidence_dir / f"{slug(ref.source_name)}.txt"
        if not path.is_file():
            raise _FetchError("not in frozen evidence")
        return _result(ref, path.read_text(encoding="utf-8"), "text/plain", max_chars, path), False
    if not ref.url:
        raise _FetchError("no url")
    scheme = urlparse(ref.url).scheme.lower()
    if len(scheme) == 1:  # Windows drive letter, i.e. a bare path
        scheme = ""
    reader = _READERS.get(scheme)
    if reader is None:
        raise _FetchError(f"unsupported scheme: {scheme}")
    cacheable = reader is _read_http
    if cacheable and use_cache and (hit := _cache_get(cache_dir, ref.url)):
        return _result(ref, hit[0], hit[1], max_chars, _cache_paths(cache_dir, ref.url)[0]), True
    data, ctype = reader(ref.url, timeout, client)
    text, ctype = _extract(data, ctype)
    path = None
    if cacheable:
        _cache_put(cache_dir, ref.url, text, ctype)
        path = _cache_paths(cache_dir, ref.url)[0]
    return _result(ref, text, ctype, max_chars, path), False


def _safe_fetch(
    ref: ExternalReference,
    cache_dir: Path,
    evidence_dir: Path | None,
    use_cache: bool,
    timeout: float,
    max_chars: int,
    client: httpx.Client | None,
) -> tuple[FetchResult, bool]:
    try:
        return _fetch(ref, cache_dir, evidence_dir, use_cache, timeout, max_chars, client)
    except Exception as exc:  # noqa: BLE001 - never raises is a hard requirement
        if isinstance(exc, _FetchError):
            msg = str(exc)
        elif isinstance(exc, httpx.HTTPStatusError):
            msg = f"HTTP {exc.response.status_code}"
        else:
            msg = f"{type(exc).__name__}: {exc}"[:300]
        return FetchResult(source_name=ref.source_name, url=ref.url, ok=False, error=msg), False


def fetch_reference(
    ref: ExternalReference,
    *,
    cache_dir: Path,
    evidence_dir: Path | None = None,
    use_cache: bool = True,
    timeout: float = 20.0,
    max_chars: int = 200_000,
    client: httpx.Client | None = None,
) -> FetchResult:
    """Fetch and extract one reference. Never raises."""
    return _safe_fetch(ref, cache_dir, evidence_dir, use_cache, timeout, max_chars, client)[0]


def gather_evidence(
    refs: list[ExternalReference],
    *,
    log: RunLog | None,
    cache_dir: Path,
    run_evidence_dir: Path | None,
    evidence_dir: Path | None = None,
    fetch: bool = True,
    timeout: float = 20.0,
    max_chars: int = 200_000,
    client: httpx.Client | None = None,
    use_cache: bool = True,
) -> dict[str, FetchResult]:
    """Fetch every reference, keyed by source_name. Never raises; logs per reference."""
    out: dict[str, FetchResult] = {}
    for ref in refs:
        cached = False
        if not fetch and evidence_dir is None:
            res = FetchResult(
                source_name=ref.source_name, url=ref.url, ok=False, error="fetch disabled"
            )
        else:
            res, cached = _safe_fetch(
                ref, cache_dir, evidence_dir, use_cache, timeout, max_chars, client
            )
        if res.ok and run_evidence_dir is not None and res.text is not None:
            try:
                run_evidence_dir.mkdir(parents=True, exist_ok=True)
                (run_evidence_dir / f"{slug(ref.source_name)}.txt").write_text(
                    res.text, encoding="utf-8"
                )
            except OSError:
                pass
        out[ref.source_name] = res
        if log is None:
            continue
        if res.ok:
            log.event(
                "reference_fetch",
                source_name=ref.source_name,
                url=ref.url,
                ok=True,
                chars=len(res.text or ""),
                content_type=res.content_type,
                cached=cached,
            )
            if res.truncated:
                log.event(
                    "evidence_truncated",
                    source_name=ref.source_name,
                    original_chars=res.original_length,
                    kept_chars=len(res.text or ""),
                )
        else:
            log.event(
                "reference_fetch_failed", source_name=ref.source_name, url=ref.url, error=res.error
            )
    return out
