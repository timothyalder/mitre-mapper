"""fetch.py: offline tests via httpx.MockTransport."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from mitre_mapper.fetch import fetch_reference, gather_evidence, slug
from mitre_mapper.models import ExternalReference
from mitre_mapper.runlog import RunLog

HTML = b"<html><body><article><p>Pegasus spyware was analysed by researchers at length.</p></article></body></html>"


def make_pdf(text: str) -> bytes:
    """Minimal one-page PDF with Helvetica text (pypdf can write but not draw text)."""
    stream = f"BT /F1 12 Tf 10 50 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 100] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def client_for(handler, calls: list | None = None) -> httpx.Client:
    def wrapped(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        return handler(request)

    return httpx.Client(transport=httpx.MockTransport(wrapped))


def ref(name: str = "Src", url: str | None = "https://example.com/a") -> ExternalReference:
    return ExternalReference(source_name=name, url=url)


def kw(tmp_path: Path, **extra):
    return {"cache_dir": tmp_path / "cache", **extra}


def test_slug_stable_and_safe():
    assert slug("Lookout Pegasus!") == "lookout-pegasus"
    assert slug("///") == "source"
    assert "/" not in slug("a/b\\c")


def test_html(tmp_path):
    c = client_for(lambda r: httpx.Response(200, content=HTML, headers={"content-type": "text/html"}))
    res = fetch_reference(ref(), client=c, **kw(tmp_path))
    assert res.ok and "Pegasus spyware" in res.text
    assert res.content_type == "text/html"


def test_pdf(tmp_path):
    pdf = make_pdf("Hello PDF evidence")
    c = client_for(lambda r: httpx.Response(200, content=pdf, headers={"content-type": "application/pdf"}))
    res = fetch_reference(ref(), client=c, **kw(tmp_path))
    assert res.ok and "Hello PDF evidence" in res.text


def test_corrupt_pdf_is_failure_not_exception(tmp_path):
    c = client_for(
        lambda r: httpx.Response(200, content=b"%PDF-1.4 garbage", headers={"content-type": "application/pdf"})
    )
    res = fetch_reference(ref(), client=c, **kw(tmp_path))
    assert not res.ok and res.error


def test_http_404_and_timeout(tmp_path):
    res = fetch_reference(ref(), client=client_for(lambda r: httpx.Response(404)), **kw(tmp_path))
    assert not res.ok and "404" in res.error

    def boom(request):
        raise httpx.ReadTimeout("slow", request=request)

    res = fetch_reference(ref(), client=client_for(boom), **kw(tmp_path))
    assert not res.ok and "ReadTimeout" in res.error


def test_redirect_followed(tmp_path):
    def handler(request):
        if request.url.path == "/old":
            return httpx.Response(301, headers={"location": "https://example.com/new"})
        return httpx.Response(200, text="final text", headers={"content-type": "text/plain"})

    res = fetch_reference(ref(url="https://example.com/old"), client=client_for(handler), **kw(tmp_path))
    assert res.ok and res.text == "final text"


def test_file_path_and_file_url(tmp_path):
    f = tmp_path / "note.md"
    f.write_text("# local evidence\n", encoding="utf-8")
    assert fetch_reference(ref(url=str(f)), **kw(tmp_path)).text.startswith("# local")
    assert fetch_reference(ref(url=f.as_uri()), **kw(tmp_path)).ok
    missing = fetch_reference(ref(url=str(tmp_path / "nope.txt")), **kw(tmp_path))
    assert not missing.ok and "not found" in missing.error


def test_url_none_and_unsupported_scheme(tmp_path):
    res = fetch_reference(ref(url=None), **kw(tmp_path))
    assert not res.ok and res.error == "no url"
    assert not fetch_reference(ref(url="ftp://x/y"), **kw(tmp_path)).ok


def test_unsupported_content_type(tmp_path):
    c = client_for(lambda r: httpx.Response(200, content=b"\x89PNG", headers={"content-type": "image/png"}))
    res = fetch_reference(ref(), client=c, **kw(tmp_path))
    assert not res.ok and "unsupported" in res.error


def test_cache_hit_and_no_cache(tmp_path):
    calls: list = []
    c = client_for(lambda r: httpx.Response(200, text="cached body", headers={"content-type": "text/plain"}), calls)
    first = fetch_reference(ref(), client=c, **kw(tmp_path))
    second = fetch_reference(ref(), client=c, **kw(tmp_path))
    assert first.ok and second.text == "cached body" and len(calls) == 1
    assert Path(second.cache_path).is_file()
    fetch_reference(ref(), client=c, use_cache=False, **kw(tmp_path))
    assert len(calls) == 2


def test_truncation(tmp_path):
    c = client_for(lambda r: httpx.Response(200, text="x" * 100, headers={"content-type": "text/plain"}))
    res = fetch_reference(ref(), client=c, max_chars=10, **kw(tmp_path))
    assert res.ok and len(res.text) == 10 and res.truncated and res.original_length == 100


def test_frozen_mode_never_uses_network(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "src.txt").write_text("frozen text", encoding="utf-8")
    calls: list = []
    c = client_for(lambda r: httpx.Response(200, text="live"), calls)
    ok = fetch_reference(ref("Src"), client=c, evidence_dir=ev, **kw(tmp_path))
    miss = fetch_reference(ref("Other"), client=c, evidence_dir=ev, **kw(tmp_path))
    assert ok.text == "frozen text"
    assert not miss.ok and miss.error == "not in frozen evidence"
    assert calls == []


def test_gather_evidence_logs_and_writes(tmp_path):
    def handler(request):
        if request.url.path == "/big":
            return httpx.Response(200, text="y" * 50, headers={"content-type": "text/plain"})
        return httpx.Response(404)

    log = RunLog.start(
        tmp_path / "runs", software_name="X", intake_text_or_path="x", model="m",
        judge_model=None, prompt_text="p",
    )
    refs = [
        ref("Big One", "https://example.com/big"),
        ref("Dead", "https://example.com/dead"),
        ref("None", None),
    ]
    out = gather_evidence(
        refs, log=log, cache_dir=tmp_path / "cache", run_evidence_dir=log.run_dir / "evidence",
        max_chars=20, client=client_for(handler),
    )
    assert set(out) == {"Big One", "Dead", "None"}
    assert (log.run_dir / "evidence" / "big-one.txt").read_text() == "y" * 20
    events = [json.loads(line) for line in log.events_path.read_text().splitlines()]
    by = {}
    for e in events:
        by.setdefault(e["event"], []).append(e)
    assert by["reference_fetch"][0]["cached"] is False and by["reference_fetch"][0]["chars"] == 20
    assert by["evidence_truncated"][0]["original_chars"] == 50
    assert by["evidence_truncated"][0]["kept_chars"] == 20
    assert len(by["reference_fetch_failed"]) == 2
    log.finalize("declined")


def test_gather_fetch_disabled(tmp_path):
    calls: list = []
    c = client_for(lambda r: httpx.Response(200, text="x"), calls)
    log = RunLog.start(
        tmp_path / "runs", software_name="X", intake_text_or_path="x", model="m",
        judge_model=None, prompt_text="p",
    )
    out = gather_evidence(
        [ref()], log=log, cache_dir=tmp_path / "c", run_evidence_dir=None, fetch=False, client=c
    )
    assert out["Src"].error == "fetch disabled" and calls == []
    assert '"reference_fetch_failed"' in log.events_path.read_text()
    log.finalize("declined")


def test_gather_frozen_logs_without_log(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "src.txt").write_text("t", encoding="utf-8")
    out = gather_evidence(
        [ref()], log=None, cache_dir=tmp_path / "c", run_evidence_dir=None, evidence_dir=ev
    )
    assert out["Src"].ok
