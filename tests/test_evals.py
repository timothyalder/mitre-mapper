"""Eval harness: cases, gold, scoring math, evidence lock, offline end-to-end (PLAN section 4)."""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from fakes import ScriptedChatModel, looping_search_model, proposal_msg, tool_call_msg
from mitre_mapper import evaluate as ev
from mitre_mapper.cli import app
from mitre_mapper.models import IntakeSpec, MappingProposal, TechniqueMapping
from mitre_mapper.runlog import read_index
from mitre_mapper.store import get_store

ROOT = Path(__file__).resolve().parents[1]
PROSE = "mitre-mapper intake description"
BODY = "Spyware that collects location data and records the microphone."
SOURCE_TEXT = "FIN7 used CrackMapExec to move laterally after the initial intrusion."


# ---- committed cases -------------------------------------------------------------------------


def test_three_cases_load_with_the_documented_metadata():
    cases = {c.case_name: c for c in ev.load_cases()}
    assert set(cases) == {"pegasus-ios", "pegasus-ios-thin", "crackmapexec"}
    assert (cases["pegasus-ios"].intake_status, cases["pegasus-ios"].twin_baseline_id) == ("user", "S0316")
    assert cases["pegasus-ios-thin"].intake_status == "attack-description"
    assert cases["pegasus-ios-thin"].thin_of == "pegasus-ios"
    crack = cases["crackmapexec"]
    assert (crack.intake_status, crack.twin_baseline_id, crack.attack_id) == ("draft", "S0165", "S0488")
    assert crack.is_draft and not cases["pegasus-ios"].is_draft
    assert all(c.intake_path.is_file() for c in cases.values())
    assert crack.holdout == "crackmapexec" and cases["pegasus-ios"].holdout == "pegasus"


def test_draft_status_is_marked_in_the_yaml_and_warned_about():
    text = (ev.CASES_DIR / "crackmapexec.yaml").read_text()
    assert "intake_status: draft  # written by Claude; rewrite in your own words" in text
    case = ev.load_cases(["crackmapexec"])[0]
    assert "DRAFT written by Claude" in ev.draft_warning(case)
    assert ev.draft_warning(ev.load_cases(["pegasus-ios"])[0]) is None


def test_fixture_intakes_have_no_user_asserted_items_and_leak_no_attack_ids():
    from mitre_mapper.intake import parse_intake

    for case in ev.load_cases():
        spec = parse_intake(case.intake_path)
        assert spec.techniques == [] and spec.groups == []  # eval fixtures assert nothing (PLAN 3.1)
        assert not re.search(r"\bT\d{4}\b|\b[GS]\d{4}\b", spec.body), case.case_name
    thin = parse_intake(ev.load_cases(["pegasus-ios-thin"])[0].intake_path)
    assert thin.references == [] and 30 <= len(thin.body.split()) <= 45
    assert "http" not in thin.body and "Citation" not in thin.body and "](" not in thin.body


def test_pegasus_gold_matches_yaml_and_live_store(datasets_dir):
    for name in ("pegasus-ios", "pegasus-ios-thin"):
        case = ev.load_cases([name])[0]
        gold = ev.derive_gold(get_store(datasets_dir).domain(case.domain), case.attack_id)
        assert sorted(case.gold_technique_ids) == gold.techniques and len(gold.techniques) == 15
        assert "T1636" not in gold.techniques  # the parent itself is not in the set
        assert sorted(case.gold_group_ids) == gold.groups == []


@pytest.mark.slow
def test_crackmapexec_gold_matches_yaml_and_live_store(datasets_dir):
    case = ev.load_cases(["crackmapexec"])[0]
    gold = ev.derive_gold(get_store(datasets_dir).domain(case.domain), case.attack_id)
    assert sorted(case.gold_technique_ids) == gold.techniques and len(gold.techniques) == 20
    assert sorted(case.gold_group_ids) == gold.groups == ["G0035", "G0046", "G0069", "G0087", "G1003"]
    assert set(case.groups_with_evidence) <= set(gold.groups)


def test_twin_baseline_numbers_pegasus(datasets_dir):
    case = ev.load_cases(["pegasus-ios"])[0]
    live = get_store(datasets_dir).domain("mobile-attack")
    gold = ev.derive_gold(live, "S0289")
    twin = ev.prf(set(live.software_techniques(case.twin_baseline_id)), set(gold.techniques))
    assert (twin["precision"], round(twin["recall"], 2), round(twin["f1"], 2)) == (0.5, 0.47, 0.48)
    assert twin["jaccard"] == pytest.approx(0.318, abs=0.001)


@pytest.mark.slow
def test_twin_baseline_numbers_crackmapexec(datasets_dir):
    live = get_store(datasets_dir).domain("enterprise-attack")
    gold = ev.derive_gold(live, "S0488")
    twin = ev.prf(set(live.software_techniques("S0165")), set(gold.techniques))
    assert (twin["precision"], twin["recall"], twin["f1"], twin["jaccard"]) == (0.6, 0.3, 0.4, 0.25)


@pytest.mark.slow
def test_groups_with_evidence_recomputes_from_frozen_text_when_present(datasets_dir):
    case = ev.load_cases(["crackmapexec"])[0]
    names = {e["source_name"]: e for e in ev.read_lock(case)}
    evidence = {}
    for n, e in names.items():
        path = case.evidence_dir / f"{ev.slug(n)}.txt"
        if e["ok"] and path.is_file():
            evidence[n] = path.read_text(encoding="utf-8")
    if len(evidence) < sum(1 for e in names.values() if e["ok"]):
        pytest.skip("frozen evidence text is not all present (gitignored; run `eval freeze`)")
    live = get_store(datasets_dir).domain(case.domain)
    got = ev.groups_named_with_software(
        evidence, live, ["G0035", "G0046", "G0069", "G0087", "G1003"], r"crack\s*map\s*exec"
    )
    assert got == sorted(case.groups_with_evidence)


# ---- committed locks and .gitignore ---------------------------------------------------------


def test_committed_locks_cover_every_reference_and_have_the_documented_fields():
    for case in ev.load_cases():
        from mitre_mapper.intake import parse_intake

        lock = ev.read_lock(case)
        assert [e["source_name"] for e in lock] == [r.source_name for r in parse_intake(case.intake_path).references]
        for e in lock:
            assert set(e) == {"source_name", "url", "sha256", "chars", "fetched_at", "ok", "error", "license"}
            assert (e["sha256"] is not None) == e["ok"]


def test_gitignore_ignores_third_party_text_but_not_public_domain_or_locks():
    if shutil.which("git") is None:
        pytest.skip("git not available")
    for case in ev.load_cases():
        for e in ev.read_lock(case):
            if not e["ok"]:
                continue
            rel = (case.evidence_dir / f"{ev.slug(e['source_name'])}.txt").relative_to(ROOT)
            ignored = subprocess.run(["git", "check-ignore", "-q", str(rel)], cwd=ROOT).returncode == 0
            assert ignored == (e["license"] != ev.PUBLIC_DOMAIN_US_GOV), (str(rel), e["license"])
        lock_rel = case.lock_path.relative_to(ROOT)
        assert subprocess.run(["git", "check-ignore", "-q", str(lock_rel)], cwd=ROOT).returncode != 0


@pytest.mark.parametrize(
    ("url", "license_"),
    [
        ("https://www.us-cert.gov/ncas/alerts/TA18-074A", "public-domain-us-gov"),
        ("https://www.cisa.gov/sites/default/files/x.pdf", "public-domain-us-gov"),
        ("https://notcisa.gov.example.com/a", "not-redistributed"),
        ("https://www.crowdstrike.com/blog/x", "not-redistributed"),
        (None, "not-redistributed"),
    ],
)
def test_license_classification(url, license_):
    assert ev.evidence_license(url) == license_


# ---- scoring math on hand-built cases -------------------------------------------------------

TACTICS = {
    "T1430": {"collection"}, "T1429": {"collection"}, "T1636.002": {"collection"},
    "T1636.003": {"collection"}, "T1404": {"privilege-escalation"}, "T1999": {"impact"},
}


def test_prf_edge_cases():
    assert ev.prf({"a", "b"}, {"a", "c"})["f1"] == 0.5
    empty = ev.prf(set(), {"a"})
    assert (empty["precision"], empty["recall"], empty["f1"]) == (None, 0.0, 0.0)
    assert ev.prf({"a"}, set())["recall"] is None and ev.prf({"a"}, set())["f1"] is None
    assert ev.prf({"x"}, {"y"})["f1"] == 0.0


def test_technique_scores_three_granularities():
    gold = ["T1636.002", "T1404", "T1430", "T1429"]
    pred = ["T1636", "T1430", "T1636.003", "T1999"]  # parent, exact, sibling sub-technique, extra
    s = ev.technique_scores(pred, gold, lambda t: TACTICS.get(t, set()))
    assert s["exact"]["recall"] == 0.25 and s["exact"]["precision"] == 0.25 and s["exact"]["tp"] == 1
    # parent-lenient: T1636.002 covered by T1636 (and T1636.003), T1430 exact; T1404/T1429 missed
    assert s["parent_lenient"]["recall"] == 0.5
    assert s["parent_lenient"]["precision"] == 0.75  # T1636, T1636.003, T1430 land on gold parents; T1999 does not
    # tactic: gold {collection, privilege-escalation}; pred {collection, impact}
    assert s["tactic"]["recall"] == 0.5 and s["tactic"]["precision"] == 0.5
    assert s["missed"] == ["T1404", "T1429", "T1636.002"] and s["extra"] == ["T1636", "T1636.003", "T1999"]


def test_group_scores_two_recalls_and_evidence_precision():
    g = ev.group_scores(["G1", "G2", "G9"], ["G1", "G2", "G3", "G4"], ["G1", "G3"], e011_pass_rate=0.5, judge_attribution=None)
    assert g["recall_all"] == 0.5
    assert g["recall_evidence"] == 0.5  # only G1 of {G1, G3}
    assert g["groups_with_evidence"] == ["G1", "G3"] and g["extra"] == ["G9"] and g["missed_all"] == ["G3", "G4"]
    assert g["precision_e011"] == 0.5 and g["precision_judge"] is None
    none = ev.group_scores([], [], [])  # Pegasus has no groups
    assert none["recall_all"] is None and none["recall_evidence"] is None


def test_retriever_recall_at_k_from_search_events():
    events = [
        {"event": "search", "tool": "search_techniques", "query": "a", "k": 10, "returned_ids": ["T1", "T2", "T3", "T4", "T5", "T6"]},
        {"event": "search", "tool": "search_techniques", "query": "b", "k": 10, "returned_ids": []},
        {"event": "search", "tool": "search_groups", "query": "c", "k": 10, "returned_ids": ["G1"]},  # ignored
        {"event": "search", "tool": "search_techniques", "query": "d", "k": 10, "returned_ids": ["T9", "T6"]},
    ]
    r = ev.retriever_scores(events, ["T1", "T6", "T7", "T8"])
    assert r["n_searches"] == 3 and r["zero_hit_searches"] == 1
    assert r["union_recall"] == 0.5  # T1, T6
    assert r["recall_at"]["5"] == 0.5  # T1 is top-5 of query a; T6 is rank 6 there but rank 2 of query d
    assert r["gold_never_retrieved"] == ["T7", "T8"]


def test_retriever_recall_at_5_counts_only_the_top_five_of_a_query():
    events = [{"event": "search", "tool": "search_techniques", "returned_ids": ["T1", "T2", "T3", "T4", "T5", "T6"]}]
    r = ev.retriever_scores(events, ["T6"])
    assert r["recall_at"] == {"5": 0.0, "10": 1.0, "25": 1.0} and r["union_recall"] == 1.0


def test_evidence_precision_uses_the_final_attempt_per_domain():
    events = [
        {"event": "group_quote_check", "domain": "d", "attempt": 1, "passed": False},
        {"event": "group_quote_check", "domain": "d", "attempt": 2, "passed": True},
        {"event": "group_quote_check", "domain": "d", "attempt": 2, "passed": False},
        {"event": "judge_verdict", "domain": "d", "attempt": 1, "items": [{"name": "group_attribution", "passed": False}]},
        {"event": "judge_verdict", "domain": "d", "attempt": 2, "items": [{"name": "group_attribution", "passed": True}]},
    ]
    assert ev.evidence_precision(events) == (0.5, 1.0)
    assert ev.evidence_precision([]) == (None, None)
    assert ev.evidence_precision([{"event": "group_quote_check", "domain": "d", "attempt": 1, "passed": True}]) == (1.0, None)


def _tm(tid, quote="q"):
    return TechniqueMapping(technique_id=tid, rationale="r", evidence=[{"source_name": PROSE, "quote": quote}])


def test_unjustified_additions_null_without_a_judge_and_rated_with_one():
    spec = IntakeSpec(name="x", type="malware", body=BODY)
    props = {"d": MappingProposal(domain="mobile-attack", techniques=[_tm("T1001"), _tm("T1002"), _tm("T1003")])}
    none = ev.unjustified_additions(None, ["T1001"], props, spec, {}, None)
    assert none["rate"] is None and none["judged"] is False and none["n_additions"] == 1

    calls = []

    def judge(spec_, evidence, additions, names):
        calls.append(([a.technique_id for a in additions], names))
        return {"T1001": (True, "ok"), "T1002": (False, "quote is about something else")}, {"model": "j"}

    got = ev.unjustified_additions(None, ["T1001", "T1002", "T1003"], props, spec, {}, judge, {"T1001": "n1"})
    assert calls == [(["T1001", "T1002", "T1003"], {"T1001": "n1"})]
    assert got["n_unsupported"] == 2 and got["rate"] == pytest.approx(0.6667, abs=1e-4)
    assert [i["supported"] for i in got["items"]] == [True, False, False]  # a missing verdict counts as unsupported
    zero = ev.unjustified_additions(None, [], props, spec, {}, judge)
    assert zero["rate"] == 0.0 and zero["judged"] is True

    def broken(*a):
        raise RuntimeError("boom")

    assert "boom" in ev.unjustified_additions(None, ["T1001"], props, spec, {}, broken)["error"]


def test_rich_vs_thin_gap():
    def res(name, thin_of, recall, f1):
        case = ev.EvalCase(case_name=name, intake="x", intake_status="user", domain="mobile-attack", attack_id="S1",
                           holdout="pegasus", thin_of=thin_of)
        scores = {"technique": {"exact": {"recall": recall, "f1": f1}, "parent_lenient": {"recall": recall + 0.1},
                                "tactic": {"recall": 0.9}}}
        return ev.CaseResult(case, None, scores)

    gaps = ev.rich_vs_thin([res("rich", None, 0.6, 0.5), res("thin", "rich", 0.2, 0.25)])
    assert gaps == [{"rich": "rich", "thin": "thin", "recall_exact": 0.4, "recall_parent_lenient": 0.4,
                     "recall_tactic": 0.0, "f1": 0.25}]
    assert "rich-vs-thin gap (rich - thin): exact recall +40 pts" in ev.render_gaps(gaps)
    assert ev.rich_vs_thin([res("rich", None, 0.6, 0.5)]) == []


# ---- evidence lock: freeze + verify (offline: sources are local files) -----------------------


def make_case(tmp_path, *, refs=True, name="synthetic", status="user", groups_with_evidence=(), holdout="pegasus",
              domain="mobile-attack", attack_id="S0289", twin="S0316", prose=BODY, platforms="[iOS]", sw="Pegasus for iOS",
              sw_type="malware") -> ev.EvalCase:
    fixture = tmp_path / "evals" / "fixtures" / name
    fixture.mkdir(parents=True)
    source = tmp_path / "source.txt"
    source.write_text(SOURCE_TEXT + "\n", encoding="utf-8")
    ref_block = (
        f"references:\n  - source_name: Synthetic Report\n    url: {source}\n    description: d\n"
        f"  - source_name: Missing Report\n    url: {tmp_path / 'nope.txt'}\n    description: d\n"
        if refs else ""
    )
    (fixture / "intake.md").write_text(
        f"---\nname: {sw}\ntype: {sw_type}\nplatforms: {platforms}\n{ref_block}---\n{prose}\n", encoding="utf-8"
    )
    return ev.EvalCase(
        case_name=name, intake=f"evals/fixtures/{name}/intake.md", intake_status=status, domain=domain,
        attack_id=attack_id, holdout=holdout, twin_baseline_id=twin, groups_with_evidence=list(groups_with_evidence),
        root=tmp_path,
    )


def test_freeze_writes_text_and_lock_then_verify_passes(tmp_path):
    case = make_case(tmp_path)
    res = ev.freeze_case(case)
    assert res.written and not res.drift
    lock = {e["source_name"]: e for e in ev.read_lock(case)}
    ok, bad = lock["Synthetic Report"], lock["Missing Report"]
    assert ok["ok"] and ok["sha256"] and ok["chars"] == len(SOURCE_TEXT) and ok["license"] == "not-redistributed"
    assert not bad["ok"] and bad["sha256"] is None and "not found" in bad["error"]
    assert (case.evidence_dir / "synthetic-report.txt").read_text().strip() == SOURCE_TEXT
    assert ev.verify_lock(case) == case.evidence_dir


def test_verify_lock_errors_tell_the_user_to_freeze(tmp_path):
    case = make_case(tmp_path)
    with pytest.raises(ev.EvalError, match=r"missing; run `mitre-mapper eval freeze --case synthetic`"):
        ev.verify_lock(case)
    ev.freeze_case(case)
    path = case.evidence_dir / "synthetic-report.txt"
    path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ev.EvalError, match=r"does not match the locked sha256.*eval freeze --case synthetic"):
        ev.verify_lock(case)
    path.unlink()
    with pytest.raises(ev.EvalError, match=r"synthetic-report.txt is missing.*eval freeze"):
        ev.verify_lock(case)
    ev.freeze_case(case)
    lock = [e for e in ev.read_lock(case) if e["source_name"] != "Missing Report"]
    case.lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(ev.EvalError, match=r"'Missing Report': not in evidence.lock.json"):
        ev.verify_lock(case)


def test_freeze_drift_is_an_error_unless_update(tmp_path):
    case = make_case(tmp_path)
    ev.freeze_case(case)
    before = case.lock_path.read_text()
    (tmp_path / "source.txt").write_text("The page changed.\n", encoding="utf-8")
    drifted = ev.freeze_case(case)
    assert drifted.drift and not drifted.written and "content changed" in drifted.drift[0]
    assert case.lock_path.read_text() == before  # nothing written
    assert (case.evidence_dir / "synthetic-report.txt").read_text().strip() == SOURCE_TEXT
    updated = ev.freeze_case(case, update=True)
    assert updated.written and not updated.drift
    assert (case.evidence_dir / "synthetic-report.txt").read_text().strip() == "The page changed."
    ev.verify_lock(case)


def test_freeze_never_lets_a_transient_failure_replace_a_good_copy(tmp_path):
    case = make_case(tmp_path)
    ev.freeze_case(case)
    before = json.loads(case.lock_path.read_text())
    (tmp_path / "source.txt").unlink()
    strict = ev.freeze_case(case)
    assert strict.drift and "now fails to fetch" in strict.drift[0]
    lenient = ev.freeze_case(case, update=True)
    assert lenient.written and lenient.warnings and not lenient.drift
    assert json.loads(case.lock_path.read_text()) == before  # still ok:true with the old hash
    ev.verify_lock(case)


def test_unchanged_refreeze_keeps_the_lock_byte_stable(tmp_path):
    case = make_case(tmp_path)
    ev.freeze_case(case)
    first = case.lock_path.read_text()
    ev.freeze_case(case)
    assert case.lock_path.read_text() == first


def test_thin_case_without_references_has_an_empty_lock(tmp_path):
    case = make_case(tmp_path, refs=False, name="thin")
    assert ev.freeze_case(case).written
    assert json.loads(case.lock_path.read_text()) == []
    ev.verify_lock(case)


# ---- end to end: scripted fake model, synthetic frozen evidence, real mobile dataset ---------

GOLD_HITS = ["T1430", "T1429", "T1409"]


def tech(tid, quote="collects location data"):
    return {"technique_id": tid, "rationale": "Described in the prose.",
            "evidence": [{"source_name": PROSE, "quote": quote}]}


def mobile_proposal(*extra):
    return {"domain": "mobile-attack", "techniques": [tech(t) for t in (*GOLD_HITS, *extra)]}


def run(case, tmp_path, model, **kw):
    return ev.run_case(
        case, model=model, judge_model=kw.pop("judge_model", None), runs_dir=tmp_path / "runs",
        datasets_dir=ROOT / "datasets", **kw,
    )


@pytest.fixture
def pegasus_case(tmp_path):
    case = make_case(tmp_path, prose="Spyware that collects location data and records the microphone.")
    ev.freeze_case(case)
    return case


def test_end_to_end_mobile_case_scores_land_on_disk_and_in_the_index(tmp_path, pegasus_case):
    model = ScriptedChatModel(script=[
        tool_call_msg("search_techniques", {"query": "location tracking", "k": 5}),
        proposal_msg(mobile_proposal("T1417")),  # T1417 is not in S0289's gold
    ])
    res = run(pegasus_case, tmp_path, model)
    rec = res.record
    assert rec.terminal_state == "minted" and rec.eval_case == "synthetic"
    scores = json.loads((res.run_dir / "scores.json").read_text())
    assert scores == rec.eval_scores == res.scores
    t = scores["technique"]
    assert t["exact"]["tp"] == 3 and t["exact"]["recall"] == 0.2 and t["exact"]["precision"] == 0.75
    assert scores["n_gold"] == 15 and scores["n_pred"] == 4 and t["extra"] == ["T1417"]
    assert 0 < t["tactic"]["recall"] <= 1 and t["parent_lenient"]["recall"] >= t["exact"]["recall"]
    assert scores["baselines"]["copy_twin"]["id"] == "S0316" and scores["baselines"]["copy_twin"]["f1"] == 0.4828
    assert scores["baselines"]["model_only"] is None and scores["unjustified_additions"]["rate"] is None
    assert scores["beats_copy_twin_f1"] is False  # 3 of 15 is nowhere near the twin
    assert scores["groups"]["recall_all"] is None  # Pegasus has no groups
    assert scores["retriever"]["n_searches"] == 1
    # the index row and the log are an ordinary run's
    row = next(r for r in read_index(tmp_path / "runs") if r.run_id == rec.run_id)
    assert row.eval_scores["technique"]["exact"]["recall"] == 0.2 and row.eval_case == "synthetic"
    events = [json.loads(line) for line in (res.run_dir / "events.jsonl").read_text().splitlines()]
    start = next(e for e in events if e["event"] == "run_start")
    assert start["eval_case"] == "synthetic" and events[-1]["event"] == "run_end"
    hold = next(e for e in events if e["event"] == "merge" and e.get("kind") == "holdout")
    assert hold["name"] == "pegasus" and hold["domain"] == "mobile-attack"
    assert hold["removed_by_type"]["malware"] == 3 and hold["masked_relationship_ids"] == []
    assert any(e["event"] == "reference_fetch" and e["source_name"] == "Synthetic Report" for e in events)  # frozen
    assert any(e["event"] == "reference_fetch_failed" and e["source_name"] == "Missing Report" for e in events)
    assert (res.run_dir / "delta.json").is_file() and (res.run_dir / "run.md").is_file()


def test_eval_does_not_modify_the_real_allocations_registry(tmp_path, pegasus_case):
    real = ROOT / "datasets" / "allocations.json"
    before = real.read_bytes()
    run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal())]))
    assert real.read_bytes() == before


def test_end_to_end_with_support_judge_and_model_only_baseline(tmp_path, pegasus_case):
    seen = {}

    def support_judge(spec, evidence, additions, names):
        seen["names"] = names
        return {"T1417": (False, "quote is about location, not input capture")}, {"model": "judge-x", "tokens_in": 7}

    def model_only(spec, evidence, domain):
        seen["evidence"] = evidence
        return ["T1430", "T1429", "T1409", "T1404", "T9999"], {"model": "m", "tokens_in": 5, "tokens_out": 2}

    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal("T1417"))]),
              support_judge=support_judge, model_only=model_only)
    s = res.scores
    ua = s["unjustified_additions"]
    assert ua["rate"] == 1.0 and ua["n_unsupported"] == 1 and ua["items"][0]["supported"] is False
    assert seen["names"]["T1417"] == "Input Capture"
    mo = s["baselines"]["model_only"]
    assert mo["tp"] == 4 and mo["n_invalid_ids"] == 1 and mo["recall"] == round(4 / 15, 4)
    assert SOURCE_TEXT in seen["evidence"]["Synthetic Report"]
    events = [json.loads(line) for line in (res.run_dir / "events.jsonl").read_text().splitlines()]
    kinds = {e.get("kind") for e in events if e["event"] == "merge"}
    assert {"eval_support_judge", "eval_baseline", "holdout"} <= kinds


def test_baseline_failures_are_recorded_not_fatal(tmp_path, pegasus_case):
    def broken(*a):
        raise RuntimeError("no model today")

    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal())]), model_only=broken)
    assert res.record.terminal_state == "minted"
    assert "no model today" in res.scores["baselines"]["model_only"]["error"]


def test_a_failing_scorer_never_loses_the_run(tmp_path, pegasus_case):
    def mapper(*args, **kw):
        from mitre_mapper.run import map_software

        def boom(log, inp):
            raise ValueError("scorer bug")

        return map_software(*args, **{**kw, "eval_scorer": boom})

    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal())]), mapper=mapper)
    assert res.record.terminal_state == "minted" and res.record.eval_scores is None
    events = [json.loads(line) for line in (res.run_dir / "events.jsonl").read_text().splitlines()]
    assert any(e["event"] == "error" and "scorer bug" in e["message"] for e in events)
    assert events[-1]["event"] == "run_end"


def test_a_budget_killed_eval_run_still_gets_scores(tmp_path, pegasus_case):
    res = run(pegasus_case, tmp_path, looping_search_model(), max_model_calls=3)
    assert res.record.terminal_state == "budget_exhausted"
    assert res.scores["terminal_state"] == "budget_exhausted"
    assert res.scores["technique"]["exact"]["recall"] == 0.0 and res.scores["n_pred"] == 0
    assert res.scores["beats_copy_twin_f1"] is False
    assert res.scores["retriever"]["n_searches"] >= 1  # the retriever number survives a failed run
    assert read_index(tmp_path / "runs")[-1].eval_scores is not None


def test_a_non_gold_only_proposal_scores_zero_recall_and_flags_additions(tmp_path, pegasus_case):
    bad = {"domain": "mobile-attack", "techniques": [tech("T1417"), tech("T1418")]}
    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(bad)]))
    t = res.scores["technique"]
    assert t["exact"]["recall"] == 0.0 and t["exact"]["f1"] == 0.0 and sorted(t["extra"]) == ["T1417", "T1418"]


def test_eval_makes_no_network_calls(tmp_path, pegasus_case, monkeypatch):
    def deny(*a, **k):
        raise AssertionError("network used during eval")

    monkeypatch.setattr(httpx.Client, "send", deny)
    monkeypatch.setattr(httpx.Client, "request", deny)
    monkeypatch.setattr(httpx, "get", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal())]))
    assert res.record.terminal_state == "minted"
    events = [json.loads(line) for line in (res.run_dir / "events.jsonl").read_text().splitlines()]
    assert not any(e["event"] == "error" for e in events)
    # and freezing is the one place the network is allowed (deny proves the guard bites)
    with pytest.raises(AssertionError):
        httpx.get("https://example.com")


def test_run_case_refuses_without_a_valid_lock_before_any_model_call(tmp_path):
    case = make_case(tmp_path)
    model = ScriptedChatModel(script=[])
    with pytest.raises(ev.EvalError, match="eval freeze"):
        run(case, tmp_path, model)
    assert model.n_calls == 0 and not (tmp_path / "runs").exists()


def test_include_reviews_scores_a_reviewed_run(tmp_path, pegasus_case):
    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal("T1417"))]))
    review = {"run_id": res.record.run_id, "ts": "2026-10-03T00:00:00.000Z",
              "techniques": {"T1430": "accepted", "T1429": "accepted", "T1409": "rejected", "T1417": "accepted"},
              "groups": {}, "missed_techniques": ["T1404"], "missed_groups": [], "notes": "n"}
    (res.run_dir / "review.json").write_text(json.dumps(review))
    out = ev.score_reviews(tmp_path / "runs", ROOT / "datasets")
    assert [o.name for o in out] == [f"review:{res.record.run_id}"]
    t = out[0].scores["technique"]
    # gold = accepted + missed = {T1430, T1429, T1417, T1404}; predicted = the minted four
    assert t["exact"]["tp"] == 3 and t["exact"]["recall"] == 0.75 and t["exact"]["precision"] == 0.75
    assert (res.run_dir / "review_scores.json").is_file()
    assert json.loads((res.run_dir / "scores.json").read_text())["case"] == "synthetic"  # untouched
    assert "review:" in ev.render_case(out[0])


def test_render_case_prints_every_required_number(tmp_path, pegasus_case):
    res = run(pegasus_case, tmp_path, ScriptedChatModel(script=[proposal_msg(mobile_proposal("T1417"))]))
    text = ev.render_case(res)
    for needle in ("technique recall: exact", "parent-lenient", "tactic", "unjustified additions", "no judge model",
                   "group recall: vs ATT&CK", "vs evidence", "baseline copy-twin S0316", "baseline model-only",
                   "retriever recall", "does NOT beat the copy-twin"):
        assert needle in text, needle


@pytest.mark.slow
def test_end_to_end_enterprise_case_scores_group_recall_two_ways(tmp_path):
    prose = "Post-exploitation tool that dumps credentials from the local account database."
    case = make_case(
        tmp_path, name="cme", status="draft", holdout="crackmapexec", domain="enterprise-attack", attack_id="S0488",
        twin="S0165", groups_with_evidence=["G0046", "G0035"], prose=prose, platforms="[Windows]",
        sw="CrackMapExec", sw_type="tool",
    )
    ev.freeze_case(case)
    proposal = {
        "domain": "enterprise-attack",
        "techniques": [
            {"technique_id": "T1003.002", "rationale": "dumps the account database",
             "evidence": [{"source_name": PROSE, "quote": "dumps credentials from the local account database"}]},
            {"technique_id": "T1046", "rationale": "network scan, not in gold",
             "evidence": [{"source_name": PROSE, "quote": "Post-exploitation tool"}]},
        ],
        "groups": [{"group_id": "G0046", "source_name": "Synthetic Report",
                    "quote": "FIN7 used CrackMapExec to move laterally"}],
    }
    res = run(case, tmp_path, ScriptedChatModel(script=[proposal_msg(proposal)]))
    assert res.record.terminal_state == "minted", res.record
    g = res.scores["groups"]
    assert g["pred"] == ["G0046"] and g["recall_all"] == 0.2 and g["recall_evidence"] == 0.5
    assert g["precision_e011"] == 1.0 and g["precision_judge"] is None
    assert res.scores["technique"]["exact"]["recall"] == 0.05
    assert res.scores["baselines"]["copy_twin"]["id"] == "S0165"
    events = [json.loads(line) for line in (res.run_dir / "events.jsonl").read_text().splitlines()]
    hold = next(e for e in events if e["event"] == "merge" and e.get("kind") == "holdout")
    assert hold["name"] == "crackmapexec" and len(hold["masked_relationship_ids"]) == 4
    assert hold["removed_by_type"] == {"relationship": 30, "tool": 1}
    assert "DRAFT" in ev.render_case(res)


# ---- the LangChain-bound pieces in evals/score.py (scripted fake models) --------------------


def test_score_module_support_judge_and_model_only_with_fake_models():
    score = ev.load_score_module()
    spec = IntakeSpec(name="x", type="malware", platforms=["iOS"], body=BODY)
    adds = [_tm("T1417", "collects location data"), _tm("T1418")]
    judge_model = ScriptedChatModel(script=[tool_call_msg("SupportVerdicts", {"items": [
        {"technique_id": "T1417", "supported": True, "rationale": "yes"},
        {"technique_id": "T1418", "supported": False, "rationale": "no"},
    ]}, tokens=(30, 4))])
    verdicts, meta = score.build_support_judge(judge_model)(spec, {}, adds, {"T1417": "Input Capture"})
    assert verdicts == {"T1417": (True, "yes"), "T1418": (False, "no")}
    assert meta["tokens_in"] == 30 and meta["model"] == "scripted-fake"
    prompt = " ".join(str(m.content) for m in judge_model.seen_messages[0])
    assert "Input Capture" in prompt and "collects location data" in prompt

    base_model = ScriptedChatModel(script=[proposal_msg(mobile_proposal())])
    ids, meta = score.build_model_only(base_model)(spec, {"R": "report text"}, "mobile-attack")
    assert ids == sorted(GOLD_HITS) and meta["tokens_in"] == 10
    assert "report text" in " ".join(str(m.content) for m in base_model.seen_messages[0])

    bad = ScriptedChatModel(script=[tool_call_msg("MappingProposal", {"domain": "mobile-attack", "techniques": "nope"})])
    with pytest.raises(ValueError, match="unparseable"):
        score.build_model_only(bad)(spec, {}, "mobile-attack")


def test_evaluate_module_has_no_langchain_import():
    import ast

    tree = ast.parse((ROOT / "src" / "mitre_mapper" / "evaluate.py").read_text())
    roots = {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    roots |= {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not roots & {"langchain", "langchain_core", "langgraph"}


# ---- CLI ----------------------------------------------------------------------------------------


def test_cli_eval_needs_a_model(monkeypatch):
    monkeypatch.delenv("MITRE_MAPPER_MODEL", raising=False)
    r = CliRunner().invoke(app, ["eval"])
    assert r.exit_code == 2 and "--model" in r.output


def test_cli_eval_unknown_case_and_missing_lock_fail_before_any_model_call(tmp_path, monkeypatch):
    r = CliRunner().invoke(app, ["eval", "--case", "nope", "--model", "x"])
    assert r.exit_code == 1 and "unknown eval case" in r.output
    case = make_case(tmp_path, name="lockless")
    (tmp_path / "evals" / "cases").mkdir(parents=True)
    (tmp_path / "evals" / "cases" / "lockless.yaml").write_text(
        "case_name: lockless\nintake: evals/fixtures/lockless/intake.md\nintake_status: draft\n"
        "domain: mobile-attack\nattack_id: S0289\nholdout: pegasus\n"
    )
    monkeypatch.setattr(ev, "CASES_DIR", tmp_path / "evals" / "cases")
    monkeypatch.setattr(ev, "REPO_ROOT", tmp_path)
    assert case.case_name == "lockless"
    r = CliRunner().invoke(app, ["eval", "--case", "lockless", "--model", "x"])
    assert r.exit_code == 1 and "mitre-mapper eval freeze --case lockless" in r.output


def test_cli_freeze_and_eval_roundtrip_with_a_fake_model(tmp_path, monkeypatch):
    case = make_case(tmp_path, name="roundtrip", status="draft")
    (tmp_path / "evals" / "cases").mkdir(parents=True)
    (tmp_path / "evals" / "cases" / "roundtrip.yaml").write_text(
        "case_name: roundtrip\nintake: evals/fixtures/roundtrip/intake.md\nintake_status: draft  # written by Claude\n"
        "domain: mobile-attack\nattack_id: S0289\nholdout: pegasus\ntwin_baseline_id: S0316\n"
    )
    monkeypatch.setattr(ev, "CASES_DIR", tmp_path / "evals" / "cases")
    monkeypatch.setattr(ev, "REPO_ROOT", tmp_path)
    runner = CliRunner()
    frozen = runner.invoke(app, ["eval", "freeze", "--case", "roundtrip"])
    assert frozen.exit_code == 0, frozen.output
    assert "Synthetic Report: ok" in frozen.output and "Missing Report: FAILED" in frozen.output
    assert (case.fixture_dir / "evidence.lock.json").is_file()
    again = runner.invoke(app, ["eval", "freeze", "--case", "roundtrip"])
    assert again.exit_code == 0
    (tmp_path / "source.txt").write_text("changed", encoding="utf-8")
    drift = runner.invoke(app, ["eval", "freeze", "--case", "roundtrip"])
    assert drift.exit_code == 1 and "HASH DRIFT" in drift.output and "--update" in drift.output
    assert runner.invoke(app, ["eval", "freeze", "--case", "roundtrip", "--update"]).exit_code == 0

    import mitre_mapper.run as run_mod

    real = run_mod.map_software
    fake = ScriptedChatModel(script=[proposal_msg(mobile_proposal())])
    monkeypatch.setattr(run_mod, "map_software", lambda *a, **kw: real(*a, **{**kw, "model": fake}))
    out = runner.invoke(app, ["eval", "--case", "roundtrip", "--model", "fake", "--runs-dir", str(tmp_path / "runs"),
                              "--datasets-dir", str(ROOT / "datasets")])
    assert out.exit_code == 0, out.output
    assert "DRAFT written by Claude" in out.output  # prominent warning
    assert "== roundtrip" in out.output and "technique recall: exact 20%" in out.output
    assert "baseline copy-twin S0316" in out.output
    assert "baseline model-only: " in out.output  # a bare string model name cannot be initialised: recorded, not fatal
    rows = read_index(tmp_path / "runs")
    assert rows[-1].eval_case == "roundtrip" and rows[-1].eval_scores["technique"]["exact"]["recall"] == 0.2
