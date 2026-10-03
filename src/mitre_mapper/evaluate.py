"""Scored eval harness (PLAN section 4, D10, D11, D17).

No LangChain in this module. Everything model-shaped is injected: the mapper (``run.map_software``),
the unjustified-addition support judge and the no-retrieval baseline (both live in
``evals/score.py``). The pure parts (gold derivation, scoring math, baselines, evidence lock) are
plain functions so they are testable on hand-built cases.

Flow of one case (:func:`run_case`)::

    verify evidence.lock.json against evals/fixtures/<case>/evidence/   (offline, no network)
    map_software(intake, fetch=False, evidence_dir=frozen, holdout=<predicate>, eval_case=<case>,
                 eval_scorer=<score hook>)
    -> the hook scores the run against the LIVE, non-held-out store just before finalize, writes
       runs/<id>/scores.json and returns the dict that lands on the index row (eval_scores)

Gold is never read from the case YAML: it is derived from the live store, and a test asserts the
YAML's human-readable copy still equals it.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from mitre_mapper.fetch import fetch_reference, slug
from mitre_mapper.holdout import get_holdout
from mitre_mapper.intake import IntakeError, parse_intake
from mitre_mapper.models import IntakeSpec, MappingProposal, Review, RunRecord, TechniqueMapping
from mitre_mapper.runlog import RunLog
from mitre_mapper.report import UNSCORED_STATES
from mitre_mapper.session import EvalScorer, ScoringInput
from mitre_mapper.store import DomainStore, get_store

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALS_DIR = REPO_ROOT / "evals"
CASES_DIR = EVALS_DIR / "cases"
LOCK_NAME = "evidence.lock.json"
RECALL_CUTOFFS = (5, 10, 25)
PUBLIC_DOMAIN_US_GOV = "public-domain-us-gov"
NOT_REDISTRIBUTED = "not-redistributed"
_US_GOV_HOSTS = ("cisa.gov", "us-cert.gov", "fbi.gov", "nsa.gov", "ic3.gov", "dhs.gov")


class EvalError(Exception):
    """A user-facing eval failure (bad case, missing/drifted evidence). Message says what to run."""


# --------------------------------------------------------------------------- cases


class EvalCase(BaseModel):
    """One ``evals/cases/<name>.yaml``."""

    model_config = ConfigDict(extra="forbid")

    case_name: str
    description: str = ""
    intake: str  # path relative to the repo root
    intake_status: Literal["user", "draft", "attack-description"]
    domain: Literal["enterprise-attack", "mobile-attack", "ics-attack"]
    attack_id: str  # the real ATT&CK software this case hides and re-derives
    holdout: str
    twin_baseline_id: str | None = None
    groups_with_evidence: list[str] = []
    gold_technique_ids: list[str] = []  # human-readable copy; scoring uses the live store
    gold_group_ids: list[str] = []  # likewise
    thin_of: str | None = None  # set on the thin case: name of its rich counterpart

    # resolved at load time
    root: Path = REPO_ROOT

    @property
    def intake_path(self) -> Path:
        return self.root / self.intake

    @property
    def fixture_dir(self) -> Path:
        return self.intake_path.parent

    @property
    def evidence_dir(self) -> Path:
        return self.fixture_dir / "evidence"

    @property
    def lock_path(self) -> Path:
        return self.fixture_dir / LOCK_NAME

    @property
    def is_draft(self) -> bool:
        return self.intake_status == "draft"


def load_case(path: Path, *, root: Path | None = None) -> EvalCase:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return EvalCase.model_validate({**data, "root": Path(root or REPO_ROOT)})
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise EvalError(f"bad eval case {path}: {exc}") from exc


def load_cases(
    names: Sequence[str] | None = None, *, cases_dir: Path | None = None, root: Path | None = None
) -> list[EvalCase]:
    """All cases (sorted by name), or the named ones in the order given."""
    cases_dir = Path(cases_dir or CASES_DIR)
    root = Path(root or REPO_ROOT)
    found = {c.case_name: c for c in (load_case(p, root=root) for p in sorted(cases_dir.glob("*.yaml")))}
    if not names:
        return [found[k] for k in sorted(found)]
    missing = [n for n in names if n not in found]
    if missing:
        raise EvalError(f"unknown eval case(s) {missing}; known: {sorted(found)}")
    return [found[n] for n in names]


# --------------------------------------------------------------------------- gold (live store)


@dataclass
class Gold:
    techniques: list[str]
    groups: list[str]
    tactics: list[str]


def _software(ds: DomainStore, attack_id: str) -> dict[str, Any] | None:
    for stix_type in ("malware", "tool"):
        obj = ds.lookup(attack_id, stix_type).obj
        if obj is not None:
            return obj
    return None


def software_groups(ds: DomainStore, attack_id: str) -> list[str]:
    """ATT&CK ids of active groups with a ``uses`` relationship to the software, sorted."""
    software = _software(ds, attack_id)
    if software is None:
        return []
    out: set[str] = set()
    for row in ds.data.get_groups_using_software(software["id"]):
        group = ds.get_by_stix_id(row["object"]["id"])
        gid = ds.attack_id(group) if group else None
        if group and gid and not (group.get("revoked") or group.get("x_mitre_deprecated")):
            out.add(gid)
    return sorted(out)


def technique_tactics(ds: DomainStore, technique_id: str) -> set[str]:
    obj = ds.lookup(technique_id, "attack-pattern").obj
    return {p["phase_name"] for p in (obj or {}).get("kill_chain_phases", []) if "phase_name" in p}


def groups_named_with_software(
    evidence: dict[str, str],
    ds: DomainStore,
    group_ids: Sequence[str],
    software_pattern: str,
    *,
    window: int = 1500,
) -> list[str]:
    """Groups whose name/alias appears within ``window`` chars of the software in one source.

    This is what makes a verbatim E011 quote possible, so it defines ``groups_with_evidence``.
    """
    from mitre_mapper.groups import normalize_text

    found: set[str] = set()
    sw = re.compile(software_pattern)
    for text in evidence.values():
        norm = normalize_text(text)
        spots = [m.start() for m in sw.finditer(norm)]
        if not spots:
            continue
        for gid in group_ids:
            group = ds.lookup(gid, "intrusion-set").obj
            for name in ds.group_names(group) if group else []:
                pat = re.compile(rf"(?<!\w){re.escape(normalize_text(name))}(?!\w)")
                if any(abs(m.start() - c) <= window for m in pat.finditer(norm) for c in spots):
                    found.add(gid)
    return sorted(found)


def derive_gold(ds: DomainStore, attack_id: str) -> Gold:
    """Gold from the LIVE (non-held-out) store: techniques, groups, and the tactics they cover."""
    if _software(ds, attack_id) is None:
        raise EvalError(f"{attack_id} not found in {ds.domain}; is the dataset the one the case was written for?")
    techniques = ds.software_techniques(attack_id)
    tactics: set[str] = set()
    for tid in techniques:
        tactics |= technique_tactics(ds, tid)
    return Gold(techniques, software_groups(ds, attack_id), sorted(tactics))


# --------------------------------------------------------------------------- scoring math (pure)


def _ratio(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def prf(pred: set[str], gold: set[str]) -> dict[str, Any]:
    """Precision / recall / F1 / Jaccard of two id sets (None where the denominator is empty)."""
    tp = len(pred & gold)
    p, r = _ratio(tp, len(pred)), _ratio(tp, len(gold))
    if not gold:
        f1 = None
    elif tp == 0:
        f1 = 0.0  # includes "predicted nothing": the pipeline did not beat any baseline
    else:
        assert p is not None and r is not None
        f1 = 2 * p * r / (p + r)
    return {
        "precision": _r(p), "recall": _r(r), "f1": _r(f1), "jaccard": _r(_ratio(tp, len(pred | gold))),
        "tp": tp, "n_pred": len(pred), "n_gold": len(gold),
    }


def parent_id(technique_id: str) -> str:
    """``T1636.002`` -> ``T1636``; a parent id is its own parent."""
    return technique_id.split(".", 1)[0]


def technique_scores(
    pred: Sequence[str], gold: Sequence[str], tactics_of: Callable[[str], set[str]]
) -> dict[str, Any]:
    """Recall (and precision) at three granularities.

    * ``exact``: the id sets.
    * ``parent_lenient``: ids compared after folding sub-techniques onto their parent, so T1636 or
      T1636.003 both cover a gold T1636.002.
    * ``tactic``: the tactics the techniques belong to.
    """
    pred_set, gold_set = set(pred), set(gold)
    out: dict[str, Any] = {"exact": prf(pred_set, gold_set)}
    pp, gp = {parent_id(t) for t in pred_set}, {parent_id(t) for t in gold_set}
    lenient = prf(pp, gp)
    covered = sum(1 for t in gold_set if parent_id(t) in pp)
    ok_preds = sum(1 for t in pred_set if parent_id(t) in gp)
    out["parent_lenient"] = {
        "recall": _r(_ratio(covered, len(gold_set))),
        "precision": _r(_ratio(ok_preds, len(pred_set))),
        "n_parent_pred": lenient["n_pred"],
        "n_parent_gold": lenient["n_gold"],
    }
    pt: set[str] = set().union(*(tactics_of(t) for t in pred_set)) if pred_set else set()
    gt: set[str] = set().union(*(tactics_of(t) for t in gold_set)) if gold_set else set()
    t = prf(pt, gt)
    out["tactic"] = {"recall": t["recall"], "precision": t["precision"], "n_pred": t["n_pred"], "n_gold": t["n_gold"]}
    out["missed"] = sorted(gold_set - pred_set)
    out["extra"] = sorted(pred_set - gold_set)
    return out


def group_scores(
    pred: Sequence[str],
    gold: Sequence[str],
    groups_with_evidence: Sequence[str],
    *,
    e011_pass_rate: float | None = None,
    judge_attribution: float | None = None,
) -> dict[str, Any]:
    """Group recall vs all ATT&CK groups and vs ``groups_with_evidence`` (the gap is evidence loss).

    Precision is *against evidence* (E011 pass rate, judge ``group_attribution``), never against
    ATT&CK. Recall is None when its gold set is empty (e.g. Pegasus has no groups).
    """
    pred_set, gold_set = set(pred), set(gold)
    with_ev = gold_set & set(groups_with_evidence)
    return {
        "gold": sorted(gold_set),
        "pred": sorted(pred_set),
        "groups_with_evidence": sorted(with_ev),
        "recall_all": _r(_ratio(len(pred_set & gold_set), len(gold_set))),
        "recall_evidence": _r(_ratio(len(pred_set & with_ev), len(with_ev))),
        "missed_all": sorted(gold_set - pred_set),
        "extra": sorted(pred_set - gold_set),  # not an error: may be evidence-backed (see precision)
        "precision_e011": _r(e011_pass_rate),
        "precision_judge": _r(judge_attribution),
    }


def read_events(run_dir: Path) -> list[dict[str, Any]]:
    path = Path(run_dir) / "events.jsonl"
    out: list[dict[str, Any]] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def retriever_scores(events: Sequence[dict[str, Any]], gold: Sequence[str]) -> dict[str, Any]:
    """Retriever recall@k from the run's ``search_techniques`` events, separate from end-to-end recall.

    ``recall_at[k]`` = share of gold found in the top-k of any query; ``union`` uses every returned id.
    """
    searches = [e for e in events if e.get("event") == "search" and e.get("tool") == "search_techniques"]
    gold_set = set(gold)
    seen_all: set[str] = set()
    by_k: dict[int, set[str]] = {k: set() for k in RECALL_CUTOFFS}
    for e in searches:
        ids = [str(i) for i in e.get("returned_ids") or []]
        seen_all.update(ids)
        for k in RECALL_CUTOFFS:
            by_k[k].update(ids[:k])
    return {
        "union_recall": _r(_ratio(len(seen_all & gold_set), len(gold_set))),
        "recall_at": {str(k): _r(_ratio(len(by_k[k] & gold_set), len(gold_set))) for k in RECALL_CUTOFFS},
        "n_searches": len(searches),
        "zero_hit_searches": sum(1 for e in searches if not e.get("returned_ids")),
        "gold_never_retrieved": sorted(gold_set - seen_all),
    }


def evidence_precision(events: Sequence[dict[str, Any]]) -> tuple[float | None, float | None]:
    """``(E011 pass rate, judge group_attribution pass rate)`` over each domain's FINAL attempt.

    E011 comes from ``group_quote_check`` events, the judge number from the last ``judge_verdict``.
    Either is None when there is nothing to measure.
    """
    last_attempt: dict[str, int] = {}
    for e in events:
        if e.get("event") == "group_quote_check" and isinstance(e.get("attempt"), int):
            d = str(e.get("domain"))
            last_attempt[d] = max(last_attempt.get(d, 0), e["attempt"])
    checks = [
        e for e in events
        if e.get("event") == "group_quote_check" and e.get("attempt") == last_attempt.get(str(e.get("domain")))
    ]
    e011 = _ratio(sum(1 for c in checks if c.get("passed")), len(checks))
    verdicts: dict[str, dict[str, Any]] = {}
    for e in events:
        if e.get("event") == "judge_verdict":
            verdicts[str(e.get("domain"))] = e
    items = [
        i for v in verdicts.values() for i in v.get("items") or [] if i.get("name") == "group_attribution"
    ]
    judged = _ratio(sum(1 for i in items if i.get("passed")), len(items)) if checks else None
    return e011, judged


# --------------------------------------------------------------------------- injected model pieces

# (value, meta) where meta carries model/tokens/latency for the run log.
SupportJudge = Callable[
    [IntakeSpec, dict[str, str], list[TechniqueMapping], dict[str, str]],
    tuple[dict[str, tuple[bool, str]], dict[str, Any]],
]  # (spec, evidence, additions, {technique id: name}) -> ({id: (supported, rationale)}, meta)
ModelOnly = Callable[[IntakeSpec, dict[str, str], str], tuple[list[str], dict[str, Any]]]


def unjustified_additions(
    log: RunLog | None,
    additions: list[str],
    proposals: dict[str, MappingProposal],
    spec: IntakeSpec,
    evidence: dict[str, str],
    support_judge: SupportJudge | None,
    names: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Proposed techniques that ATT&CK does not have, judged on "does the cited evidence support this".

    Precision-against-evidence replaces precision-against-ATT&CK: ATT&CK is incomplete, so an
    addition is only *unjustified* when the evidence it cites does not support it. ``rate`` is None
    without a judge model (never silently 0).
    """
    base: dict[str, Any] = {"n_additions": len(additions), "additions": additions, "judged": False,
                            "n_unsupported": None, "rate": None, "items": []}
    if support_judge is None:
        return base
    if not additions:
        return {**base, "judged": True, "n_unsupported": 0, "rate": 0.0}
    by_id = {t.technique_id: t for p in proposals.values() for t in p.techniques if not t.user_asserted}
    mappings = [by_id[a] for a in additions if a in by_id]
    try:
        verdicts, meta = support_judge(spec, evidence, mappings, names or {})
    except Exception as exc:  # noqa: BLE001 - a judge failure must not lose the scores
        err = f"{type(exc).__name__}: {exc}"
        if log is not None:
            log.event("merge", kind="eval_support_judge", n_additions=len(additions), error=err)
        return {**base, "error": err}
    if log is not None:
        log.event("merge", kind="eval_support_judge", n_additions=len(additions), **meta)
    items = [
        {"id": a, "supported": bool(verdicts.get(a, (False, "no verdict"))[0]),
         "rationale": verdicts.get(a, (False, "judge returned no verdict for this technique"))[1]}
        for a in additions
    ]
    unsupported = sum(1 for i in items if not i["supported"])
    return {**base, "judged": True, "n_unsupported": unsupported, "rate": _r(unsupported / len(additions)),
            "items": items}


# --------------------------------------------------------------------------- the scorer hook


def predicted_from_mapping(
    techniques: dict[str, list[dict[str, Any]]], groups: dict[str, list[dict[str, Any]]]
) -> tuple[list[str], list[str]]:
    """Technique ids and EXISTING-group ids of a ``mint`` payload (eval fixtures have no user items)."""
    tids = sorted({t["id"] for ts in techniques.values() for t in ts})
    gids = sorted({g["id"] for gs in groups.values() for g in gs if g.get("kind") == "existing"})
    return tids, gids


def score_run(
    case: EvalCase,
    *,
    datasets_dir: Path,
    predicted_techniques: list[str],
    predicted_groups: list[str],
    events: Sequence[dict[str, Any]],
    state: str,
    log: RunLog | None = None,
    spec: IntakeSpec | None = None,
    evidence: dict[str, str] | None = None,
    proposals: dict[str, MappingProposal] | None = None,
    support_judge: SupportJudge | None = None,
    model_only: ModelOnly | None = None,
) -> dict[str, Any]:
    """The full ``eval_scores`` dict for one case run."""
    live = get_store(datasets_dir).domain(case.domain)  # non-held-out: the answer key
    gold = derive_gold(live, case.attack_id)
    tech = technique_scores(predicted_techniques, gold.techniques, lambda t: technique_tactics(live, t))
    e011, judged = evidence_precision(events)
    scores: dict[str, Any] = {
        "case": case.case_name,
        "attack_id": case.attack_id,
        "intake_status": case.intake_status,
        "terminal_state": state,
        "scored": True,
        "n_gold": len(gold.techniques),
        "n_pred": len(set(predicted_techniques)),
        "technique": tech,
        "unjustified_additions": unjustified_additions(
            log, tech["extra"], proposals or {}, spec, evidence or {}, support_judge,
            {t: (live.lookup(t, "attack-pattern").obj or {}).get("name", "") for t in tech["extra"]},
        ) if spec is not None else {"judged": False, "rate": None, "n_additions": len(tech["extra"])},
        "groups": group_scores(
            predicted_groups, gold.groups, case.groups_with_evidence,
            e011_pass_rate=e011, judge_attribution=judged,
        ),
        "retriever": retriever_scores(events, gold.techniques),
    }
    baselines: dict[str, Any] = {}
    if case.twin_baseline_id:
        twin = prf(set(live.software_techniques(case.twin_baseline_id)), set(gold.techniques))
        baselines["copy_twin"] = {"id": case.twin_baseline_id, **twin}
    else:
        baselines["copy_twin"] = None
    baselines["model_only"] = None
    if model_only is not None and spec is not None:
        try:
            ids, meta = model_only(spec, evidence or {}, case.domain)
            valid = {t for t in ids if live.lookup(t, "attack-pattern").obj is not None}
            baselines["model_only"] = {
                **prf(set(ids), set(gold.techniques)), "n_invalid_ids": len(set(ids) - valid),
                "model": meta.get("model"),
            }
            if log is not None:
                log.event("merge", kind="eval_baseline", baseline="model_only", **meta)
        except Exception as exc:  # noqa: BLE001 - a baseline failure must not lose the scores
            baselines["model_only"] = {"error": f"{type(exc).__name__}: {exc}", "f1": None}
            if log is not None:
                log.event("merge", kind="eval_baseline", baseline="model_only", error=str(exc))
    scores["baselines"] = baselines
    f1 = tech["exact"]["f1"]
    twin_f1 = (baselines["copy_twin"] or {}).get("f1")
    scores["beats_copy_twin_f1"] = None if f1 is None or twin_f1 is None else f1 > twin_f1
    mo_f1 = (baselines["model_only"] or {}).get("f1")
    scores["beats_model_only_f1"] = None if f1 is None or mo_f1 is None else f1 > mo_f1
    return scores


def make_scorer(
    case: EvalCase,
    *,
    datasets_dir: Path,
    support_judge: SupportJudge | None = None,
    model_only: ModelOnly | None = None,
) -> EvalScorer:
    """Build the ``eval_scorer`` hook ``run.map_software`` calls just before finalizing."""

    def scorer(log: RunLog, inp: ScoringInput) -> dict[str, Any]:
        if inp.state in UNSCORED_STATES:
            # the mapper never got to answer: record why instead of scoring an empty mapping as 0
            scores = {
                "case": case.case_name, "attack_id": case.attack_id, "intake_status": case.intake_status,
                "terminal_state": inp.state, "scored": False, "reason": inp.state, "error": inp.error,
            }
            log.write_artifact("scores.json", scores)
            return scores
        outcome = inp.outcome
        minted = outcome is not None and outcome.state == "minted" and inp.state == "minted"
        tids, gids = predicted_from_mapping(outcome.techniques, outcome.groups) if minted and outcome else ([], [])
        scores = score_run(
            case,
            datasets_dir=datasets_dir,
            predicted_techniques=tids,
            predicted_groups=gids,
            events=read_events(log.run_dir),
            state=inp.state,
            log=log,
            spec=inp.spec,
            evidence=inp.evidence,
            proposals=inp.proposals,
            support_judge=support_judge,
            model_only=model_only,
        )
        log.write_artifact("scores.json", scores)
        return scores

    return scorer


# --------------------------------------------------------------------------- evidence lock (D17)


def load_score_module() -> Any:
    """Import ``evals/score.py`` (the LangChain-bound eval pieces) by path.

    It lives outside ``src/`` on purpose: this module must stay LangChain-free (acceptance 13).
    """
    import importlib.util

    path = EVALS_DIR / "score.py"
    spec = importlib.util.spec_from_file_location("mitre_mapper_evals_score", path)
    if spec is None or spec.loader is None:
        raise EvalError(f"cannot load {path}")
    import sys

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # pydantic resolves the module's forward references through it
    spec.loader.exec_module(module)
    return module


def evidence_license(url: str | None) -> str:
    """US-government works are public domain and may be committed; everything else is gitignored."""
    host = re.sub(r"^[a-z]+://", "", (url or "").lower()).split("/", 1)[0].split(":")[0]
    if any(host == h or host.endswith("." + h) for h in _US_GOV_HOSTS):
        return PUBLIC_DOMAIN_US_GOV
    return NOT_REDISTRIBUTED


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_lock(case: EvalCase) -> list[dict[str, Any]]:
    try:
        data = json.loads(case.lock_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise EvalError(
            f"{case.case_name}: {case.lock_path} is missing; run `mitre-mapper eval freeze --case {case.case_name}`"
        ) from None
    except (OSError, ValueError) as exc:
        raise EvalError(f"{case.case_name}: unreadable {case.lock_path}: {exc}") from exc
    if not isinstance(data, list):
        raise EvalError(f"{case.case_name}: {case.lock_path} must be a JSON list")
    return data


def _intake(case: EvalCase) -> IntakeSpec:
    try:
        return parse_intake(case.intake_path)
    except IntakeError as exc:
        raise EvalError(f"{case.case_name}: invalid intake {case.intake_path}: {exc}") from exc


def verify_lock(case: EvalCase) -> Path:
    """Offline check that the frozen evidence is exactly what the lock says; return the evidence dir.

    Every intake reference needs a lock entry; every ``ok`` entry needs its file with the locked
    sha256. Anything else is a clear error telling the user to run ``eval freeze``.
    """
    lock = {e.get("source_name"): e for e in read_lock(case)}
    problems: list[str] = []
    for ref in _intake(case).references:
        entry = lock.get(ref.source_name)
        if entry is None:
            problems.append(f"{ref.source_name!r}: not in {LOCK_NAME}")
            continue
        if not entry.get("ok"):
            continue  # a source that could not be frozen stays unavailable (logged as a fetch failure)
        path = case.evidence_dir / f"{slug(ref.source_name)}.txt"
        if not path.is_file():
            problems.append(f"{ref.source_name!r}: frozen text {path.name} is missing")
        elif _sha256(path.read_bytes()) != entry.get("sha256"):
            problems.append(f"{ref.source_name!r}: {path.name} does not match the locked sha256")
    if problems:
        raise EvalError(
            f"{case.case_name}: frozen evidence is not usable ({'; '.join(problems)}). "
            f"Run `mitre-mapper eval freeze --case {case.case_name}` (add --update to accept changed content)."
        )
    return case.evidence_dir


@dataclass
class FreezeResult:
    case: str
    entries: list[dict[str, Any]] = field(default_factory=list)
    drift: list[str] = field(default_factory=list)  # human-readable, only without --update
    warnings: list[str] = field(default_factory=list)  # a locked source failed to refetch; kept as locked
    written: bool = False


def freeze_case(
    case: EvalCase,
    *,
    update: bool = False,
    timeout: float = 30.0,
    fetcher: Callable[..., Any] = fetch_reference,
    cache_dir: Path | None = None,
) -> FreezeResult:
    """The ONLY networked eval step. Fetch every intake reference, write the text and the lock.

    Hash drift (a locked source now hashes differently or no longer fetches) is an error unless
    ``update``: nothing is written for the case until the user accepts it.
    """
    spec = _intake(case)
    try:
        old = {e["source_name"]: e for e in read_lock(case)}
    except EvalError:
        old = {}
    tmp_cache = Path(tempfile.mkdtemp(prefix="mitre-mapper-freeze-")) if cache_dir is None else cache_dir
    result = FreezeResult(case.case_name)
    pending: dict[str, str] = {}
    try:
        for ref in spec.references:
            res = fetcher(ref, cache_dir=tmp_cache, use_cache=False, timeout=timeout)
            prev = old.get(ref.source_name)
            if res.ok and res.text is not None:
                text = res.text.replace("\r\n", "\n").replace("\r", "\n")
                data = text.encode("utf-8")
                digest = _sha256(data)
                if prev and prev.get("ok") and prev.get("sha256") == digest:
                    result.entries.append(prev)  # unchanged: keep the lock line byte-stable
                    pending[ref.source_name] = text
                    continue
                if prev and prev.get("ok") and not update:
                    result.drift.append(f"{ref.source_name!r}: content changed since it was locked")
                    result.entries.append(prev)
                    continue
                result.entries.append({
                    "source_name": ref.source_name, "url": ref.url, "sha256": digest, "chars": len(text),
                    "fetched_at": _now(), "ok": True, "error": None, "license": evidence_license(ref.url),
                })
                pending[ref.source_name] = text
            else:
                if prev and prev.get("ok"):
                    # Never let a transient failure replace a good frozen copy, even with --update.
                    msg = f"{ref.source_name!r}: locked, but now fails to fetch ({res.error}); kept as locked"
                    (result.warnings if update else result.drift).append(msg)
                    result.entries.append(prev)
                    continue
                result.entries.append({
                    "source_name": ref.source_name, "url": ref.url, "sha256": None, "chars": 0,
                    "fetched_at": _now(), "ok": False, "error": res.error, "license": evidence_license(ref.url),
                })
    finally:
        if cache_dir is None:
            shutil.rmtree(tmp_cache, ignore_errors=True)
    if result.drift:
        return result
    case.evidence_dir.mkdir(parents=True, exist_ok=True)
    for name, text in pending.items():
        (case.evidence_dir / f"{slug(name)}.txt").write_bytes(text.encode("utf-8"))
    case.lock_path.write_text(json.dumps(result.entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    result.written = True
    return result


# --------------------------------------------------------------------------- running cases


@dataclass
class CaseResult:
    case: EvalCase
    record: RunRecord | None
    scores: dict[str, Any] | None
    run_dir: Path | None = None
    label: str | None = None  # set for reviewed runs

    @property
    def name(self) -> str:
        return self.label or self.case.case_name


Mapper = Callable[..., RunRecord]


def run_case(
    case: EvalCase,
    *,
    model: Any,
    judge_model: Any | None,
    runs_dir: Path,
    datasets_dir: Path,
    mapper: Mapper | None = None,
    support_judge: SupportJudge | None = None,
    model_only: ModelOnly | None = None,
    max_attempts: int = 3,
    max_model_calls: int = 60,
    **mapper_kwargs: Any,
) -> CaseResult:
    """One case, fully offline: frozen evidence, held-out store, scored on finalize.

    Eval runs mint into a throwaway copy of ``allocations.json`` so they never touch the real
    SX/GX registry.
    """
    evidence_dir = verify_lock(case)
    if mapper is None:
        from mitre_mapper.run import map_software as mapper  # lazy: the CLI normally passes it
    holdout = get_holdout(case.holdout)
    with tempfile.TemporaryDirectory(prefix="mitre-mapper-eval-") as tmp:
        alloc = Path(tmp) / "allocations.json"
        real = Path(datasets_dir) / "allocations.json"
        alloc.write_text(real.read_text(encoding="utf-8") if real.is_file() else "{}", encoding="utf-8")
        record = mapper(
            case.intake_path,
            model=model,
            judge_model=judge_model,
            runs_dir=runs_dir,
            datasets_dir=datasets_dir,
            max_attempts=max_attempts,
            max_model_calls=max_model_calls,
            allocations_path=alloc,
            fetch=False,  # no network, ever, during eval
            evidence_dir=evidence_dir,
            holdout=holdout,
            eval_case=case.case_name,
            eval_scorer=make_scorer(case, datasets_dir=Path(datasets_dir), support_judge=support_judge,
                                    model_only=model_only),
            **mapper_kwargs,
        )
    run_dir = Path(runs_dir) / record.run_id
    return CaseResult(case, record, record.eval_scores, run_dir)


def rich_vs_thin(results: Sequence[CaseResult]) -> list[dict[str, Any]]:
    """For every thin case with a scored rich counterpart: the gap evidence buys (rich minus thin)."""
    by_name = {r.case.case_name: r for r in results if r.scores}
    out: list[dict[str, Any]] = []
    for r in results:
        if not (r.case.thin_of and r.scores and r.case.thin_of in by_name):
            continue
        rich = by_name[r.case.thin_of].scores or {}
        thin = r.scores

        def gap(path: tuple[str, ...]) -> float | None:
            a: Any = rich
            b: Any = thin
            for k in path:
                a = (a or {}).get(k) if isinstance(a, dict) else None
                b = (b or {}).get(k) if isinstance(b, dict) else None
            return None if a is None or b is None else round(a - b, 4)

        out.append({
            "rich": r.case.thin_of, "thin": r.case.case_name,
            "recall_exact": gap(("technique", "exact", "recall")),
            "recall_parent_lenient": gap(("technique", "parent_lenient", "recall")),
            "recall_tactic": gap(("technique", "tactic", "recall")),
            "f1": gap(("technique", "exact", "f1")),
        })
    return out


# --------------------------------------------------------------------------- reviewed runs


def score_reviews(runs_dir: Path, datasets_dir: Path) -> list[CaseResult]:
    """Score reviewed runs (``review.json``) as extra cases. Ground truth = the user's verdict.

    gold = accepted + missed items; predicted = the run's minted mapping. Writes
    ``review_scores.json`` in the run folder (``scores.json`` stays the eval run's own).
    """
    out: list[CaseResult] = []
    for review_path in sorted(Path(runs_dir).glob("*/review.json")):
        run_dir = review_path.parent
        try:
            review = Review.model_validate_json(review_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        events = read_events(run_dir)
        start = next((e for e in events if e.get("event") == "run_start"), {})
        mint = next((e for e in reversed(events) if e.get("event") == "mint"), None)
        domains = next((e["domains"] for e in reversed(events) if e.get("event") == "domain_resolved"), [])
        if not domains:
            continue
        gold_t = sorted({t for t, v in review.techniques.items() if v == "accepted"} | set(review.missed_techniques))
        gold_g = sorted({g for g, v in review.groups.items() if v == "accepted"} | set(review.missed_groups))
        pred_t, pred_g = (
            predicted_from_mapping(mint.get("techniques") or {}, mint.get("groups") or {}) if mint else ([], [])
        )
        stores = [get_store(datasets_dir).domain(d) for d in domains]

        def tactics_of(t: str, stores: list[DomainStore] = stores) -> set[str]:
            return set().union(*(technique_tactics(s, t) for s in stores))

        e011, judged = evidence_precision(events)
        scores = {
            "case": f"review:{run_dir.name}",
            "source": "review",
            "software": start.get("software_name"),
            "terminal_state": next((e.get("terminal_state") for e in reversed(events) if e.get("event") == "run_end"), None),
            "n_gold": len(gold_t),
            "n_pred": len(set(pred_t)),
            "technique": technique_scores(pred_t, gold_t, tactics_of),
            "groups": group_scores(pred_g, gold_g, gold_g, e011_pass_rate=e011, judge_attribution=judged),
            "retriever": retriever_scores(events, gold_t),
        }
        (run_dir / "review_scores.json").write_text(json.dumps(scores, indent=2) + "\n", encoding="utf-8")
        case = EvalCase(
            case_name=f"review:{run_dir.name}", intake="-", intake_status="user", domain=domains[0],
            attack_id="-", holdout="-",
        )
        out.append(CaseResult(case, None, scores, run_dir, label=f"review:{run_dir.name}"))
    return out


# --------------------------------------------------------------------------- rendering


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def _f(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def draft_warning(case: EvalCase) -> str | None:
    if not case.is_draft:
        return None
    return (
        f"WARNING: the intake for case {case.case_name!r} is a DRAFT written by Claude "
        f"({case.intake}). Rewrite it in your own words before trusting this score."
    )


def render_case(res: CaseResult) -> str:
    s = res.scores
    lines = [f"== {res.name}" + (f"  [run {res.record.run_id}]" if res.record else "")]
    w = draft_warning(res.case)
    if w:
        lines.append("  " + w)
    if not s:
        lines.append("  no scores (run did not reach the scorer)")
        return "\n".join(lines)
    if s.get("scored") is False:
        lines.append(f"  not scored: {s['reason']} ({s.get('error') or 'no message'})")
        return "\n".join(lines)
    t = s["technique"]
    lines.append(f"  terminal state: {s['terminal_state']}   gold {s['n_gold']} / predicted {s['n_pred']}")
    lines.append(
        "  technique recall: exact {} (P {} F1 {}) | parent-lenient {} | tactic {}".format(
            _pct(t["exact"]["recall"]), _f(t["exact"]["precision"]), _f(t["exact"]["f1"]),
            _pct(t["parent_lenient"]["recall"]), _pct(t["tactic"]["recall"]),
        )
    )
    ua = s.get("unjustified_additions") or {}
    lines.append(
        "  unjustified additions: {} ({} additions{})".format(
            _pct(ua.get("rate")), ua.get("n_additions", 0), "" if ua.get("judged") else "; no judge model"
        )
    )
    g = s["groups"]
    lines.append(
        "  group recall: vs ATT&CK {} ({}/{}) | vs evidence {} ({} with evidence) | E011 pass {} | judge attribution {}".format(
            _pct(g["recall_all"]), len(set(g["pred"]) & set(g["gold"])), len(g["gold"]),
            _pct(g["recall_evidence"]), len(g["groups_with_evidence"]),
            _pct(g["precision_e011"]), _pct(g["precision_judge"]),
        )
    )
    r = s["retriever"]
    lines.append(
        "  retriever recall: union {} | @5 {} @10 {} @25 {} ({} searches, {} zero-hit)".format(
            _pct(r["union_recall"]), _pct(r["recall_at"]["5"]), _pct(r["recall_at"]["10"]),
            _pct(r["recall_at"]["25"]), r["n_searches"], r["zero_hit_searches"],
        )
    )
    b = s.get("baselines") or {}
    twin = b.get("copy_twin")
    mo = b.get("model_only")
    lines.append(
        "  baseline copy-twin {}: {}".format(
            twin["id"] if twin else "-",
            "n/a" if not twin else f"P {_f(twin['precision'])} R {_f(twin['recall'])} F1 {_f(twin['f1'])}",
        )
    )
    lines.append(
        "  baseline model-only: "
        + (
            "n/a (no model)" if not mo
            else f"error ({mo['error']})" if "error" in mo
            else f"P {_f(mo['precision'])} R {_f(mo['recall'])} F1 {_f(mo['f1'])}"
        )
    )
    verdict = s.get("beats_copy_twin_f1")
    if verdict is not None:
        lines.append(f"  pipeline F1 {'BEATS' if verdict else 'does NOT beat'} the copy-twin baseline")
    return "\n".join(lines)


def render_gaps(gaps: Sequence[dict[str, Any]]) -> str:
    lines = []
    for g in gaps:
        lines.append(
            "rich-vs-thin gap ({rich} - {thin}): exact recall {e} | parent-lenient {p} | tactic {t} | F1 {f}".format(
                rich=g["rich"], thin=g["thin"],
                e=_signed(g["recall_exact"]), p=_signed(g["recall_parent_lenient"]),
                t=_signed(g["recall_tactic"]), f=_signed(g["f1"], 2),
            )
        )
    return "\n".join(lines)


def _signed(x: float | None, digits: int = 0) -> str:
    if x is None:
        return "n/a"
    return f"{x * 100:+.0f} pts" if digits == 0 else f"{x:+.2f}"
