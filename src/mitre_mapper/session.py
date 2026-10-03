"""Run-session core shared by the LangChain loop (``run.py``) and the MCP server.

Everything that happens *after something proposes a mapping* lives here, so both surfaces call the
SAME functions and therefore produce identical events, artifacts, index rows and ``run.md`` (PLAN
D12, section 0):

* :func:`process_proposal` - one attempt: force ``user_asserted`` False for agent items, write
  ``proposal_<n>.json``, ``proposal_draft`` (with ``rejected_candidates``), the ``retry`` set-diff,
  ``group_quote_check``, preview lint, ``lint_<n>.json`` and ``lint_result``.
* :func:`complete_mapping` - user-asserted merge, new-group handling, final lint, the cross-domain
  merge, mint commit (allocations), ``allocation`` / ``mint`` events and ``delta.json``. It returns
  the terminal state; the caller finalizes the run.
* :class:`Session` - the MCP-side state machine (attempt counting, latest proposal per domain) built
  from those functions. ``start_session`` opens an MCP run.

No LangChain imports (acceptance criterion 13).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import frontmatter
from pydantic import ValidationError

from mitre_mapper.allocations import Allocations
from mitre_mapper.fetch import gather_evidence
from mitre_mapper.groups import check_group_quote
from mitre_mapper.intake import IntakeError, parse_intake, resolve_domains
from mitre_mapper.lint import has_errors
from mitre_mapper.mint import MintResult, build_objects
from mitre_mapper.models import (
    Delta,
    ExternalReference,
    GroupMapping,
    IntakeSpec,
    LintFinding,
    MappingProposal,
    Severity,
    TechniqueMapping,
)
from mitre_mapper.runlog import Budget, RunLog
from mitre_mapper.store import AttackStore, get_store
from mitre_mapper.tools import REPO_ROOT, ToolContext, now_stix, preview_lint

DEFAULT_SKILL_PATH = REPO_ROOT / "skills" / "map-software" / "SKILL.md"
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "fetch"
INTAKE_SOURCE = "mitre-mapper intake"
MCP_MODEL_NAME = "mcp-client"
FALLBACK_PROMPT = "mitre-mapper MCP session (skills/map-software/SKILL.md not found)"

LINT_FAILED_ATTEMPTS = "attempts exhausted with lint ERRORs"
LINT_FAILED_FINAL = "final lint (with user-asserted items) has ERRORs"


def load_system_prompt(skill_path: Path = DEFAULT_SKILL_PATH) -> str:
    """The SKILL.md body (frontmatter stripped) is the system prompt."""
    return frontmatter.loads(skill_path.read_text(encoding="utf-8")).content.strip()


def proposal_ids(proposal: MappingProposal) -> tuple[set[str], set[str]]:
    """``(technique ids, group ids)`` of a proposal."""
    return {t.technique_id for t in proposal.techniques}, {g.group_id for g in proposal.groups}


def force_agent_items_unasserted(proposal: MappingProposal, domain: str) -> MappingProposal:
    """SECURITY: only intake-derived items may carry ``user_asserted`` (they skip the judge).

    An agent that marks its own items would bypass review, so every agent-proposed
    item is forced to ``user_asserted=False``. The domain is also pinned.
    """
    return proposal.model_copy(
        update={
            "domain": domain,
            "techniques": [t.model_copy(update={"user_asserted": False}) for t in proposal.techniques],
            "groups": [g.model_copy(update={"user_asserted": False}) for g in proposal.groups],
        }
    )


def write_lint(log: RunLog, domain: str, name: str, findings: Sequence[LintFinding]) -> None:
    log.write_artifact(f"{domain}/{name}.json", [f.model_dump(mode="json") for f in findings])


def dataset_manifest(datasets_dir: Path) -> dict[str, Any]:
    try:
        return json.loads((datasets_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def gather_intake_evidence(
    log: RunLog,
    spec: IntakeSpec,
    *,
    cache_dir: Path,
    evidence_dir: Path | None,
    fetch: bool,
    use_cache: bool,
    timeout: float,
) -> dict[str, str]:
    """Fetch intake + new-group references (never raises); keep only ok text."""
    refs: dict[str, ExternalReference] = {}
    for ref in [*spec.references, *(r for g in spec.groups if g.new for r in g.new.references)]:
        refs.setdefault(ref.source_name, ref)
    results = gather_evidence(
        list(refs.values()),
        log=log,
        cache_dir=cache_dir,
        run_evidence_dir=log.run_dir / "evidence",
        evidence_dir=evidence_dir,
        fetch=fetch,
        use_cache=use_cache,
        timeout=timeout,
    )
    return {name: r.text for name, r in results.items() if r.ok and r.text is not None}


# --------------------------------------------------------------------------- one attempt


@dataclass
class AttemptResult:
    """Outcome of :func:`process_proposal`."""

    proposal: MappingProposal
    findings: list[LintFinding]
    has_errors: bool
    error_reason: str | None  # ``lint_errors: E002,...`` when has_errors, else None


def log_no_structured_output(log: RunLog, domain: str, attempt: int, reason: str) -> None:
    """An attempt that produced no valid MappingProposal (same event on both surfaces)."""
    log.event("retry", domain=domain, attempt=attempt, reason=f"no_structured_output: {reason}", added=[], removed=[])


def process_proposal(
    ctx: ToolContext,
    raw: MappingProposal,
    *,
    attempt: int,
    prev: MappingProposal | None,
    retry_reason: str | None,
    created: str,
) -> AttemptResult:
    """Log and lint one proposal attempt. ``ctx.returned_ids`` feeds ``rejected_candidates``."""
    log, spec, store, evidence = ctx.log, ctx.spec, ctx.store, ctx.evidence
    domain = ctx.domain
    assert ctx.allocations is not None
    proposal = force_agent_items_unasserted(raw, domain)
    log.write_artifact(f"{domain}/proposal_{attempt}.json", proposal)
    tech_ids, group_ids = proposal_ids(proposal)
    cited = tech_ids | group_ids
    log.event(
        "proposal_draft",
        domain=domain,
        attempt=attempt,
        technique_ids=sorted(tech_ids),
        group_ids=sorted(group_ids),
        declined=proposal.declined,
        rejected_candidates=sorted(set(ctx.returned_ids) - cited),
    )
    if prev is not None:
        p_t, p_g = proposal_ids(prev)
        log.event(
            "retry",
            domain=domain,
            attempt=attempt,
            reason=retry_reason,
            added=sorted((tech_ids | group_ids) - (p_t | p_g)),
            removed=sorted((p_t | p_g) - (tech_ids | group_ids)),
        )
    for gm in proposal.groups:
        check = check_group_quote(gm, spec, store.domain(domain), evidence)
        log.event(
            "group_quote_check",
            domain=domain,
            attempt=attempt,
            group_id=check.group_id,
            passed=check.passed,
            reason=check.reason,
            source=check.source_name,
            software_aliases_matched=check.software_aliases_matched,
            group_aliases_matched=check.group_aliases_matched,
        )
    findings = preview_lint(spec, proposal, store, ctx.allocations, evidence, created)
    write_lint(log, domain, f"lint_{attempt}", findings)
    log.event(
        "lint_result", domain=domain, attempt=attempt, findings=[f.model_dump(mode="json") for f in findings]
    )
    errors = has_errors(findings)
    reason = (
        "lint_errors: " + ",".join(sorted({f.rule_id for f in findings if f.severity == Severity.ERROR}))
        if errors
        else None
    )
    return AttemptResult(proposal, findings, errors, reason)


def log_unmatched_actors(log: RunLog, domain: str, proposal: MappingProposal) -> None:
    for actor in proposal.unmatched_actors:
        log.event(
            "unmatched_actor", domain=domain, actor=actor.actor, quote=actor.quote, source_name=actor.source_name
        )


# --------------------------------------------------------------------------- merge + mint


def user_asserted_items(
    spec: IntakeSpec, domains: list[str], store: AttackStore, intake_ref_name: str
) -> dict[str, tuple[list[TechniqueMapping], list[GroupMapping]]]:
    """Intake-pinned techniques/groups, routed to the domain that owns them."""
    out: dict[str, tuple[list[TechniqueMapping], list[GroupMapping]]] = {d: ([], []) for d in domains}

    def owner(attack_id: str, stix_type: str) -> str:
        for d in domains:
            if store.domain(d).lookup(attack_id, stix_type).obj is not None:
                return d
        return domains[0]  # unresolvable: lands in the first domain so lint E002 reports it

    for tid in spec.techniques:
        out[owner(tid, "attack-pattern")][0].append(
            TechniqueMapping(
                technique_id=tid, rationale="Asserted by the user in the intake file.", user_asserted=True
            )
        )
    for g in spec.groups:
        if g.ref:
            out[owner(g.ref, "intrusion-set")][1].append(
                GroupMapping(
                    group_id=g.ref,
                    quote="Asserted by the user in the intake file.",
                    source_name=intake_ref_name,
                    user_asserted=True,
                )
            )
    return out


def mint_payload(
    live: dict[str, MappingProposal], result: MintResult, store: AttackStore
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """The final mapping for the ``mint`` event: techniques and groups per domain."""
    techniques: dict[str, list[dict[str, Any]]] = {}
    groups: dict[str, list[dict[str, Any]]] = {}
    for domain, proposal in sorted(live.items()):
        ds = store.domain(domain)
        techniques[domain] = []
        for t in proposal.techniques:
            obj = ds.lookup(t.technique_id, "attack-pattern").obj
            sources = (
                [INTAKE_SOURCE]
                if t.user_asserted
                else list(dict.fromkeys(e.source_name for e in t.evidence))
            )
            techniques[domain].append(
                {
                    "id": t.technique_id,
                    "name": obj.get("name") if obj else None,
                    "user_asserted": t.user_asserted,
                    "sources": sources,
                }
            )
        groups[domain] = []
        for g in proposal.groups:
            obj = ds.lookup(g.group_id, "intrusion-set").obj
            groups[domain].append(
                {
                    "id": g.group_id,
                    "name": obj.get("name") if obj else None,
                    "user_asserted": g.user_asserted,
                    "kind": "existing",
                }
            )
        for o in result.by_domain.get(domain, []):
            if o.get("type") == "intrusion-set":
                groups[domain].append(
                    {
                        "id": o["external_references"][0]["external_id"],
                        "name": o.get("name"),
                        "user_asserted": True,
                        "kind": "new",
                    }
                )
    return techniques, groups


@dataclass
class MappingOutcome:
    """What :func:`complete_mapping` decided. The caller finalizes the run with ``state``/``error``."""

    state: str  # minted | declined | lint_failed
    error: str | None = None
    delta: Delta | None = None
    software_id: str | None = None  # STIX id
    software_attack_id: str | None = None  # SX####
    allocations: dict[str, str] = field(default_factory=dict)
    n_objects: int = 0
    domains: list[str] = field(default_factory=list)
    techniques: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    groups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    final_errors: dict[str, list[LintFinding]] = field(default_factory=dict)


def complete_mapping(
    log: RunLog,
    *,
    spec: IntakeSpec,
    store: AttackStore,
    allocations: Allocations,
    evidence: dict[str, str],
    domains: list[str],
    accepted: Mapping[str, MappingProposal],
    created: str,
    datasets_dir: Path,
) -> MappingOutcome:
    """Everything after the per-domain proposals are accepted: merge, final lint, mint, delta.json.

    Does NOT finalize the run; the caller does (``run.py`` directly, the MCP tools through the
    logging wrapper so the ``tool_call`` event precedes ``run_end``).
    """
    accepted = dict(accepted)
    # User-asserted items: always included, flagged, never judged.
    targets = list(accepted) or domains
    asserted = user_asserted_items(spec, targets, store, INTAKE_SOURCE)
    for domain, (techs, groups) in asserted.items():
        if not (techs or groups):
            continue
        base = accepted.get(domain) or MappingProposal(domain=domain)  # type: ignore[arg-type]
        accepted[domain] = base.model_copy(
            update={
                "declined": False,
                "decline_rationale": None,
                "techniques": [*base.techniques, *techs],
                "groups": [*base.groups, *groups],
            }
        )
        if techs:
            log.event("user_asserted", kind="intake", domain=domain, techniques=[t.technique_id for t in techs])
        for g in groups:
            log.event("user_asserted", kind="group_ref", domain=domain, group_id=g.group_id)
    new_groups = [g.new for g in spec.groups if g.new is not None]
    for new in new_groups:
        log.event("user_asserted", kind="new_group", name=new.name, aliases=new.aliases, techniques=new.techniques)
    if new_groups and all(p.declined for p in accepted.values()):
        # User-defined groups are content the agent's decline cannot veto: keep one domain
        # live so they are minted (final lint E001 still applies to the software itself).
        first = targets[0]
        base = accepted.get(first) or MappingProposal(domain=first)  # type: ignore[arg-type]
        accepted[first] = base.model_copy(update={"declined": False, "decline_rationale": None})

    live = {d: p for d, p in accepted.items() if not p.declined}
    if not live:
        return MappingOutcome("declined")

    # Final lint on the merged proposals (includes user-asserted items).
    final_errors: dict[str, list[LintFinding]] = {}
    for domain, proposal in live.items():
        findings = preview_lint(spec, proposal, store, allocations, evidence, created)
        write_lint(log, domain, "lint_final", findings)
        log.event(
            "lint_result",
            domain=domain,
            attempt="final",
            phase="final",
            findings=[f.model_dump(mode="json") for f in findings],
        )
        if has_errors(findings):
            final_errors[domain] = [f for f in findings if f.severity == Severity.ERROR]
    if final_errors:
        return MappingOutcome("lint_failed", LINT_FAILED_FINAL, final_errors=final_errors)

    log.event(
        "merge",
        kind="cross_domain",
        domains=sorted(live),
        n_techniques={d: len(p.techniques) for d, p in live.items()},
        n_groups={d: len(p.groups) for d, p in live.items()},
    )
    result = build_objects(spec, live, store, allocations, created, commit=True, run_id=log.run_id)
    names = {o["id"]: o.get("name") for o in result.objects}
    for attack_id, stix_id in sorted(result.allocations.items()):
        log.event("allocation", attack_id=attack_id, name=names.get(stix_id), stix_id=stix_id)
    mint_techniques, mint_groups = mint_payload(live, result, store)
    log.event(
        "mint",
        software_id=result.software["id"],
        n_objects=len(result.objects),
        domains=sorted(live),
        techniques=mint_techniques,
        groups=mint_groups,
    )
    delta = Delta(
        run_id=log.run_id,
        created=created,
        dataset_manifest=dataset_manifest(datasets_dir),
        tool_version=log.header["tool_version"],
        git_sha=log.header["git_sha"],
        prompt_sha256=log.header["prompt_sha256"],
        allocations=result.allocations,
        target_domains=sorted(live),  # type: ignore[arg-type]
        objects=result.objects,
    )
    log.write_artifact("delta.json", delta)
    return MappingOutcome(
        "minted",
        delta=delta,
        software_id=result.software["id"],
        software_attack_id=result.software["external_references"][0]["external_id"],
        allocations=dict(result.allocations),
        n_objects=len(result.objects),
        domains=sorted(live),
        techniques=mint_techniques,
        groups=mint_groups,
    )


# --------------------------------------------------------------------------- MCP session


class SessionError(Exception):
    """A tool was called with a run/domain that cannot serve it (returned as ``{"error": ...}``)."""


@dataclass
class DomainState:
    """Per-domain MCP attempt state."""

    ctx: ToolContext
    attempts: int = 0
    prev: MappingProposal | None = None  # last failed proposal (for the retry set-diff)
    retry_reason: str | None = None
    latest: MappingProposal | None = None  # latest submitted, lint-clean proposal
    last_failed: bool = False  # latest submission had ERRORs (or was unparseable)


class Session:
    """One open MCP run: the log, the intake, and per-domain attempt state."""

    def __init__(
        self,
        *,
        log: RunLog,
        spec: IntakeSpec,
        store: AttackStore,
        allocations: Allocations,
        evidence: dict[str, str],
        domains: list[str],
        created: str,
        datasets_dir: Path,
        max_attempts: int,
    ) -> None:
        self.log = log
        self.spec = spec
        self.store = store
        self.allocations = allocations
        self.evidence = evidence
        self.domains = domains
        self.created = created
        self.datasets_dir = datasets_dir
        self.max_attempts = max_attempts
        self.lock = threading.RLock()
        self.states: dict[str, DomainState] = {
            d: DomainState(
                ToolContext(
                    log=log, store=store, domain=d, spec=spec, evidence=evidence, allocations=allocations,
                    session=self,
                )
            )
            for d in domains
        }

    @property
    def run_id(self) -> str:
        return self.log.run_id

    def context(self, domain: str | None = None, *, any_domain: bool = False) -> ToolContext:
        """The tool context for ``domain`` (optional when the run has exactly one).

        ``any_domain=True`` is for domain-independent tools (evidence, references, mint, end).
        """
        if self.log.finalized:
            raise SessionError(f"run {self.run_id} is already closed")
        if domain is None and any_domain:
            domain = self.domains[0]
        if domain is None:
            if len(self.domains) != 1:
                raise SessionError(f"this run spans several domains; pass domain= one of {self.domains}")
            domain = self.domains[0]
        if domain not in self.states:
            raise SessionError(f"domain {domain!r} is not part of this run; choose one of {self.domains}")
        return self.states[domain].ctx

    # -- submit

    def submit(self, domain: str, raw: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, str | None] | None]:
        """Count an attempt, log + lint the proposal. Returns ``(result, finalize_request)``."""
        with self.lock:
            st = self.states[domain]
            if st.attempts >= self.max_attempts:
                return {"error": f"max_attempts ({self.max_attempts}) already used for {domain}"}, None
            st.attempts += 1
            attempt = st.attempts
            left = self.max_attempts - attempt
            try:
                parsed = MappingProposal.model_validate({**raw, "domain": domain})
            except ValidationError as exc:
                self.log.write_artifact(f"{domain}/proposal_{attempt}_invalid.json", raw)
                reason = "; ".join(
                    f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:8]
                )
                log_no_structured_output(self.log, domain, attempt, reason)
                st.last_failed = True
                result = {
                    "attempt": attempt, "max_attempts": self.max_attempts, "attempts_left": left,
                    "has_errors": True,
                    "error": f"proposal is not a valid MappingProposal: {reason}",
                }
                return result, self._exhausted(domain, left)
            res = process_proposal(
                st.ctx, parsed, attempt=attempt, prev=st.prev, retry_reason=st.retry_reason, created=self.created
            )
            st.ctx.returned_ids.clear()  # next attempt's rejected_candidates start from here
            by_sev = {
                sev: [f.model_dump(mode="json") for f in res.findings if f.severity == sev]
                for sev in (Severity.ERROR, Severity.WARN, Severity.INFO)
            }
            result: dict[str, Any] = {
                "domain": domain,
                "attempt": attempt,
                "max_attempts": self.max_attempts,
                "attempts_left": left,
                "has_errors": res.has_errors,
                "errors": by_sev[Severity.ERROR],
                "warnings": by_sev[Severity.WARN],
                "info": by_sev[Severity.INFO],
            }
            if res.has_errors:
                st.prev, st.retry_reason, st.last_failed = res.proposal, res.error_reason, True
                result["next"] = (
                    f"Fix every ERROR and call submit_proposal again ({left} attempt(s) left)."
                    if left
                    else "No attempts left."
                )
                return result, self._exhausted(domain, left)
            st.latest, st.last_failed = res.proposal, False
            pending = [d for d in self.domains if d != domain and self.states[d].latest is None]
            result["next"] = (
                f"Lint-clean. Still needed: submit_proposal for {pending}." if pending
                else "Lint-clean. Call mint_delta, or resubmit to improve (counts as an attempt)."
            )
            return result, None

    def _exhausted(self, domain: str, left: int) -> tuple[str, str | None] | None:
        """Out of attempts with the latest submission failing: close the run as ``lint_failed``."""
        if left > 0:
            return None
        self.log.event(
            "merge", kind="attempt_budget", domain=domain, attempts=self.states[domain].attempts,
            max_attempts=self.max_attempts, exhausted=True,
        )
        return ("lint_failed", LINT_FAILED_ATTEMPTS)

    # -- mint / end

    def mint(self) -> tuple[dict[str, Any], tuple[str, str | None] | None]:
        """Refuse unless every domain has a lint-clean latest proposal; else merge and mint."""
        with self.lock:
            blocking = {
                d: (
                    "latest submission has lint ERRORs; resubmit a corrected proposal"
                    if st.last_failed
                    else "no proposal submitted"
                )
                for d, st in self.states.items()
                if st.latest is None or st.last_failed
            }
            if blocking:
                return {"error": "mint_delta refused: not every domain has a lint-clean proposal",
                        "blocking": blocking}, None
            accepted = {d: st.latest for d, st in self.states.items() if st.latest is not None}
            for d, p in accepted.items():
                log_unmatched_actors(self.log, d, p)
            out = complete_mapping(
                self.log, spec=self.spec, store=self.store, allocations=self.allocations,
                evidence=self.evidence, domains=self.domains, accepted=accepted, created=self.created,
                datasets_dir=self.datasets_dir,
            )
            if out.state == "lint_failed":
                return (
                    {
                        "error": "mint_delta refused: the final lint of the merged mapping (including "
                        "user-asserted items) has ERRORs; nothing was minted and the run is closed",
                        "terminal_state": "lint_failed",
                        "errors": {d: [f.model_dump(mode="json") for f in fs] for d, fs in out.final_errors.items()},
                    },
                    ("lint_failed", out.error),
                )
            if out.state == "declined":
                return {"terminal_state": "declined", "declined": True, "run_id": self.run_id}, ("declined", None)
            return (
                {
                    "terminal_state": "minted",
                    "minted": True,
                    "run_id": self.run_id,
                    "delta_path": str(self.log.run_dir / "delta.json"),
                    "software_id": out.software_attack_id,
                    "software_stix_id": out.software_id,
                    "allocations": out.allocations,
                    "n_objects": out.n_objects,
                    "domains": out.domains,
                    "techniques": out.techniques,
                    "groups": out.groups,
                },
                ("minted", None),
            )

    def end(self, reason: str, terminal_state: str) -> tuple[dict[str, Any], tuple[str, str | None]]:
        """Close without minting. ``declined`` keeps ``error`` null (as the LangChain decline does)."""
        if terminal_state not in ("declined", "error"):
            raise SessionError("terminal_state must be 'declined' or 'error'")
        self.log.event("merge", kind="end_run", requested_state=terminal_state, reason=reason)
        return (
            {"run_id": self.run_id, "terminal_state": terminal_state},
            (terminal_state, reason if terminal_state == "error" else None),
        )


def start_session(
    intake_path: Path | str,
    *,
    runs_dir: Path | str,
    datasets_dir: Path | str,
    allocations_path: Path | str | None = None,
    max_attempts: int = 3,
    fetch: bool = True,
    evidence_dir: Path | str | None = None,
    use_cache: bool = True,
    fetch_timeout: float = 20.0,
    cache_dir: Path | str | None = None,
    skill_path: Path | str = DEFAULT_SKILL_PATH,
) -> tuple[Session | None, RunLog]:
    """Open an MCP run (``surface="mcp"``). Returns ``(session, log)``; ``session`` is None when the
    intake was invalid (the run is then already closed as ``error`` with ``intake_invalid`` logged)."""
    intake_path = Path(intake_path).expanduser()
    datasets_dir = Path(datasets_dir)
    allocations_path = Path(allocations_path or datasets_dir / "allocations.json")
    try:
        prompt = load_system_prompt(Path(skill_path))
    except OSError:
        prompt = FALLBACK_PROMPT
    spec: IntakeSpec | None = None
    errors: list[str] = []
    try:
        spec = parse_intake(intake_path)
    except IntakeError as exc:
        errors = list(exc.errors) or [str(exc)]
    log = RunLog.start(
        runs_dir,
        software_name=spec.name if spec else intake_path.stem,
        intake_text_or_path=intake_path if intake_path.is_file() else "",
        model=MCP_MODEL_NAME,
        judge_model=None,
        prompt_text=prompt,
        budget=Budget(max_model_calls=0),  # model calls are invisible over MCP; attempts are counted instead
        manifest_path=datasets_dir / "MANIFEST.json",
        surface="mcp",
    )
    if spec is None:
        log.event("intake_invalid", errors=errors)
        log.finalize("error", error="invalid intake: " + "; ".join(errors))
        return None, log
    try:
        domains: list[str] = list(resolve_domains(spec))
        log.event("domain_resolved", domains=domains)
        evidence = gather_intake_evidence(
            log, spec,
            cache_dir=Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR,
            evidence_dir=Path(evidence_dir) if evidence_dir else None,
            fetch=fetch, use_cache=use_cache, timeout=fetch_timeout,
        )
        log.event("merge", kind="judge_config", judge=None, note="no judge model configured; judge skipped")
        log.event("merge", kind="mcp_config", max_attempts=max_attempts, surface="mcp")
        session = Session(
            log=log, spec=spec, store=get_store(datasets_dir), allocations=Allocations(allocations_path),
            evidence=evidence, domains=domains, created=now_stix(), datasets_dir=datasets_dir,
            max_attempts=max_attempts,
        )
    except BaseException as exc:  # never leave a started run without run_end
        import traceback

        log.event("error", type=type(exc).__name__, message=str(exc),
                  traceback="".join(traceback.format_exception(exc, limit=-6))[-2000:])
        log.finalize("error", error=f"{type(exc).__name__}: {exc}")
        raise
    return session, log
