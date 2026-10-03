"""The outer loop: ``map_software`` (PLAN 3.8).

Thin orchestration only. Lint rules, STIX shapes, id policy and event
definitions live in the core; this module decides what to call and in what order,
and guarantees the run always finalizes (``runlog.run_context``).

Per domain: agent attempt -> ``group_quote_check`` logging -> lint -> (lint-clean only)
the judge, exactly once -> accept or retry with feedback. Evidence is gathered once, before
the domain loop, and handed to the tools, lint and the judge as ``{source_name: text}``.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import frontmatter
from langchain_core.language_models.chat_models import BaseChatModel

from mitre_mapper.agent import AgentOutputError, build_agent, invoke_agent
from mitre_mapper.allocations import Allocations
from mitre_mapper.fetch import gather_evidence
from mitre_mapper.groups import check_group_quote
from mitre_mapper.intake import IntakeError, parse_intake, resolve_domains
from mitre_mapper.judge import JudgeOutputError, JudgeResult, judge
from mitre_mapper.lint import has_errors
from mitre_mapper.mint import MintResult, build_objects
from mitre_mapper.models import (
    Delta,
    ExternalReference,
    GroupMapping,
    IntakeSpec,
    LintFinding,
    MappingProposal,
    RubricItem,
    RunRecord,
    Severity,
    TechniqueMapping,
    Verdict,
)
from mitre_mapper.runlog import Budget, BudgetExhausted, ProviderError, RunLog, run_context
from mitre_mapper.store import AttackStore, get_store
from mitre_mapper.tools import REPO_ROOT, ToolContext, now_stix, preview_lint

DEFAULT_SKILL_PATH = REPO_ROOT / "skills" / "map-software" / "SKILL.md"
INTAKE_SOURCE = "mitre-mapper intake"
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "fetch"
JUDGE_OUTPUT_INVALID = "judge_output_invalid"


def load_system_prompt(skill_path: Path = DEFAULT_SKILL_PATH) -> str:
    """The SKILL.md body (frontmatter stripped) is the system prompt."""
    return frontmatter.loads(skill_path.read_text(encoding="utf-8")).content.strip()


def _model_name(model: str | BaseChatModel) -> str:
    if isinstance(model, str):
        return model
    return str(getattr(model, "model_name", None) or type(model).__name__)


def _ids(proposal: MappingProposal) -> tuple[set[str], set[str]]:
    return {t.technique_id for t in proposal.techniques}, {g.group_id for g in proposal.groups}


def _force_agent_items_unasserted(proposal: MappingProposal, domain: str) -> MappingProposal:
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


def render_feedback(findings: Sequence[LintFinding]) -> str:
    """Render ERROR findings as a retry message for the agent."""
    errors = [f for f in findings if f.severity == Severity.ERROR]
    lines = ["Your proposal failed lint. Fix every ERROR below, then call MappingProposal again:"]
    for f in errors:
        target = f" [{f.target}]" if f.target else ""
        extra = f" details={json.dumps(f.details, default=str)}" if f.details else ""
        lines.append(f"- {f.rule_id}{target}: {f.message}{extra}")
    return "\n".join(lines)


def render_judge_feedback(verdict: Verdict) -> str:
    """Render the judge's FAILED rubric items as a retry message for the agent."""
    lines = [
        "An independent reviewer rejected your proposal. Address every failed item below, "
        "then call MappingProposal again:"
    ]
    lines += [f"- {i.name}: {i.rationale}" for i in verdict.failed_items]
    return "\n".join(lines)


def _first_message(spec: IntakeSpec, domain: str, evidence: dict[str, str], feedback: str | None) -> str:
    refs = "\n".join(
        f"- {r.source_name}" + (f" ({r.url})" if r.url else "") + (f": {r.description}" if r.description else "")
        for r in spec.references
    )
    parts = [
        f"Map this {spec.type} to ATT&CK domain `{domain}`.",
        f"Name: {spec.name}",
        f"Aliases: {', '.join(spec.aliases) or 'none'}",
        f"Platforms: {', '.join(spec.platforms) or 'unspecified'}",
        f"References:\n{refs or '- none'}",
        f"Evidence available via get_evidence: {', '.join(sorted(evidence)) or 'none'}",
        f"Intake prose:\n{spec.body.strip() or '(none)'}",
    ]
    if spec.techniques:
        parts.append(
            "The user already pinned these techniques (do not repeat them): "
            + ", ".join(spec.techniques)
        )
    if feedback:
        parts.append(feedback)
    return "\n\n".join(parts)


def _write_lint(log: RunLog, domain: str, name: str, findings: Sequence[LintFinding]) -> None:
    log.write_artifact(f"{domain}/{name}.json", [f.model_dump(mode="json") for f in findings])


def _user_asserted_items(
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


def _dataset_manifest(datasets_dir: Path) -> dict[str, Any]:
    try:
        return json.loads((datasets_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _run_judge(
    *,
    log: RunLog,
    judge_model: str | BaseChatModel,
    proposal: MappingProposal,
    spec: IntakeSpec,
    evidence: dict[str, str],
    domain: str,
    attempt: int,
) -> Verdict:
    """Call the judge once, log ``judge_verdict`` + ``verdict_<n>.json``, charge the budget.

    ``JudgeOutputError`` becomes a failed verdict (item ``judge_output_invalid``);
    ``ProviderError`` propagates (the run finalizes as ``provider_error``).
    """
    result: JudgeResult | None = None
    spent: tuple[int, int, float] = (0, 0, 0.0)
    try:
        result = judge(proposal, spec, evidence, judge_model)
    except JudgeOutputError as exc:
        verdict = Verdict(
            approved=False,
            items=[RubricItem(name=JUDGE_OUTPUT_INVALID, passed=False, rationale=str(exc))],
            summary="judge output could not be parsed",
        )
        sha, spent = exc.prompt_sha256, (exc.tokens_in, exc.tokens_out, exc.latency_s)
    except ProviderError:
        with contextlib.suppress(BudgetExhausted):  # the call happened; don't mask the real error
            log.model_call(0, 0, 0.0)
        raise
    else:
        verdict, sha = result.verdict, result.prompt_sha256
        spent = (result.tokens_in, result.tokens_out, result.latency_s)
    items = [i.model_dump(mode="json") for i in verdict.items]
    log.write_artifact(
        f"{domain}/verdict_{attempt}.json",
        {**verdict.model_dump(mode="json"), "prompt_sha256": sha, "tokens": {"in": spent[0], "out": spent[1]},
         "latency_s": round(spent[2], 3)},
    )
    log.event("judge_verdict", domain=domain, attempt=attempt, approved=verdict.approved, items=items,
              prompt_sha256=sha)
    if result is None or result.tokens_in or result.tokens_out or result.latency_s:
        log.model_call(*spent)  # after logging, so a BudgetExhausted still leaves the verdict
    return verdict


def _attempt_domain(
    *,
    log: RunLog,
    ctx: ToolContext,
    agent: Any,
    spec: IntakeSpec,
    store: AttackStore,
    allocations: Allocations,
    domain: str,
    max_attempts: int,
    created: str,
    judge_model: str | BaseChatModel | None = None,
) -> tuple[str, MappingProposal | None]:
    """Run the attempts loop for one domain.

    Returns (``accepted|declined|lint_failed|judge_rejected``, proposal). The terminal
    failure is ``judge_rejected`` only when the last failed attempt was a judge rejection.
    """
    prev: MappingProposal | None = None
    feedback: str | None = None
    retry_reason: str | None = None
    last_proposal: MappingProposal | None = None
    last_failure = "lint_failed"
    evidence = ctx.evidence
    for attempt in range(1, max_attempts + 1):
        ctx.returned_ids.clear()
        try:
            raw = invoke_agent(agent, [{"role": "user", "content": _first_message(spec, domain, evidence, feedback)}])
        except AgentOutputError as exc:
            log.event("retry", domain=domain, attempt=attempt, reason=f"no_structured_output: {exc}", added=[], removed=[])
            feedback = "You did not call the MappingProposal tool. Finish by calling it."
            last_failure = "lint_failed"
            continue
        proposal = _force_agent_items_unasserted(raw, domain)
        last_proposal = proposal
        log.write_artifact(f"{domain}/proposal_{attempt}.json", proposal)
        tech_ids, group_ids = _ids(proposal)
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
            p_t, p_g = _ids(prev)
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
        findings = preview_lint(spec, proposal, store, allocations, evidence, created)
        _write_lint(log, domain, f"lint_{attempt}", findings)
        log.event(
            "lint_result",
            domain=domain,
            attempt=attempt,
            findings=[f.model_dump(mode="json") for f in findings],
        )
        if has_errors(findings):
            prev = proposal
            feedback = render_feedback(findings)
            last_failure = "lint_failed"
            retry_reason = "lint_errors: " + ",".join(
                sorted({f.rule_id for f in findings if f.severity == Severity.ERROR})
            )
            continue
        if judge_model is not None:  # exactly one judge call per lint-clean attempt (D6)
            verdict = _run_judge(
                log=log, judge_model=judge_model, proposal=proposal, spec=spec, evidence=evidence,
                domain=domain, attempt=attempt,
            )
            if not verdict.approved:
                prev = proposal
                feedback = render_judge_feedback(verdict)
                last_failure = "judge_rejected"
                failed = [i.name for i in verdict.failed_items]
                retry_reason = (
                    JUDGE_OUTPUT_INVALID
                    if failed == [JUDGE_OUTPUT_INVALID]
                    else "judge_rejected: " + ",".join(sorted(failed))
                )
                continue
        return ("declined" if proposal.declined else "accepted"), proposal
    return last_failure, last_proposal


def _gather(
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


def _mint_payload(
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


def map_software(
    intake_path: Path | str,
    *,
    model: str | BaseChatModel,
    judge_model: str | BaseChatModel | None = None,
    runs_dir: Path | str,
    datasets_dir: Path | str,
    max_attempts: int = 3,
    max_model_calls: int = 60,
    allocations_path: Path | str | None = None,
    skill_path: Path | str = DEFAULT_SKILL_PATH,
    fetch: bool = True,
    evidence_dir: Path | str | None = None,
    use_cache: bool = True,
    fetch_timeout: float = 20.0,
    cache_dir: Path | str | None = None,
) -> RunRecord:
    """Map one intake file to a delta. Always returns the finalized ``RunRecord``.

    ``judge_model=None`` skips the judge (logged once as ``merge``/``judge_config``).
    ``evidence_dir`` is frozen mode: evidence is read only from there, never the network.
    """
    intake_path = Path(intake_path)
    datasets_dir = Path(datasets_dir)
    allocations_path = Path(allocations_path or datasets_dir / "allocations.json")
    system_prompt = load_system_prompt(Path(skill_path))

    spec: IntakeSpec | None = None
    intake_errors: list[str] = []
    try:
        spec = parse_intake(intake_path)
    except IntakeError as exc:
        intake_errors = list(exc.errors) or [str(exc)]
    intake_text: str | Path = intake_path if intake_path.is_file() else ""

    # Budget is per domain (PLAN 3.8); the cap on the run is the sum over domains.
    n_domains = len(resolve_domains(spec)) if spec else 1
    budget = Budget(max_model_calls=max_model_calls * n_domains)
    with run_context(
        runs_dir,
        software_name=spec.name if spec else intake_path.stem,
        intake_text_or_path=intake_text,
        model=_model_name(model),
        judge_model=_model_name(judge_model) if judge_model is not None else None,
        prompt_text=system_prompt,
        budget=budget,
        manifest_path=datasets_dir / "MANIFEST.json",
    ) as log:
        if spec is None:
            log.event("intake_invalid", errors=intake_errors)
            log.finalize("error", error="invalid intake: " + "; ".join(intake_errors))
            return _record(runs_dir, log)

        domains: list[str] = list(resolve_domains(spec))
        log.event("domain_resolved", domains=domains)
        evidence = _gather(
            log,
            spec,
            cache_dir=Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR,
            evidence_dir=Path(evidence_dir) if evidence_dir else None,
            fetch=fetch,
            use_cache=use_cache,
            timeout=fetch_timeout,
        )
        log.event(
            "merge",
            kind="judge_config",
            judge=_model_name(judge_model) if judge_model is not None else None,
            note=None if judge_model is not None else "no judge model configured; judge skipped",
        )
        store = get_store(datasets_dir)
        allocations = Allocations(allocations_path)
        created = now_stix()

        accepted: dict[str, MappingProposal] = {}
        failed_state: str | None = None
        for domain in domains:
            ctx = ToolContext(
                log=log, store=store, domain=domain, spec=spec, evidence=evidence, allocations=allocations
            )
            agent = build_agent(model, ctx, system_prompt)
            outcome, proposal = _attempt_domain(
                log=log, ctx=ctx, agent=agent, spec=spec, store=store, allocations=allocations,
                domain=domain, max_attempts=max_attempts, created=created, judge_model=judge_model,
            )
            if outcome in ("accepted", "declined") and proposal is not None:
                accepted[domain] = proposal  # a declined one is kept only if user-asserted items revive it
                for actor in proposal.unmatched_actors:
                    log.event(
                        "unmatched_actor",
                        domain=domain,
                        actor=actor.actor,
                        quote=actor.quote,
                        source_name=actor.source_name,
                    )
            else:
                failed_state = outcome
                break

        if failed_state is not None:
            log.finalize(
                failed_state,
                error="attempts exhausted with lint ERRORs"
                if failed_state == "lint_failed"
                else "attempts exhausted; the judge rejected the last lint-clean proposal",
            )
            return _record(runs_dir, log)

        # User-asserted items: always included, flagged, never judged.
        targets = list(accepted) or domains
        asserted = _user_asserted_items(spec, targets, store, INTAKE_SOURCE)
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
                log.event(
                    "user_asserted", kind="intake", domain=domain, techniques=[t.technique_id for t in techs]
                )
            for g in groups:
                log.event("user_asserted", kind="group_ref", domain=domain, group_id=g.group_id)
        new_groups = [g.new for g in spec.groups if g.new is not None]
        for new in new_groups:
            log.event(
                "user_asserted", kind="new_group", name=new.name, aliases=new.aliases, techniques=new.techniques
            )
        if new_groups and all(p.declined for p in accepted.values()):
            # User-defined groups are content the agent's decline cannot veto: keep one domain
            # live so they are minted (final lint E001 still applies to the software itself).
            first = targets[0]
            base = accepted.get(first) or MappingProposal(domain=first)  # type: ignore[arg-type]
            accepted[first] = base.model_copy(update={"declined": False, "decline_rationale": None})

        live = {d: p for d, p in accepted.items() if not p.declined}
        if not live:
            log.finalize("declined", error=None)
            return _record(runs_dir, log)

        # Final lint on the merged proposals (includes user-asserted items).
        final_errors = False
        for domain, proposal in live.items():
            findings = preview_lint(spec, proposal, store, allocations, evidence, created)
            _write_lint(log, domain, "lint_final", findings)
            log.event(
                "lint_result",
                domain=domain,
                attempt="final",
                phase="final",
                findings=[f.model_dump(mode="json") for f in findings],
            )
            final_errors = final_errors or has_errors(findings)
        if final_errors:
            log.finalize("lint_failed", error="final lint (with user-asserted items) has ERRORs")
            return _record(runs_dir, log)

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
        mint_techniques, mint_groups = _mint_payload(live, result, store)
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
            dataset_manifest=_dataset_manifest(datasets_dir),
            tool_version=log.header["tool_version"],
            git_sha=log.header["git_sha"],
            prompt_sha256=log.header["prompt_sha256"],
            allocations=result.allocations,
            target_domains=sorted(live),  # type: ignore[arg-type]
            objects=result.objects,
        )
        log.write_artifact("delta.json", delta)
        log.finalize("minted")
    # Reached normally, or after run_context swallowed BudgetExhausted/ProviderError
    # (it has already finalized the run); other exceptions propagate.
    return _record(runs_dir, log)


def _record(runs_dir: Path | str, log: RunLog) -> RunRecord:
    """Re-read the index row finalize() just appended for this run."""
    from mitre_mapper.runlog import read_index

    for rec in reversed(read_index(runs_dir)):
        if rec.run_id == log.run_id:
            return rec
    raise RuntimeError(f"index row for {log.run_id} not found")
