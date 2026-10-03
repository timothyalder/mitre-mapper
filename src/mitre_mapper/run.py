"""The outer loop: ``map_software`` (PLAN 3.8).

Thin orchestration only. Lint rules, STIX shapes, id policy and event
definitions live in the core; this module decides what to call and in what order,
and guarantees the run always finalizes (``runlog.run_context``).

Wave 2 slice: no evidence fetch (``evidence == {}``) and no judge. The judge hook
is marked ``JUDGE HOOK`` below.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import frontmatter
from langchain_core.language_models.chat_models import BaseChatModel

from mitre_mapper.agent import AgentOutputError, build_agent, invoke_agent
from mitre_mapper.allocations import Allocations
from mitre_mapper.intake import IntakeError, parse_intake, resolve_domains
from mitre_mapper.lint import has_errors
from mitre_mapper.mint import build_objects
from mitre_mapper.models import (
    Delta,
    GroupMapping,
    IntakeSpec,
    LintFinding,
    MappingProposal,
    RunRecord,
    Severity,
    TechniqueMapping,
)
from mitre_mapper.runlog import Budget, RunLog, run_context
from mitre_mapper.store import AttackStore, get_store
from mitre_mapper.tools import REPO_ROOT, ToolContext, now_stix, preview_lint

DEFAULT_SKILL_PATH = REPO_ROOT / "skills" / "map-software" / "SKILL.md"
INTAKE_SOURCE = "mitre-mapper intake"


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
) -> tuple[str, MappingProposal | None]:
    """Run the attempts loop for one domain. Returns (``accepted|declined|lint_failed``, proposal)."""
    prev: MappingProposal | None = None
    feedback: str | None = None
    retry_reason: str | None = None
    last_proposal: MappingProposal | None = None
    for attempt in range(1, max_attempts + 1):
        ctx.returned_ids.clear()
        try:
            raw = invoke_agent(agent, [{"role": "user", "content": _first_message(spec, domain, ctx.evidence, feedback)}])
        except AgentOutputError as exc:
            log.event("retry", domain=domain, attempt=attempt, reason=f"no_structured_output: {exc}", added=[], removed=[])
            feedback = "You did not call the MappingProposal tool. Finish by calling it."
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
        findings = preview_lint(spec, proposal, store, allocations, ctx.evidence, created)
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
            retry_reason = "lint_errors: " + ",".join(
                sorted({f.rule_id for f in findings if f.severity == Severity.ERROR})
            )
            continue
        # JUDGE HOOK (Wave 3D): for a lint-clean, non-declined proposal call
        # ``judge(proposal, intake, evidence)`` exactly once, write verdict_<n>.json, emit
        # ``judge_verdict``; on rejection set ``feedback`` and ``continue``.
        return ("declined" if proposal.declined else "accepted"), proposal
    return "lint_failed", last_proposal


def map_software(
    intake_path: Path | str,
    *,
    model: str | BaseChatModel,
    judge_model: str | None = None,
    runs_dir: Path | str,
    datasets_dir: Path | str,
    max_attempts: int = 3,
    max_model_calls: int = 60,
    allocations_path: Path | str | None = None,
    skill_path: Path | str = DEFAULT_SKILL_PATH,
) -> RunRecord:
    """Map one intake file to a delta. Always returns the finalized ``RunRecord``."""
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
        judge_model=judge_model,
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
        evidence: dict[str, str] = {}  # Wave 3A adds gather_evidence(); never raises.
        store = get_store(datasets_dir)
        allocations = Allocations(allocations_path)
        created = now_stix()

        accepted: dict[str, MappingProposal] = {}
        failed = False
        for domain in domains:
            ctx = ToolContext(
                log=log, store=store, domain=domain, spec=spec, evidence=evidence, allocations=allocations
            )
            agent = build_agent(model, ctx, system_prompt)
            outcome, proposal = _attempt_domain(
                log=log, ctx=ctx, agent=agent, spec=spec, store=store, allocations=allocations,
                domain=domain, max_attempts=max_attempts, created=created,
            )
            if outcome == "accepted" and proposal is not None:
                accepted[domain] = proposal
            elif outcome == "lint_failed":
                failed = True
                break
            elif outcome == "declined" and proposal is not None:
                accepted[domain] = proposal  # kept only if user-asserted items revive it

        if failed:
            log.finalize("lint_failed", error="attempts exhausted with lint ERRORs")
            return _record(runs_dir, log)

        # User-asserted items: always included, flagged, never judged.
        intake_ref = INTAKE_SOURCE
        asserted = _user_asserted_items(spec, list(accepted) or domains, store, intake_ref)
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
            log.event(
                "user_asserted",
                kind="intake",
                domain=domain,
                techniques=[t.technique_id for t in techs],
                groups=[g.group_id for g in groups],
            )
        for g in spec.groups:
            if g.new is not None:
                log.event("user_asserted", kind="new_group", name=g.new.name, note="minting deferred to Wave 3C")

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
        log.event(
            "mint",
            software_id=result.software["id"],
            n_objects=len(result.objects),
            domains=sorted(live),
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
