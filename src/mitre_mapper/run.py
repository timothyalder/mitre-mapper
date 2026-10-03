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

from langchain_core.language_models.chat_models import BaseChatModel

from mitre_mapper.agent import AgentOutputError, build_agent, invoke_agent
from mitre_mapper.allocations import Allocations
from mitre_mapper.intake import IntakeError, parse_intake, resolve_domains
from mitre_mapper.judge import JudgeOutputError, JudgeResult, judge
from mitre_mapper.models import (
    IntakeSpec,
    LintFinding,
    MappingProposal,
    RubricItem,
    RunRecord,
    Severity,
    Verdict,
)
from mitre_mapper.runlog import Budget, BudgetExhausted, ProviderError, RunLog, run_context
from mitre_mapper.session import (  # the shared core (also driven by the MCP server)
    DEFAULT_CACHE_DIR,
    DEFAULT_SKILL_PATH,
    LINT_FAILED_ATTEMPTS,
    EvalScorer,
    MappingOutcome,
    ScoringInput,
    complete_mapping,
    gather_intake_evidence,
    load_system_prompt,
    log_no_structured_output,
    log_unmatched_actors,
    process_proposal,
    render_pinned,
    render_retry_message,
)
from mitre_mapper.holdout import HoldoutSpec
from mitre_mapper.store import AttackStore, get_store
from mitre_mapper.tools import ToolContext, now_stix

JUDGE_OUTPUT_INVALID = "judge_output_invalid"


def _model_name(model: str | BaseChatModel) -> str:
    if isinstance(model, str):
        return model
    return str(getattr(model, "model_name", None) or type(model).__name__)


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


def _first_message(
    spec: IntakeSpec,
    domain: str,
    evidence: dict[str, str],
    feedback: str | None,
    prev: MappingProposal | None = None,
) -> str:
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
    pinned = render_pinned(spec)
    if pinned:
        parts.append(pinned)
    if feedback:
        parts.append(render_retry_message(feedback, prev))
    return "\n\n".join(parts)


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
            message = _first_message(spec, domain, evidence, feedback, prev)
            raw = invoke_agent(agent, [{"role": "user", "content": message}])
        except AgentOutputError as exc:
            log_no_structured_output(log, domain, attempt, str(exc))
            feedback = "You did not call the MappingProposal tool. Finish by calling it."
            last_failure = "lint_failed"
            continue
        res = process_proposal(
            ctx, raw, attempt=attempt, prev=prev, retry_reason=retry_reason, created=created
        )
        proposal = res.proposal
        last_proposal = proposal
        if res.has_errors:
            prev = proposal
            feedback = render_feedback(res.findings)
            last_failure = "lint_failed"
            retry_reason = res.error_reason
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
    holdout: HoldoutSpec | None = None,
    eval_case: str | None = None,
    eval_scorer: EvalScorer | None = None,
) -> RunRecord:
    """Map one intake file to a delta. Always returns the finalized ``RunRecord``.

    ``judge_model=None`` skips the judge (logged once as ``merge``/``judge_config``).
    ``evidence_dir`` is frozen mode: evidence is read only from there, never the network.

    Eval mode (PLAN 4): ``holdout`` hides the answer from the store (the diff is logged as a
    ``merge`` kind=holdout event), ``eval_case`` lands on the run_start event and index row, and
    ``eval_scorer`` is called just before finalization (also on budget/provider failures) so its
    scores land on the index row. An eval run is otherwise an ordinary run.
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
        eval_case=eval_case,
        budget=budget,
        manifest_path=datasets_dir / "MANIFEST.json",
        allocations_path=allocations_path,
    ) as log:
        if spec is None:
            log.event("intake_invalid", errors=intake_errors)
            log.finalize("error", error="invalid intake: " + "; ".join(intake_errors))
            return _record(runs_dir, log)

        domains: list[str] = list(resolve_domains(spec))
        accepted: dict[str, MappingProposal] = {}
        evidence: dict[str, str] = {}
        outcome: MappingOutcome | None = None

        def finish(state: str, error: str | None) -> None:
            """Finalize, first letting the eval scorer (if any) compute scores. Never loses run_end."""
            scores: dict[str, Any] | None = None
            if eval_scorer is not None:
                try:
                    scores = eval_scorer(
                        log,
                        ScoringInput(
                            state=state, error=error, spec=spec, evidence=evidence, domains=domains,
                            outcome=outcome, proposals=dict(accepted),
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 - a scorer bug must not lose the run
                    log.event("error", type=type(exc).__name__, message=f"eval scorer failed: {exc}")
            log.finalize(state, error=error, eval_scores=scores)

        try:
            log.event("domain_resolved", domains=domains)
            evidence.update(
                gather_intake_evidence(
                    log,
                    spec,
                    cache_dir=Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR,
                    evidence_dir=Path(evidence_dir) if evidence_dir else None,
                    fetch=fetch,
                    use_cache=use_cache,
                    timeout=fetch_timeout,
                )
            )
            log.event(
                "merge",
                kind="judge_config",
                judge=_model_name(judge_model) if judge_model is not None else None,
                note=None if judge_model is not None else "no judge model configured; judge skipped",
            )
            store = get_store(datasets_dir, holdout)
            if holdout is not None:
                for domain in domains:  # the diff the agent is blind to, logged for the improvement loop
                    report = store.domain(domain).holdout_report
                    if report is not None:
                        log.event("merge", kind="holdout", **report.to_event())
            allocations = Allocations(allocations_path)
            created = now_stix()

            failed_state: str | None = None
            for domain in domains:
                ctx = ToolContext(
                    log=log, store=store, domain=domain, spec=spec, evidence=evidence, allocations=allocations
                )
                agent = build_agent(model, ctx, system_prompt)
                dom_outcome, proposal = _attempt_domain(
                    log=log, ctx=ctx, agent=agent, spec=spec, store=store, allocations=allocations,
                    domain=domain, max_attempts=max_attempts, created=created, judge_model=judge_model,
                )
                if dom_outcome in ("accepted", "declined") and proposal is not None:
                    accepted[domain] = proposal  # a declined one is kept only if user-asserted items revive it
                    log_unmatched_actors(log, domain, proposal)
                else:
                    failed_state = dom_outcome
                    break

            if failed_state is not None:
                finish(
                    failed_state,
                    LINT_FAILED_ATTEMPTS
                    if failed_state == "lint_failed"
                    else "attempts exhausted; the judge rejected the last lint-clean proposal",
                )
                return _record(runs_dir, log)

            outcome = complete_mapping(
                log, spec=spec, store=store, allocations=allocations, evidence=evidence, domains=domains,
                accepted=accepted, created=created, datasets_dir=datasets_dir,
            )
            finish(outcome.state, outcome.error)
        except (BudgetExhausted, ProviderError) as exc:
            if eval_scorer is None or log.finalized:
                raise  # run_context logs and finalizes exactly as for any run
            if isinstance(exc, BudgetExhausted):
                log.event("budget_exhausted", message=str(exc), **log.budget.snapshot())
                finish("budget_exhausted", str(exc))
            else:
                log.event("provider_error", message=exc.message)
                finish("provider_error", exc.message)
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
