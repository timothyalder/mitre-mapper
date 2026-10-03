"""Independent judge for agent-proposed mappings (PLAN 3.6, D2, D6).

Pure: ``judge`` returns data and raises :class:`ProviderError` (provider failures) or
:class:`JudgeOutputError` (the model answered but not with a parseable ``Verdict``);
``run.py`` does the logging and treats the latter as a failed judge attempt.
User-asserted items are removed before the prompt is built, so the model never sees them.

LangChain API (langchain-core 1.6.6, verified): ``model.with_structured_output(Verdict,
include_raw=True)`` binds ``Verdict`` as a forced tool (``bind_tools([Verdict], tool_choice="any")``)
and parses the first tool call with ``PydanticToolsParser``. The result is
``{"raw": AIMessage, "parsed": Verdict | None, "parsing_error": Exception | None}``. Token usage comes
from ``raw.usage_metadata``. A fake model must therefore answer with one tool call named ``Verdict``
whose args are ``{"approved", "items": [{"name", "passed", "rationale"}], "summary"}``.

``approved`` from the model is never trusted: it is recomputed as "all four rubric items present and
passed". A missing item counts as a failed item.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from mitre_mapper.models import IntakeSpec, MappingProposal, RubricItem, Verdict
from mitre_mapper.runlog import ProviderError

REPO_ROOT = Path(__file__).resolve().parents[2]
RUBRIC_PATH = REPO_ROOT / "skills" / "map-software" / "references" / "judge-rubric.md"
RUBRIC_ITEMS = ("evidence_grounding", "technique_specificity", "omission_check", "group_attribution")

MAX_CHARS_PER_SOURCE = 20_000
MAX_CHARS_TOTAL = 80_000


class JudgeOutputError(Exception):
    """The judge model returned output that is not a parseable ``Verdict``.

    Carries the (zero-or-more) tokens/latency already spent so the caller can still
    charge the budget.
    """

    def __init__(
        self, message: str, *, tokens_in: int = 0, tokens_out: int = 0, latency_s: float = 0.0,
        prompt_sha256: str = "",
    ) -> None:
        super().__init__(message)
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.latency_s = latency_s
        self.prompt_sha256 = prompt_sha256


@dataclass
class JudgeResult:
    verdict: Verdict
    tokens_in: int
    tokens_out: int
    latency_s: float
    prompt_sha256: str


def load_rubric(path: Path = RUBRIC_PATH) -> str:
    return path.read_text(encoding="utf-8")


def agent_proposed(proposal: MappingProposal) -> MappingProposal:
    """Copy of ``proposal`` with every user-asserted item removed."""
    return proposal.model_copy(
        update={
            "techniques": [t for t in proposal.techniques if not t.user_asserted],
            "groups": [g for g in proposal.groups if not g.user_asserted],
        }
    )


def _has_agent_content(p: MappingProposal) -> bool:
    return bool(
        p.techniques or p.groups or p.declined or getattr(p, "unmatched_actors", None)
    )


def _render_evidence(evidence: dict[str, str]) -> str:
    if not evidence:
        return "(no evidence text was available)"
    parts: list[str] = []
    budget = MAX_CHARS_TOTAL
    for name, text in evidence.items():
        cap = min(MAX_CHARS_PER_SOURCE, max(budget, 0))
        shown = text[:cap]
        budget -= len(shown)
        note = ""
        if len(shown) < len(text):
            note = (
                f"\n[TRUNCATED: showing the first {len(shown)} of {len(text)} characters; "
                "the rest was not provided to you]"
            )
        parts.append(f"### Source: {name}\n<<<\n{shown}\n>>>{note}")
    return "\n\n".join(parts)


def build_messages(
    proposal: MappingProposal, spec: IntakeSpec, evidence: dict[str, str], rubric: str
) -> list[Any]:
    """System rubric + human message with intake summary, agent-proposed items, evidence."""
    p = agent_proposed(proposal)
    intake = [f"Name: {spec.name}", f"Type: {spec.type}"]
    if spec.aliases:
        intake.append("Aliases: " + ", ".join(spec.aliases))
    if spec.platforms:
        intake.append("Platforms: " + ", ".join(spec.platforms))
    if spec.body.strip():
        intake.append("Description:\n" + spec.body.strip())
    human = (
        f"ATT&CK domain: {p.domain}\n\n## Software\n"
        + "\n".join(intake)
        + "\n\n## Agent-proposed mapping (JSON)\n"
        + p.model_dump_json(indent=2)
        + "\n\n## Evidence text\nLong sources are truncated and marked as such.\n\n"
        + _render_evidence(evidence)
        + "\n\nReturn your per-item verdict now."
    )
    return [SystemMessage(content=rubric), HumanMessage(content=human)]


def _finalize(verdict: Verdict) -> Verdict:
    by_name = {i.name: i for i in verdict.items}
    items = list(verdict.items)
    for name in RUBRIC_ITEMS:
        if name not in by_name:
            items.append(
                RubricItem(name=name, passed=False, rationale="judge returned no verdict for this item")
            )
    approved = all(by_name[n].passed if n in by_name else False for n in RUBRIC_ITEMS)
    return Verdict(approved=approved, items=items, summary=verdict.summary)


def _approved_without_model() -> Verdict:
    return Verdict(
        approved=True,
        items=[
            RubricItem(name=n, passed=True, rationale="no agent-proposed items to judge")
            for n in RUBRIC_ITEMS
        ],
        summary="Nothing agent-proposed; judge not called.",
    )


def judge(
    proposal: MappingProposal,
    spec: IntakeSpec,
    evidence: dict[str, str],
    model: str | BaseChatModel,
) -> JudgeResult:
    """Judge the agent-proposed part of ``proposal``. Raises ProviderError on provider failure, JudgeOutputError on unparseable output."""
    p = agent_proposed(proposal)
    if not _has_agent_content(p):
        return JudgeResult(_approved_without_model(), 0, 0, 0.0, "")
    messages = build_messages(proposal, spec, evidence, load_rubric())
    prompt_sha = hashlib.sha256(
        "\n".join(str(m.content) for m in messages).encode("utf-8")
    ).hexdigest()
    start = time.perf_counter()
    try:
        if isinstance(model, str):
            from langchain.chat_models import init_chat_model

            model = init_chat_model(model)
        out = model.with_structured_output(Verdict, include_raw=True).invoke(messages)
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError(f"{type(exc).__name__}: {exc}") from exc
    latency = time.perf_counter() - start
    parsed = out.get("parsed")
    usage = getattr(out.get("raw"), "usage_metadata", None) or {}
    if not isinstance(parsed, Verdict):
        raise JudgeOutputError(
            f"judge returned unparseable output: {out.get('parsing_error')!r}",
            tokens_in=int(usage.get("input_tokens", 0)),
            tokens_out=int(usage.get("output_tokens", 0)),
            latency_s=latency,
            prompt_sha256=prompt_sha,
        )
    return JudgeResult(
        verdict=_finalize(parsed),
        tokens_in=int(usage.get("input_tokens", 0)),
        tokens_out=int(usage.get("output_tokens", 0)),
        latency_s=latency,
        prompt_sha256=prompt_sha,
    )


def replay_judge(
    run_dir: Path,
    domain: str,
    attempt: int,
    model: str | BaseChatModel,
    *,
    evidence_dir: Path | None = None,
) -> JudgeResult:
    """Re-run the judge on ``<run_dir>/<domain>/proposal_<attempt>.json``."""
    from mitre_mapper.intake import parse_intake

    run_dir = Path(run_dir)
    proposal = MappingProposal.model_validate_json(
        (run_dir / domain / f"proposal_{attempt}.json").read_text(encoding="utf-8")
    )
    spec = parse_intake(run_dir / "intake.md")
    ev_dir = evidence_dir if evidence_dir is not None else run_dir / "evidence"
    evidence: dict[str, str] = {}
    if ev_dir.is_dir():
        for f in sorted(ev_dir.glob("*.txt")):
            evidence[f.stem] = f.read_text(encoding="utf-8")
    try:  # evidence files are named by slug(source_name); restore source names when possible
        from mitre_mapper.fetch import slug

        names = {slug(r.source_name): r.source_name for r in spec.references}
        evidence = {names.get(k, k): v for k, v in evidence.items()}
    except Exception:  # fetch.py may be absent or slug may differ
        pass
    return judge(proposal, spec, evidence, model)
