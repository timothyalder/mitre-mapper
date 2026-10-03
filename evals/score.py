"""LangChain-bound pieces of the eval harness: the unjustified-addition support judge and the
no-retrieval, model-only baseline.

Loaded by path (``evaluate.load_score_module``) so ``src/mitre_mapper/evaluate.py`` stays free of
LangChain imports (acceptance criterion 13). Both builders return plain callables that
``evaluate.score_run`` injects; both return ``(value, meta)`` where ``meta`` (model, tokens,
latency) is logged on the run as a ``merge`` event, because eval model calls sit outside the
run's own budget.
"""

from __future__ import annotations

import time
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from mitre_mapper.llm import resolve_model
from mitre_mapper.models import IntakeSpec, MappingProposal, TechniqueMapping

MAX_CHARS_PER_SOURCE = 12_000
MAX_CHARS_TOTAL = 60_000
INTAKE_SOURCE = "mitre-mapper intake description"


class SupportItem(BaseModel):
    technique_id: str
    supported: bool
    rationale: str


class SupportVerdicts(BaseModel):
    items: list[SupportItem]


SUPPORT_SYSTEM = """You audit ATT&CK technique mappings for malware and tools.
For each proposed technique you receive the quotes the mapper cited. Decide ONE thing: does the
cited evidence (the quotes, read in the context of the source text provided) support that this
software uses that technique? Judge only from the text shown. Do not use your own knowledge of
the software and do not reward a technique for being plausible. A quote that is about something
else, or that is only loosely related, does not support the technique. Answer with one item per
technique id."""

MODEL_ONLY_SYSTEM = """You map software to MITRE ATT&CK techniques. You have no tools and no search.
Use only the intake description and the evidence text below (plus your general knowledge) and answer
with a MappingProposal for the given ATT&CK domain. Use real ATT&CK technique ids (T#### or
T####.###). Quote evidence verbatim where you can. Do not propose groups unless a quote names both
the software and the group."""


def _chat(model: Any) -> Any:
    return resolve_model(model)


def _model_name(model: Any) -> str:
    return model if isinstance(model, str) else str(getattr(model, "model_name", None) or type(model).__name__)


def _usage(raw: Any) -> tuple[int, int]:
    u = getattr(raw, "usage_metadata", None) or {}
    return int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))


def _render_sources(evidence: dict[str, str], only: set[str] | None = None) -> str:
    parts: list[str] = []
    budget = MAX_CHARS_TOTAL
    for name, text in evidence.items():
        if only is not None and name not in only:
            continue
        shown = text[: min(MAX_CHARS_PER_SOURCE, max(budget, 0))]
        budget -= len(shown)
        note = "" if len(shown) == len(text) else f"\n[TRUNCATED at {len(shown)} of {len(text)} chars]"
        parts.append(f"### Source: {name}\n<<<\n{shown}\n>>>{note}")
    return "\n\n".join(parts) or "(no evidence text was available)"


def build_support_judge(judge_model: Any) -> Any:
    """``SupportJudge``: per added technique, does the cited evidence support it?"""

    def support_judge(
        spec: IntakeSpec,
        evidence: dict[str, str],
        additions: list[TechniqueMapping],
        names: dict[str, str],
    ) -> tuple[dict[str, tuple[bool, str]], dict[str, Any]]:
        cited = {e.source_name for t in additions for e in t.evidence}
        pool = {**evidence, INTAKE_SOURCE: spec.body}
        blocks = []
        for t in additions:
            quotes = "\n".join(f'  - [{e.source_name}] "{e.quote}"' for e in t.evidence) or "  - (no quote cited)"
            blocks.append(
                f"Technique {t.technique_id} {names.get(t.technique_id, '')}\n"
                f"Mapper rationale: {t.rationale}\nCited quotes:\n{quotes}"
            )
        human = (
            f"Software: {spec.name} ({spec.type})\n\n## Proposed techniques\n" + "\n\n".join(blocks)
            + "\n\n## Source text\n" + _render_sources(pool, cited | {INTAKE_SOURCE})
        )
        t0 = time.perf_counter()
        out = _chat(judge_model).with_structured_output(SupportVerdicts, include_raw=True).invoke(
            [SystemMessage(content=SUPPORT_SYSTEM), HumanMessage(content=human)]
        )
        latency = time.perf_counter() - t0
        parsed = out.get("parsed")
        tin, tout = _usage(out.get("raw"))
        meta = {"model": _model_name(judge_model), "tokens_in": tin, "tokens_out": tout, "latency_s": round(latency, 3)}
        if not isinstance(parsed, SupportVerdicts):
            raise ValueError(f"support judge returned unparseable output: {out.get('parsing_error')!r}")
        return {i.technique_id: (i.supported, i.rationale) for i in parsed.items}, meta

    return support_judge


def build_model_only(model: Any) -> Any:
    """``ModelOnly``: intake + evidence in, technique ids out, no tools and no retrieval."""

    def model_only(spec: IntakeSpec, evidence: dict[str, str], domain: str) -> tuple[list[str], dict[str, Any]]:
        human = (
            f"ATT&CK domain: {domain}\nName: {spec.name}\nType: {spec.type}\n"
            f"Aliases: {', '.join(spec.aliases) or 'none'}\nPlatforms: {', '.join(spec.platforms) or 'unspecified'}\n\n"
            f"## Intake description\n{spec.body.strip() or '(none)'}\n\n## Evidence\n{_render_sources(evidence)}"
        )
        t0 = time.perf_counter()
        out = _chat(model).with_structured_output(MappingProposal, include_raw=True).invoke(
            [SystemMessage(content=MODEL_ONLY_SYSTEM), HumanMessage(content=human)]
        )
        latency = time.perf_counter() - t0
        parsed = out.get("parsed")
        tin, tout = _usage(out.get("raw"))
        meta = {"model": _model_name(model), "tokens_in": tin, "tokens_out": tout, "latency_s": round(latency, 3)}
        if not isinstance(parsed, MappingProposal):
            raise ValueError(f"model-only baseline returned unparseable output: {out.get('parsing_error')!r}")
        return sorted({t.technique_id for t in parsed.techniques}), meta

    return model_only
