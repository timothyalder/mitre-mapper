"""LangChain wiring: ``create_agent`` over :mod:`mitre_mapper.tools`.

Thin adapter only. Logging and business rules live in the core; the single
middleware here forwards per-turn stats to ``RunLog.model_call`` (budget) and
normalises provider failures to :class:`runlog.ProviderError`.

Measured at Wave 2 (langchain 1.4.3 / langgraph 1.2.12):

* ``ToolStrategy(MappingProposal)`` registers an artificial tool named
  ``MappingProposal`` whose arguments are the proposal fields.
* ``BudgetExhausted`` / ``ProviderError`` raised inside ``wrap_model_call`` propagate
  out of ``graph.invoke`` unwrapped (tests pin this); ``GraphRecursionError`` is
  converted to ``BudgetExhausted`` in :func:`invoke_agent`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, ModelRequest, ModelResponse
from langchain.agents.structured_output import StructuredOutputError, ToolStrategy
from langchain.chat_models import init_chat_model
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphRecursionError

from mitre_mapper import tools as T
from mitre_mapper.models import MappingProposal
from mitre_mapper.runlog import BudgetExhausted, ProviderError, RunLog

# Each model call costs ~2 graph steps (model + tools). The budget must fire first,
# so the graph limit is deliberately looser than 2 * max_model_calls.
RECURSION_PER_MODEL_CALL = 2
RECURSION_SLACK = 10


class AgentOutputError(Exception):
    """The agent finished without producing a structured MappingProposal."""


def recursion_limit_for(max_model_calls: int) -> int:
    return RECURSION_PER_MODEL_CALL * max_model_calls + RECURSION_SLACK


class RunLogMiddleware(AgentMiddleware):  # type: ignore[type-arg]
    """Forward per-turn tokens/latency to the run log; normalise provider errors."""

    def __init__(self, log: RunLog) -> None:
        super().__init__()
        self.log = log

    def wrap_model_call(  # type: ignore[override]
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], ModelResponse],
    ) -> ModelResponse:
        t0 = time.monotonic()
        try:
            response = handler(request)
        except (BudgetExhausted, ProviderError, StructuredOutputError):
            raise
        except Exception as exc:  # noqa: BLE001 - everything else is a provider failure
            latency = time.monotonic() - t0
            self._record(0, 0, latency)
            raise ProviderError(f"{type(exc).__name__}: {exc}") from exc
        tokens_in = tokens_out = 0
        for msg in response.result:
            if isinstance(msg, AIMessage) and msg.usage_metadata:
                tokens_in += int(msg.usage_metadata.get("input_tokens", 0))
                tokens_out += int(msg.usage_metadata.get("output_tokens", 0))
        self._record(tokens_in, tokens_out, time.monotonic() - t0)
        return response

    def _record(self, tokens_in: int, tokens_out: int, latency: float) -> None:
        # May raise BudgetExhausted; on the failure path don't mask the provider error.
        self.log.model_call(tokens_in, tokens_out, latency)


@dataclass
class BuiltAgent:
    """A compiled agent plus the deliberate recursion limit it must be invoked with."""

    graph: Any
    recursion_limit: int


def _langchain_tools(ctx: T.ToolContext) -> list[StructuredTool]:
    """One StructuredTool per tools.py function, bound to ``ctx``."""

    def search_techniques(query: str, k: int = 10) -> dict[str, Any]:
        """Keyword (BM25) search over active techniques in the current domain."""
        return T.search_techniques(ctx, query=query, k=k)

    def get_technique(attack_id: str) -> dict[str, Any]:
        """Get one technique by ATT&CK id, e.g. T1430 or T1636.002."""
        return T.get_technique(ctx, attack_id=attack_id)

    def search_groups(query: str, k: int = 10) -> dict[str, Any]:
        """Keyword search over existing ATT&CK groups (names and aliases)."""
        return T.search_groups(ctx, query=query, k=k)

    def get_group(attack_id: str) -> dict[str, Any]:
        """Get one existing ATT&CK group by id (G0035) or by name/alias (Carbon Spider)."""
        return T.get_group(ctx, attack_id=attack_id)

    def search_software(query: str, k: int = 10) -> dict[str, Any]:
        """Keyword search over existing ATT&CK malware and tools."""
        return T.search_software(ctx, query=query, k=k)

    def get_software(attack_id: str) -> dict[str, Any]:
        """Get one existing malware/tool by id, e.g. S0316."""
        return T.get_software(ctx, attack_id=attack_id)

    def get_software_techniques(attack_id: str) -> dict[str, Any]:
        """List techniques ATT&CK maps for an existing software id."""
        return T.get_software_techniques(ctx, attack_id=attack_id)

    def get_evidence(source_name: str, offset: int = 0, max_chars: int = 8000) -> dict[str, Any]:
        """Return a window of the fetched evidence text for a reference source_name.

        Long evidence is paged: use the returned next_offset as offset to read on.
        """
        return T.get_evidence(ctx, source_name=source_name, offset=offset, max_chars=max_chars)

    def read_reference(name: str) -> dict[str, Any]:
        """Read a reference document: linter-rules.md or stix-shapes.md."""
        return T.read_reference(ctx, name=name)

    fns = (
        search_techniques,
        get_technique,
        search_groups,
        get_group,
        search_software,
        get_software,
        get_software_techniques,
        get_evidence,
        read_reference,
    )
    return [StructuredTool.from_function(f, name=f.__name__) for f in fns]


def build_agent(
    model: str | BaseChatModel, ctx: T.ToolContext, system_prompt: str
) -> BuiltAgent:
    """Compile the mapping agent. Logs the recursion limit it will run with."""
    chat = init_chat_model(model) if isinstance(model, str) else model
    graph = create_agent(
        chat,
        tools=_langchain_tools(ctx),
        system_prompt=system_prompt,
        response_format=ToolStrategy(MappingProposal),
        middleware=[RunLogMiddleware(ctx.log)],
    )
    limit = recursion_limit_for(ctx.log.budget.max_model_calls)
    # No dedicated event exists for this; ``merge`` is the closest free-form event.
    ctx.log.event(
        "merge",
        kind="agent_config",
        domain=ctx.domain,
        recursion_limit=limit,
        max_model_calls=ctx.log.budget.max_model_calls,
        structured_output_tool="MappingProposal",
    )
    return BuiltAgent(graph=graph, recursion_limit=limit)


def invoke_agent(agent: BuiltAgent, messages: list[dict[str, str]]) -> MappingProposal:
    """Run the agent to a structured proposal.

    Raises ``BudgetExhausted`` / ``ProviderError`` (from the middleware) unwrapped,
    ``BudgetExhausted`` on recursion-limit overflow, ``AgentOutputError`` if the
    agent ended without a proposal.
    """
    try:
        state = agent.graph.invoke(
            {"messages": messages}, config={"recursion_limit": agent.recursion_limit}
        )
    except GraphRecursionError as exc:
        raise BudgetExhausted(f"graph recursion limit {agent.recursion_limit} hit: {exc}") from exc
    proposal = state.get("structured_response")
    if not isinstance(proposal, MappingProposal):
        raise AgentOutputError("agent ended without calling the MappingProposal tool")
    return proposal
