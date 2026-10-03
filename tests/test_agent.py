"""agent.py: wiring, exception propagation out of langgraph, recursion limit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fakes import ScriptedChatModel, looping_search_model, proposal_msg, tool_call_msg
from mitre_mapper import agent as A
from mitre_mapper import tools as T
from mitre_mapper.intake import parse_intake
from mitre_mapper.models import MappingProposal
from mitre_mapper.runlog import Budget, BudgetExhausted, ProviderError, RunLog

FIXTURE = Path(__file__).parent / "fixtures" / "pegasus-ios.md"
MSGS = [{"role": "user", "content": "go"}]


def make(tmp_path, attack_store, model, max_calls=5):
    log = RunLog.start(
        tmp_path / "runs",
        software_name="t",
        intake_text_or_path=FIXTURE,
        model="m",
        judge_model=None,
        prompt_text="p",
        budget=Budget(max_model_calls=max_calls),
    )
    ctx = T.ToolContext(
        log=log, store=attack_store, domain="mobile-attack", spec=parse_intake(FIXTURE)
    )
    return log, A.build_agent(model, ctx, "system prompt")


def test_structured_proposal_and_tool_logging(tmp_path, attack_store):
    prop = {"domain": "mobile-attack", "declined": True, "decline_rationale": "x"}
    model = ScriptedChatModel(
        script=[tool_call_msg("search_techniques", {"query": "sms"}), proposal_msg(prop)]
    )
    log, agent = make(tmp_path, attack_store, model)
    out = A.invoke_agent(agent, MSGS)
    assert isinstance(out, MappingProposal) and out.declined
    assert log.budget.n_calls == 2 and log.budget.tokens_in == 20
    names = [json.loads(l)["event"] for l in log.events_path.read_text().splitlines()]
    assert "search" in names and "tool_call" in names
    cfg = next(
        e for e in map(json.loads, log.events_path.read_text().splitlines()) if e.get("kind") == "agent_config"
    )
    assert cfg["recursion_limit"] == A.recursion_limit_for(5)


def test_budget_exhausted_propagates_unwrapped(tmp_path, attack_store):
    _, agent = make(tmp_path, attack_store, looping_search_model(), max_calls=3)
    with pytest.raises(BudgetExhausted):
        A.invoke_agent(agent, MSGS)


def test_provider_error_propagates_unwrapped(tmp_path, attack_store):
    model = ScriptedChatModel(script=[ValueError("auth failed")])
    _, agent = make(tmp_path, attack_store, model)
    with pytest.raises(ProviderError) as ei:
        A.invoke_agent(agent, MSGS)
    assert "auth failed" in ei.value.message


def test_recursion_limit_becomes_budget_exhausted(tmp_path, attack_store):
    _, agent = make(tmp_path, attack_store, looping_search_model(), max_calls=1000)
    agent.recursion_limit = 6  # force the graph limit below the budget
    with pytest.raises(BudgetExhausted, match="recursion"):
        A.invoke_agent(agent, MSGS)


def test_no_structured_output_raises_agent_output_error(tmp_path, attack_store):
    from langchain_core.messages import AIMessage

    model = ScriptedChatModel(script=[AIMessage(content="I give up")])
    _, agent = make(tmp_path, attack_store, model)
    with pytest.raises(A.AgentOutputError):
        A.invoke_agent(agent, MSGS)
