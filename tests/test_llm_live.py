"""Live smoke for ``claude-code:`` models (needs the ``claude`` CLI logged in; run with ``-m live``)."""

from __future__ import annotations

import os

import pytest
from langchain.agents import create_agent
from langchain.agents.structured_output import ToolStrategy
from langchain_core.messages import HumanMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from mitre_mapper.llm import resolve_model
from mitre_mapper.models import Verdict

pytestmark = pytest.mark.live
MODEL = os.environ.get("MITRE_MAPPER_LIVE_CLAUDE_CODE_MODEL", "claude-code:claude-sonnet-5-5")


def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


class Result(BaseModel):
    """Final answer."""

    total: int


def test_bind_tools_round_trip():
    pytest.importorskip("claude_code_langchain")
    model = resolve_model(MODEL).bind_tools([StructuredTool.from_function(add, name="add")], tool_choice="any")
    out = model.invoke([HumanMessage(content="What is 17 + 25? Use the add tool.")])
    assert out.tool_calls and out.tool_calls[0]["name"] == "add"
    assert out.tool_calls[0]["args"] == {"a": 17, "b": 25}
    assert out.usage_metadata and out.usage_metadata["input_tokens"] > 0


def test_agent_with_toolstrategy_round_trip():
    pytest.importorskip("claude_code_langchain")
    agent = create_agent(
        resolve_model(MODEL),
        tools=[StructuredTool.from_function(add, name="add")],
        system_prompt="Use the add tool for arithmetic, then give the final answer.",
        response_format=ToolStrategy(Result),
    )
    state = agent.invoke({"messages": [{"role": "user", "content": "What is 17 + 25?"}]})
    assert state["structured_response"].total == 42


def test_with_structured_output_verdict():
    pytest.importorskip("claude_code_langchain")
    out = resolve_model(MODEL).with_structured_output(Verdict, include_raw=True).invoke(
        [HumanMessage(content=(
            "Fill in a verdict: approved=false, one item named evidence_grounding with passed=false "
            "and rationale 'quotes absent', summary 'rejected'."
        ))]
    )
    assert isinstance(out["parsed"], Verdict), out
    assert out["parsed"].approved is False and out["parsed"].items[0].name == "evidence_grounding"
