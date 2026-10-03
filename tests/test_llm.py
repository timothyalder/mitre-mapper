"""PromptedToolCallingModel / resolve_model, against a scripted inner model (no network)."""

from __future__ import annotations

from typing import Any

import pytest
from langchain.agents import create_agent
from langchain.agents.structured_output import ToolStrategy
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, PrivateAttr

from mitre_mapper import llm
from mitre_mapper.llm import PromptedToolCallingModel, extract_json_objects, parse_reply, resolve_model
from mitre_mapper.models import Verdict


class TextInner(BaseChatModel):
    """Tool-less chat model: replays text replies, records the prompts it saw."""

    replies: list[str] = []
    usage_in_metadata: bool = False
    _i: int = PrivateAttr(default=0)
    _prompts: list[list[BaseMessage]] = PrivateAttr(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "text-inner"

    @property
    def prompts(self) -> list[list[BaseMessage]]:
        return self._prompts

    def _generate(self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **kw: Any) -> ChatResult:
        self._prompts.append(list(messages))
        text = self.replies[self._i]
        self._i += 1
        usage = {"input_tokens": 100, "cache_read_input_tokens": 50, "output_tokens": 7}
        if self.usage_in_metadata:
            msg = AIMessage(content=text, usage_metadata={"input_tokens": 3, "output_tokens": 4, "total_tokens": 7})
        else:
            msg = AIMessage(content=text, response_metadata={"usage": usage})
        return ChatResult(generations=[ChatGeneration(message=msg)])


def echo(text: str) -> str:
    """Echo text back."""
    return text


ECHO = StructuredTool.from_function(echo, name="echo")


def shim(*replies: str, **kw: Any) -> tuple[PromptedToolCallingModel, TextInner]:
    inner = TextInner(replies=list(replies), **kw)
    return PromptedToolCallingModel(inner=inner, model_name="t"), inner


def test_extract_json_objects_tolerates_fences_prose_and_braces_in_strings():
    text = 'Sure!\n```json\n{"content": "a } b { c"}\n```\nthen {"x": {"y": 1}} and {broken'
    assert extract_json_objects(text) == [{"content": "a } b { c"}, {"x": {"y": 1}}]


def test_parse_reply_shapes():
    content, calls = parse_reply('{"tool_calls":[{"name":"echo","args":{"text":"hi"}}]}', ["echo"], require_tool=False)
    assert content == "" and calls == [{"name": "echo", "args": {"text": "hi"}, "id": "call_0", "type": "tool_call"}]
    assert parse_reply('{"content":"done"}', ["echo"], require_tool=False) == ("done", [])
    # a bare {"name","args"} is accepted as one call; args given as a JSON string are decoded
    _, calls = parse_reply('{"name":"echo","args":"{\\"text\\":\\"x\\"}"}', ["echo"], require_tool=False)
    assert calls[0]["args"] == {"text": "x"}
    with pytest.raises(llm.ToolProtocolError):
        parse_reply('{"tool_calls":[{"name":"nope","args":{}}]}', ["echo"], require_tool=False)
    with pytest.raises(llm.ToolProtocolError):
        parse_reply('{"content":"x"}', ["echo"], require_tool=True)
    with pytest.raises(llm.ToolProtocolError):
        parse_reply("no json here", ["echo"], require_tool=False)


def test_bind_tools_roundtrip_with_prose_around_json_and_usage_mapping():
    m, inner = shim('Here you go: ```json\n{"tool_calls":[{"name":"echo","args":{"text":"hi"}}]}\n```')
    out = m.bind_tools([ECHO]).invoke([SystemMessage(content="BASE"), HumanMessage(content="go")])
    assert out.tool_calls == [{"name": "echo", "args": {"text": "hi"}, "id": "call_0", "type": "tool_call"}]
    assert out.usage_metadata == {"input_tokens": 150, "output_tokens": 7, "total_tokens": 157}
    system, human = inner.prompts[0]
    assert isinstance(system, SystemMessage) and system.content.startswith("BASE")
    assert '"name":"echo"' in system.content and "tool_calls" in system.content
    assert "go" in human.content


def test_usage_metadata_from_inner_is_preferred():
    m, _ = shim('{"content":"ok"}', usage_in_metadata=True)
    out = m.invoke([HumanMessage(content="x")])
    assert out.usage_metadata["input_tokens"] == 3 and out.content == "ok"


def test_transcript_renders_prior_tool_calls_and_results():
    m, inner = shim('{"content":"done"}')
    history = [
        HumanMessage(content="start"),
        AIMessage(content="", tool_calls=[{"name": "echo", "args": {"text": "a"}, "id": "c1", "type": "tool_call"}]),
        ToolMessage(content="RESULT-A", tool_call_id="c1", name="echo"),
    ]
    m.bind_tools([ECHO]).invoke(history)
    human = inner.prompts[0][1].content
    assert '"tool_calls"' in human and '"text": "a"' in human
    assert "RESULT-A" in human and "id=c1" in human and human.rstrip().endswith("protocol.")


def test_required_tool_choice_repairs_once_then_succeeds():
    m, inner = shim('{"content":"i refuse to call tools"}', '{"tool_calls":[{"name":"echo","args":{"text":"x"}}]}')
    out = m.bind_tools([ECHO], tool_choice="any").invoke([HumanMessage(content="x")])
    assert out.tool_calls[0]["name"] == "echo"
    assert len(inner.prompts) == 2 and "INVALID" in inner.prompts[1][1].content
    assert out.response_metadata["prompted_tools"]["repairs"] == 1
    assert out.usage_metadata["input_tokens"] == 300  # both calls are charged


def test_unparseable_twice_degrades_to_plain_content():
    m, inner = shim("garbage one", "garbage two")
    out = m.bind_tools([ECHO], tool_choice="any").invoke([HumanMessage(content="x")])
    assert out.tool_calls == [] and out.content == "garbage two"
    assert out.response_metadata["prompted_tools"]["protocol_failure"]
    assert len(inner.prompts) == 2  # exactly one repair


def test_unknown_tool_triggers_repair():
    m, _ = shim('{"tool_calls":[{"name":"nope","args":{}}]}', '{"content":"fine"}')
    out = m.bind_tools([ECHO]).invoke([HumanMessage(content="x")])
    assert out.content == "fine" and out.response_metadata["prompted_tools"]["repairs"] == 1


def test_named_tool_choice_accepts_bare_args_object():
    m, _ = shim('{"text": "bare"}')
    out = m.bind_tools([ECHO], tool_choice="echo").invoke([HumanMessage(content="x")])
    assert out.tool_calls[0]["args"] == {"text": "bare"}


def test_with_structured_output_verdict():
    reply = (
        '{"tool_calls":[{"name":"Verdict","args":{"approved":true,"summary":"s","items":'
        '[{"name":"evidence_grounding","passed":true,"rationale":"r"}]}}]}'
    )
    m, inner = shim(reply)
    out = m.with_structured_output(Verdict, include_raw=True).invoke([HumanMessage(content="judge")])
    assert isinstance(out["parsed"], Verdict) and out["parsed"].items[0].name == "evidence_grounding"
    assert out["raw"].usage_metadata["input_tokens"] == 150
    assert "You MUST call a tool" in inner.prompts[0][0].content


class Answer(BaseModel):
    """Final answer."""

    value: str


def test_create_agent_toolstrategy_end_to_end():
    m, inner = shim(
        '{"tool_calls":[{"name":"echo","args":{"text":"ping"}}]}',
        '{"tool_calls":[{"name":"Answer","args":{"value":"pong"}}]}',
    )
    agent = create_agent(m, tools=[ECHO], system_prompt="SYS", response_format=ToolStrategy(Answer))
    state = agent.invoke({"messages": [{"role": "user", "content": "go"}]})
    assert state["structured_response"] == Answer(value="pong")
    second = inner.prompts[1][1].content  # the echoed tool result was shown to the model
    assert "ping" in second and "tool result for echo" in second


def test_resolve_model_passthrough_and_strings(monkeypatch: pytest.MonkeyPatch):
    inner = TextInner()
    assert resolve_model(inner) is inner
    seen: list[str] = []
    import langchain.chat_models as cm

    monkeypatch.setattr(cm, "init_chat_model", lambda s: seen.append(s) or inner)
    assert resolve_model("openai:gpt-x") is inner and seen == ["openai:gpt-x"]


def test_resolve_claude_code_scheme_wraps_in_prompted_model():
    pytest.importorskip("claude_code_langchain")
    m = resolve_model("claude-code:claude-haiku-4-5-20251001")
    assert isinstance(m, PromptedToolCallingModel)
    assert m.model_name == "claude-code:claude-haiku-4-5-20251001"
    assert m.inner.model_name == "claude-haiku-4-5-20251001"
    opts = m.inner._get_claude_options([HumanMessage(content="x")])
    assert opts.extra_args == {"tools": "", "setting-sources": ""} and opts.max_turns == 1
    assert opts.cwd and "mitre-mapper-claude-" in str(opts.cwd)
