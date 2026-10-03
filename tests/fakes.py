"""Scripted fake chat model for default (non-live) tests (PLAN D22).

``GenericFakeChatModel`` has no ``bind_tools``, so this replays a list of
``AIMessage`` objects (tool calls, then the final structured-output call) and
reports ``usage_metadata`` so budget accounting works.

Structured output via ``ToolStrategy(MappingProposal)``: langchain registers an
artificial tool named ``MappingProposal`` (the class name) whose arguments are the
proposal's fields. The final scripted message is therefore a tool call
``{"name": "MappingProposal", "args": {<proposal dict>}}`` -- see :func:`proposal_msg`.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Sequence
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import PrivateAttr

_ids = itertools.count(1)


def tool_call_msg(name: str, args: dict[str, Any], *, tokens: tuple[int, int] = (10, 5)) -> AIMessage:
    """An AIMessage requesting one tool call."""
    msg = AIMessage(
        content="",
        tool_calls=[{"name": name, "args": args, "id": f"call_{next(_ids)}", "type": "tool_call"}],
    )
    msg.usage_metadata = {
        "input_tokens": tokens[0],
        "output_tokens": tokens[1],
        "total_tokens": sum(tokens),
    }
    return msg


def proposal_msg(proposal: dict[str, Any]) -> AIMessage:
    """The final structured-output tool call ToolStrategy(MappingProposal) expects."""
    return tool_call_msg("MappingProposal", proposal)


class ScriptedChatModel(BaseChatModel):
    """Replays ``script`` in order.

    Items: an ``AIMessage``, or an ``Exception`` instance (raised, simulating a
    provider error). After the script is exhausted: if ``loop`` is set it is called
    to produce endless messages (budget-kill tests), else ``IndexError``.
    """

    script: list[Any] = []
    loop: Callable[[], AIMessage] | None = None
    model_name: str = "scripted-fake"

    _cursor: int = PrivateAttr(default=0)
    _seen: list[list[BaseMessage]] = PrivateAttr(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted-fake"

    @property
    def n_calls(self) -> int:
        return self._cursor

    @property
    def seen_messages(self) -> list[list[BaseMessage]]:
        return self._seen

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ScriptedChatModel:  # type: ignore[override]
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self._seen.append(list(messages))
        if self._cursor < len(self.script):
            item = self.script[self._cursor]
        elif self.loop is not None:
            item = self.loop()
        else:
            raise IndexError("ScriptedChatModel script exhausted")
        self._cursor += 1
        if isinstance(item, BaseException):
            raise item
        msg = item.model_copy(deep=True)
        if msg.usage_metadata is None:
            msg.usage_metadata = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        return ChatResult(generations=[ChatGeneration(message=msg)])


def looping_search_model() -> ScriptedChatModel:
    """Never finishes: searches forever (kills the run via budget)."""
    return ScriptedChatModel(
        loop=lambda: tool_call_msg("search_techniques", {"query": "spyware", "k": 3})
    )
