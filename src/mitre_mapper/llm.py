"""Model resolution and a generic tool-calling shim for chat models that have none.

``resolve_model(spec)`` is the one place a model spec becomes a ``BaseChatModel``:

* a ``BaseChatModel`` instance passes through unchanged (use ``ChatOpenAI(...)`` etc. directly);
* ``"claude-code:<model-id>"`` builds a ``ClaudeCodeChatModel`` (optional extra
  ``mitre-mapper[claude-code]``; runs on the user's Claude Code subscription via the ``claude``
  CLI) wrapped in :class:`PromptedToolCallingModel`;
* any other string goes to ``init_chat_model`` (``"anthropic:..."``, ``"openai:..."``), as before.

:class:`PromptedToolCallingModel` is provider-agnostic: it gives ANY tool-less ``BaseChatModel``
a ``bind_tools`` (and therefore ``with_structured_output`` and ``create_agent`` + ``ToolStrategy``)
by rendering the tool JSON schemas and a strict reply protocol into the system prompt, rendering
the conversation (including earlier tool calls and tool results) as text, and parsing the reply
back into ``AIMessage.tool_calls``. This is *prompted* tool calling, not native: it costs an extra
round trip on malformed output (one repair re-ask), and the model can ignore the protocol. Failures
degrade to a plain-content ``AIMessage`` that ``ToolStrategy`` / the judge already handle.

Claude Code specifics (measured against claude-code-sdk 0.0.25 + CLI 2.1.285):

* the SDK raises ``MessageParseError`` on the CLI's ``rate_limit_event`` message, so every call
  fails; :func:`_patch_sdk_parser` tolerates unknown message types (patched at runtime from here,
  never in site-packages);
* the stock adapter would run with the user's settings, CLAUDE.md and every built-in tool;
  :class:`IsolatedClaudeCodeChat` runs in an empty cwd with ``--tools ""`` and
  ``--setting-sources ""`` so the model is a plain text completer;
* usage lives in ``response_metadata["usage"]`` (not ``usage_metadata``); the shim maps it.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Sequence
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict

CLAUDE_CODE_PREFIX = "claude-code:"

PROTOCOL = """\
# Tool-calling protocol (mandatory)

You cannot call tools natively. You act by replying with exactly ONE JSON object and nothing
else (no prose before or after, no markdown fences). Two shapes are allowed:

1. Call one or more tools:
   {{"tool_calls": [{{"name": "<tool name>", "args": {{ ...arguments... }}}}]}}
2. Answer in plain text:
   {{"content": "<your answer>"}}

Rules:
- "name" must be one of the tools listed below; "args" must be a JSON object that follows that
  tool's parameter schema exactly.
- Prefer ONE tool call per reply. Tool results arrive in the next turn.
- After a tool call you will see the tool's result in the conversation; continue from there.
{choice_rule}
# Available tools (JSON Schema)

{tools}
"""

CHOICE_RULES = {
    "any": '- You MUST call a tool in this reply. A plain-text {"content": ...} reply is not allowed.\n',
    "none": '- Do NOT call any tool in this reply; answer with {"content": ...}.\n',
}


class ToolProtocolError(ValueError):
    """The model's reply did not follow the tool-calling protocol (internal; never escapes)."""


# --------------------------------------------------------------------------- parsing


def extract_json_objects(text: str) -> list[Any]:
    """Every parseable top-level JSON object in ``text``, in order.

    Tolerates code fences and prose around the object: scans for ``{`` and takes the balanced
    span (string- and escape-aware) that parses; text inside a parsed object is not rescanned.
    """
    found: list[Any] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth, in_str, esc, j = 0, False, False, i
        end = -1
        while j < n:
            ch = text[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        if end == -1:
            i += 1  # unbalanced from here; try the next brace
            continue
        try:
            found.append(json.loads(text[i : end + 1]))
            i = end + 1
        except json.JSONDecodeError:
            i += 1
    return found


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            p if isinstance(p, str) else str(p.get("text", "")) for p in content if isinstance(p, (str, dict))
        )
    return str(content)


def parse_reply(
    text: str, tool_names: Sequence[str], *, require_tool: bool, id_prefix: str = "call"
) -> tuple[str, list[dict[str, Any]]]:
    """Parse a reply into ``(content, tool_calls)``; raise :class:`ToolProtocolError` if invalid.

    ``require_tool`` (tool_choice any/named) makes a content-only reply invalid. A single bound
    tool plus a bare args object (no wrapper) is accepted when a tool is required: a common slip.
    """
    objs = [o for o in extract_json_objects(text) if isinstance(o, dict)]
    if not objs:
        raise ToolProtocolError("no JSON object found in the reply")
    names = set(tool_names)
    for obj in objs:
        raw_calls = obj.get("tool_calls")
        if raw_calls is None and "name" in obj and "args" in obj:
            raw_calls = [obj]
        if isinstance(raw_calls, list) and raw_calls:
            calls: list[dict[str, Any]] = []
            for k, rc in enumerate(raw_calls):
                if not isinstance(rc, dict) or rc.get("name") not in names:
                    raise ToolProtocolError(
                        f"unknown tool {rc.get('name') if isinstance(rc, dict) else rc!r}; "
                        f"valid tools: {sorted(names)}"
                    )
                args = rc.get("args", rc.get("arguments", {}))
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError as exc:
                        raise ToolProtocolError(f"args of {rc['name']} is not a JSON object") from exc
                if not isinstance(args, dict):
                    raise ToolProtocolError(f"args of {rc['name']} must be a JSON object")
                calls.append(
                    {"name": rc["name"], "args": args, "id": f"{id_prefix}_{k}", "type": "tool_call"}
                )
            return "", calls
        if "content" in obj:
            if require_tool:
                raise ToolProtocolError("a tool call is required but the reply was plain content")
            return _text(obj["content"]), []
    if require_tool and len(tool_names) == 1:
        return "", [{"name": tool_names[0], "args": objs[0], "id": f"{id_prefix}_0", "type": "tool_call"}]
    raise ToolProtocolError('the JSON object has neither "tool_calls" nor "content"')


# --------------------------------------------------------------------------- usage


def usage_of(message: BaseMessage) -> dict[str, int]:
    """Token usage of an inner reply, from ``usage_metadata`` or Claude Code's ``response_metadata``."""
    um = getattr(message, "usage_metadata", None)
    if um:
        tin, tout = int(um.get("input_tokens", 0)), int(um.get("output_tokens", 0))
        return {"input_tokens": tin, "output_tokens": tout, "total_tokens": tin + tout}
    raw = (getattr(message, "response_metadata", None) or {}).get("usage") or {}
    if not isinstance(raw, dict):
        return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    tin = (
        int(raw.get("input_tokens", 0) or 0)
        + int(raw.get("cache_creation_input_tokens", 0) or 0)
        + int(raw.get("cache_read_input_tokens", 0) or 0)
    )
    tout = int(raw.get("output_tokens", 0) or 0)
    return {"input_tokens": tin, "output_tokens": tout, "total_tokens": tin + tout}


# --------------------------------------------------------------------------- the shim


class PromptedToolCallingModel(BaseChatModel):
    """Give any chat model ``bind_tools`` via a prompted JSON protocol (see module docstring)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    inner: BaseChatModel
    model_name: str = ""
    tool_schemas: list[dict[str, Any]] = []
    tool_choice: str | None = None  # None/"auto" | "any" | "none" | "<tool name>"
    max_repairs: int = 1

    @property
    def _llm_type(self) -> str:
        return f"prompted-tools/{self.inner._llm_type}"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"inner": self.inner._identifying_params, "tool_choice": self.tool_choice}

    # ---- binding

    def bind_tools(  # type: ignore[override]
        self, tools: Sequence[Any], *, tool_choice: str | bool | dict[str, Any] | None = None, **kwargs: Any
    ) -> PromptedToolCallingModel:
        """Return a copy bound to ``tools``. Extra kwargs (e.g. ``ls_structured_output_format``) are ignored."""
        schemas = [convert_to_openai_tool(t) for t in tools]
        choice: str | None
        if tool_choice is True or tool_choice in ("any", "required"):
            choice = "any"
        elif isinstance(tool_choice, dict):
            choice = str((tool_choice.get("function") or tool_choice).get("name") or "any")
        elif isinstance(tool_choice, str) and tool_choice not in ("auto",):
            choice = tool_choice
        else:
            choice = None
        return self.model_copy(update={"tool_schemas": schemas, "tool_choice": choice})

    # ---- rendering

    @property
    def _tool_names(self) -> list[str]:
        return [s["function"]["name"] for s in self.tool_schemas]

    def _required_tools(self) -> list[str] | None:
        """Names the reply must pick from, or None when a plain reply is fine."""
        if self.tool_choice == "any":
            return self._tool_names
        if self.tool_choice and self.tool_choice not in ("none",):
            return [self.tool_choice]
        return None

    def render_system(self, base: str) -> str:
        tools = "\n".join(
            json.dumps(
                {
                    "name": s["function"]["name"],
                    "description": s["function"].get("description", ""),
                    "parameters": s["function"].get("parameters", {}),
                },
                separators=(",", ":"),
            )
            for s in self.tool_schemas
        ) or "(none)"
        rule = CHOICE_RULES.get(self.tool_choice or "", "")
        if self.tool_choice and self.tool_choice not in ("any", "none"):
            rule = f'- You MUST call the tool "{self.tool_choice}" in this reply.\n'
        protocol = PROTOCOL.format(choice_rule=rule, tools=tools)
        return (base + "\n\n" if base.strip() else "") + protocol

    @staticmethod
    def render_transcript(messages: Sequence[BaseMessage]) -> str:
        """Conversation as text, with prior tool calls/results in the protocol's own format."""
        parts: list[str] = []
        for m in messages:
            if isinstance(m, SystemMessage):
                continue
            if isinstance(m, HumanMessage):
                parts.append(f"[user]\n{_text(m.content)}")
            elif isinstance(m, AIMessage):
                if m.tool_calls:
                    payload = {"tool_calls": [{"name": c["name"], "args": c["args"]} for c in m.tool_calls]}
                    ids = ", ".join(c.get("id") or "?" for c in m.tool_calls)
                    parts.append(f"[assistant: tool call(s) {ids}]\n{json.dumps(payload)}")
                else:
                    parts.append(f"[assistant]\n{json.dumps({'content': _text(m.content)})}")
            elif isinstance(m, ToolMessage):
                status = " (error)" if getattr(m, "status", None) == "error" else ""
                parts.append(f"[tool result for {m.name or '?'} id={m.tool_call_id}{status}]\n{_text(m.content)}")
            else:
                parts.append(f"[{m.type}]\n{_text(m.content)}")
        parts.append("[your turn]\nReply now with exactly one JSON object as specified in the protocol.")
        return "\n\n".join(parts)

    # ---- generation

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        base = "\n\n".join(_text(m.content) for m in messages if isinstance(m, SystemMessage))
        system = SystemMessage(content=self.render_system(base))
        transcript = self.render_transcript(messages)
        required = self._required_tools()
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        meta: dict[str, Any] = {}
        prompt: list[BaseMessage] = [system, HumanMessage(content=transcript)]
        content, calls, repairs, last_error, raw_text = "", [], 0, "", ""
        for attempt in range(self.max_repairs + 1):
            reply = self.inner.invoke(prompt)
            for k, v in usage_of(reply).items():
                usage[k] += v
            meta = dict(getattr(reply, "response_metadata", None) or {})
            raw_text = _text(reply.content)
            try:
                content, calls = parse_reply(
                    raw_text, self._tool_names, require_tool=required is not None
                )
                last_error = ""
                break
            except ToolProtocolError as exc:
                last_error = str(exc)
                repairs += 1 if attempt < self.max_repairs else 0
                prompt = [
                    system,
                    HumanMessage(
                        content=transcript
                        + f"\n\n[your previous reply, INVALID]\n{raw_text[:4000]}\n\n"
                        f"[error] {last_error}. Reply again with exactly one JSON object as specified."
                    ),
                ]
        if last_error:  # repair failed: degrade to plain content; callers log/handle it
            content, calls = raw_text, []
        meta.update(
            {
                "prompted_tools": {
                    "repairs": repairs,
                    "protocol_failure": last_error or None,
                    "model_calls": repairs + 1,
                }
            }
        )
        msg = AIMessage(
            content=content,
            tool_calls=calls,
            usage_metadata=usage,  # type: ignore[arg-type]
            response_metadata=meta,
        )
        return ChatResult(generations=[ChatGeneration(message=msg)])


# --------------------------------------------------------------------------- Claude Code


def _patch_sdk_parser() -> None:
    """Make claude-code-sdk 0.0.25 tolerate message types newer CLIs emit (rate_limit_event, ...).

    The SDK's ``parse_message`` raises on unknown types, which kills every query against CLI
    2.1.x. Wrapped from here at runtime; idempotent; site-packages is never edited.
    """
    import claude_code_sdk._internal.client as sdk_client
    from claude_code_sdk._errors import MessageParseError
    from claude_code_sdk.types import SystemMessage as SdkSystemMessage

    current = sdk_client.parse_message
    if getattr(current, "_mitre_mapper_patched", False):
        return

    def tolerant(data: Any) -> Any:
        try:
            return current(data)
        except MessageParseError:
            if isinstance(data, dict) and str(data.get("type", "")).endswith("_event"):
                return SdkSystemMessage(subtype=str(data.get("type")), data=data)
            raise

    tolerant._mitre_mapper_patched = True  # type: ignore[attr-defined]
    sdk_client.parse_message = tolerant


def make_claude_code_chat(model_id: str) -> BaseChatModel:
    """A text-only ``ClaudeCodeChatModel`` for ``model_id`` (needs the ``claude-code`` extra)."""
    try:
        from claude_code_langchain import ClaudeCodeChatModel
        from claude_code_sdk import ClaudeCodeOptions
    except ImportError as exc:  # pragma: no cover - depends on the optional extra
        raise ImportError(
            "claude-code: models need the optional extra: uv sync --extra claude-code "
            "(and the `claude` CLI logged in)"
        ) from exc
    _patch_sdk_parser()
    workdir = tempfile.mkdtemp(prefix="mitre-mapper-claude-")  # empty cwd: no CLAUDE.md / project files

    class IsolatedClaudeCodeChat(ClaudeCodeChatModel):  # type: ignore[misc]
        """ClaudeCodeChatModel as a plain text completer: no tools, no user settings, no project."""

        def _get_claude_options(self, messages: list[BaseMessage]) -> Any:
            return ClaudeCodeOptions(
                model=self.model_name,
                system_prompt="You are a text-only assistant. Follow the instructions in the prompt exactly.",
                max_turns=1,
                cwd=workdir,
                extra_args={"tools": "", "setting-sources": ""},
            )

    return IsolatedClaudeCodeChat(model=model_id)


def resolve_model(spec: str | BaseChatModel) -> BaseChatModel:
    """Turn a model spec into a chat model. Instances pass through unchanged."""
    if not isinstance(spec, str):
        return spec
    if spec.startswith(CLAUDE_CODE_PREFIX):
        model_id = spec[len(CLAUDE_CODE_PREFIX) :]
        return PromptedToolCallingModel(inner=make_claude_code_chat(model_id), model_name=spec)
    from langchain.chat_models import init_chat_model

    return init_chat_model(spec)
