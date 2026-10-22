"""A deterministic stand-in for the LLM, used by attack replays and tests.

ScriptedModel plays back a fixed list of AI turns (tool calls or text). It lets us replay
an attack exactly, with no GPU and no Ollama, and it models the worst case: a model that
has been fully persuaded by the attacker and requests the malicious tool call every time.
Whether the action actually HAPPENS is then decided only by the backend code.
"""
from __future__ import annotations

import uuid
from typing import Any, Callable, Union

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import ConfigDict, Field

Step = Union[AIMessage, Callable[[list[BaseMessage]], AIMessage]]


def tool_call(name: str, **args: Any) -> AIMessage:
    """An AI turn that requests one tool call."""
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"call_{uuid.uuid4().hex[:8]}", "type": "tool_call"}])


def say(text: str) -> AIMessage:
    return AIMessage(content=text)


def echo_last_tool_result(prefix: str = "") -> Callable[[list[BaseMessage]], AIMessage]:
    """Final turn that repeats the last tool output, like a model summarising it."""
    def _step(messages: list[BaseMessage]) -> AIMessage:
        last = next((m for m in reversed(messages) if m.type == "tool"), None)
        return AIMessage(content=f"{prefix}{last.content if last else ''}")
    return _step


class ScriptedModel(BaseChatModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    script: list[Any] = Field(default_factory=list)
    position: int = 0
    prompts_seen: list[list[BaseMessage]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedModel":
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs: Any) -> ChatResult:
        self.prompts_seen.append(list(messages))
        step = self.script[self.position] if self.position < len(self.script) else say("(end of script)")
        self.position += 1
        msg = step(messages) if callable(step) else step
        return ChatResult(generations=[ChatGeneration(message=msg)])
