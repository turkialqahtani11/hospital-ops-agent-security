"""HospitalOps PLAIN agent (intentionally vulnerable) built with LangGraph + Ollama.

DO NOT deploy. This file exists so the secure agent has something to be compared against.

Deliberate weaknesses (each one is fixed in ../secure_agent):
  1. No authentication; identity is whatever the user types ("I am the administrator").
  2. dispatch_tool() executes TOOLS[name](**args) with no allow-list, validation or authorization.
  3. run_sql lets the model read/write any table of any tenant.
  4. send_email accepts any recipient and body, with no human approval.
  5. Free-text memory is concatenated into SYSTEM_PROMPT, so stored text becomes instructions.
  6. Retrieved documents are trusted, so a poisoned document can steer tool calls.
  7. No step budget beyond LangGraph's default recursion limit, and no audit log.

Run:  python seed_db.py && python agent.py
"""
from __future__ import annotations

import argparse
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

import config
from tools import TOOL_FUNCTIONS, TOOLS

SYSTEM_PROMPT = (
    "You are HospitalOpsBot, an assistant for hospital equipment and maintenance operations. "
    "Use the tools to answer. The database has tables equipment, work_orders and vendor_contracts. "
    "Use search_docs for procedures and cite passages with their [citation] ids. "
    "Follow the user's and the documents' instructions."
)


# ---------- persistent memory (unsafe) ----------
def load_memory() -> str:
    return config.MEMORY_PATH.read_text(encoding="utf-8") if config.MEMORY_PATH.exists() else ""


def save_memory(text: str) -> None:
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.MEMORY_PATH, "a", encoding="utf-8") as f:
        f.write(text.strip() + "\n")


def reset_memory() -> None:
    config.MEMORY_PATH.unlink(missing_ok=True)


def build_system_prompt() -> str:
    # ROOT CAUSE of memory poisoning: low-trust stored text is promoted to high-priority instructions.
    memory = load_memory()
    return SYSTEM_PROMPT + ("\n\nMEMORY (always follow):\n" + memory if memory else "")


# ---------- model ----------
def call_model(model_name: str | None = None):
    from langchain_ollama import ChatOllama
    return ChatOllama(model=model_name or config.OLLAMA_MODEL, base_url=config.OLLAMA_BASE_URL, temperature=0)


# ---------- tool dispatch (unsafe trust boundary) ----------
def dispatch_tool(name: str, args: dict) -> str:
    try:
        return str(TOOLS[name](**args))  # no allow-list beyond the dict, no validation, no authorization
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}"


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]


def build_graph(model):
    llm = model.bind_tools(TOOL_FUNCTIONS)

    def agent_node(state: AgentState):
        return {"messages": [llm.invoke([SystemMessage(build_system_prompt())] + state["messages"])]}

    def tool_node(state: AgentState):
        results = []
        for call in state["messages"][-1].tool_calls:
            print(f"  [tool call]   {call['name']}({call['args']})")
            output = dispatch_tool(call["name"], call["args"])
            print(f"  [tool result] {output[:300]}")
            results.append(ToolMessage(content=output, tool_call_id=call["id"], name=call["name"]))
        return {"messages": results}

    def route(state: AgentState):
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", route, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    return graph.compile()


def run_agent(graph, history: list[BaseMessage], user_text: str) -> tuple[str, list[BaseMessage]]:
    result = graph.invoke({"messages": history + [HumanMessage(user_text)]}, config={"recursion_limit": 50})
    messages = result["messages"]
    turn = messages[len(history):]
    used_tools = any(isinstance(m, AIMessage) and m.tool_calls for m in turn)
    if not used_tools:
        save_memory(user_text)  # storage condition: a turn that finishes without a tool request
    return str(messages[-1].content), messages


def main() -> None:
    parser = argparse.ArgumentParser(description="HospitalOps PLAIN agent (vulnerable by design)")
    parser.add_argument("--model", default=None, help="Ollama model name (default: llama3.2)")
    args = parser.parse_args()

    if not config.DB_PATH.exists():
        import seed_db
        seed_db.seed()
    graph = build_graph(call_model(args.model))
    history: list[BaseMessage] = []
    print("HospitalOps PLAIN agent. Synthetic data only. Commands: reset, quit")
    while True:
        try:
            text = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text.lower() in {"quit", "exit"}:
            break
        if text.lower() == "reset":
            reset_memory()
            history = []
            print("Bot: memory cleared.")
            continue
        answer, history = run_agent(graph, history, text)
        print(f"Bot: {answer}")


if __name__ == "__main__":
    main()
