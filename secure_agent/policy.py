"""Authorization (RBAC + least privilege).

The backend decides; the model only proposes. Unknown tools are denied by default.
"""
from __future__ import annotations

from dataclasses import dataclass

from auth import Principal

READ_ONLY_TOOLS = frozenset({"list_equipment", "get_equipment", "list_work_orders", "search_docs"})
WRITE_TOOLS = frozenset({"create_work_order", "send_email", "set_preference"})
ALL_TOOLS = READ_ONLY_TOOLS | WRITE_TOOLS

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "technician": READ_ONLY_TOOLS | {"set_preference"},
    "biomed_engineer": READ_ONLY_TOOLS | {"set_preference", "create_work_order"},
    "ops_manager": READ_ONLY_TOOLS | {"set_preference", "create_work_order", "send_email"},
}

# Human-only actions: never exposed to the LLM as tools.
HUMAN_ACTIONS: dict[str, frozenset[str]] = {
    "approve_email": frozenset({"ops_manager"}),
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorize_tool(principal: Principal, tool_name: str) -> Decision:
    if tool_name not in ALL_TOOLS:
        return Decision(False, f"DENIED: unknown tool '{tool_name}' (not on the allow-list)")
    if tool_name not in ROLE_PERMISSIONS.get(principal.role, frozenset()):
        return Decision(False, f"DENIED: role '{principal.role}' may not use '{tool_name}'")
    return Decision(True, "ALLOWED")


def authorize_human_action(principal: Principal, action: str) -> Decision:
    if principal.role not in HUMAN_ACTIONS.get(action, frozenset()):
        return Decision(False, f"DENIED: role '{principal.role}' may not perform '{action}'")
    return Decision(True, "ALLOWED")


def tools_for(principal: Principal) -> list[str]:
    """Least privilege at the schema level too: the model is only shown tools the role may call."""
    return sorted(ROLE_PERMISSIONS.get(principal.role, frozenset()))
