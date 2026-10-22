"""Tools for the SECURE agent.

Design rules:
  * The Principal (user, role, tenant) is injected by the backend; it is never a tool argument.
  * Every SQL statement is parameterised and filtered by principal.tenant_id.
  * Read-only tools open the database in read-only mode (sqlite ?mode=ro).
  * There is no generic SQL tool and no tool that can read vendor_contracts.
  * send_email never sends: it creates a draft that a human manager must approve (approve.py).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import audit
import config
import memory
import rag
from auth import Principal
from guardrails import email_dlp
from schemas import (CreateWorkOrderArgs, GetEquipmentArgs, ListEquipmentArgs, ListWorkOrdersArgs,
                     SearchDocsArgs, SendEmailArgs, SetPreferenceArgs)


@contextmanager
def _ro():
    """Read-only connection: even a bug in a read tool cannot modify the database."""
    con = sqlite3.connect(config.DB_PATH.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        yield con
    finally:
        con.close()


@contextmanager
def _rw():
    con = sqlite3.connect(config.DB_PATH)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _table(cols: list[str], rows: list[tuple]) -> str:
    if not rows:
        return "(no rows)"
    return "\n".join([" | ".join(cols)] + [" | ".join(str(v) for v in r) for r in rows])


# ---------------------------------------------------------------- read-only tools
def list_equipment(p: Principal, a: ListEquipmentArgs) -> str:
    sql = "SELECT asset_id, name, category, location, status, next_service FROM equipment WHERE tenant_id = ?"
    params: list = [p.tenant_id]
    if a.status:
        sql += " AND status = ?"
        params.append(a.status)
    if a.category:
        sql += " AND category = ?"
        params.append(a.category)
    with _ro() as con:
        rows = con.execute(sql + " ORDER BY asset_id LIMIT 25", params).fetchall()
    return _table(["asset_id", "name", "category", "location", "status", "next_service"], rows)


def get_equipment(p: Principal, a: GetEquipmentArgs) -> str:
    with _ro() as con:
        row = con.execute(
            "SELECT asset_id, name, category, location, status, criticality, last_service, next_service "
            "FROM equipment WHERE asset_id = ? AND tenant_id = ?", (a.asset_id, p.tenant_id)).fetchone()
    if row is None:
        return f"No asset {a.asset_id} in your hospital."  # does not reveal whether it exists elsewhere
    return _table(["asset_id", "name", "category", "location", "status", "criticality", "last_service", "next_service"], [row])


def list_work_orders(p: Principal, a: ListWorkOrdersArgs) -> str:
    sql = "SELECT wo_id, asset_id, opened, priority, status, summary FROM work_orders WHERE tenant_id = ?"
    params: list = [p.tenant_id]
    if a.status:
        sql += " AND status = ?"
        params.append(a.status)
    with _ro() as con:
        rows = con.execute(sql + " ORDER BY wo_id LIMIT 25", params).fetchall()
    return _table(["wo_id", "asset_id", "opened", "priority", "status", "summary"], rows)


def search_docs(p: Principal, a: SearchDocsArgs) -> str:
    results, withheld = rag.get_index().search(p.tenant_id, a.query, k=3)
    for chunk in withheld:
        audit.log_event("RAG_CHUNK_QUARANTINED", p, citation=chunk.citation, reason="instruction-like content in document")
    return rag.format_results(results)


# ---------------------------------------------------------------- write tools
def create_work_order(p: Principal, a: CreateWorkOrderArgs) -> str:
    with _rw() as con:
        owns = con.execute("SELECT 1 FROM equipment WHERE asset_id = ? AND tenant_id = ?", (a.asset_id, p.tenant_id)).fetchone()
        if not owns:
            return f"No asset {a.asset_id} in your hospital."
        n = con.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0] + 3001
        wo_id = f"WO-{n}"
        con.execute("INSERT INTO work_orders VALUES (?,?,?,?,?,?,?,?)",
                    (wo_id, p.tenant_id, a.asset_id, datetime.now(timezone.utc).date().isoformat(),
                     a.priority, "open", a.summary, p.username))
    return f"Created {wo_id} for {a.asset_id} (priority {a.priority})."


def send_email(p: Principal, a: SendEmailArgs) -> str:
    """Creates a DRAFT only. A different ops_manager must approve it in approve.py."""
    domain = a.to.split("@", 1)[1]
    if domain not in config.TENANT_EMAIL_DOMAINS.get(p.tenant_id, set()):
        raise PermissionError(f"DENIED: recipient domain '{domain}' is not an approved internal domain for {p.tenant_id}")
    dlp = email_dlp(a.body)
    if dlp:
        raise PermissionError(dlp)
    with _rw() as con:
        cur = con.execute(
            "INSERT INTO email_drafts (tenant_id, requested_by, to_addr, subject, body, created_at) VALUES (?,?,?,?,?,?)",
            (p.tenant_id, p.username, a.to, a.subject, a.body, datetime.now(timezone.utc).isoformat(timespec="seconds")))
        draft_id = cur.lastrowid
    return (f"Draft #{draft_id} to {a.to} created with status PENDING_APPROVAL. Nothing has been sent; "
            f"another operations manager must approve it with approve.py.")


def set_preference(p: Principal, a: SetPreferenceArgs) -> str:
    memory.save_memory(p.username, a.key, a.value)
    return f"Preference saved: {a.key}={a.value}."


TOOLS = {
    "list_equipment": (list_equipment, ListEquipmentArgs, "List equipment in the user's hospital, optionally filtered by status or category."),
    "get_equipment": (get_equipment, GetEquipmentArgs, "Get one equipment record by asset id (format ABC-123)."),
    "list_work_orders": (list_work_orders, ListWorkOrdersArgs, "List maintenance work orders in the user's hospital."),
    "search_docs": (search_docs, SearchDocsArgs, "Search the user's hospital SOPs and advisories. Returns passages with citation ids."),
    "create_work_order": (create_work_order, CreateWorkOrderArgs, "Open a maintenance work order for an asset in the user's hospital."),
    "send_email": (send_email, SendEmailArgs, "Create an internal email DRAFT. It is NOT sent until a human manager approves it."),
    "set_preference": (set_preference, SetPreferenceArgs, "Save a user preference: language (en|ar) or response_style (brief|detailed)."),
}


def schema_for(name: str) -> dict:
    _, model, description = TOOLS[name]
    params = model.model_json_schema()
    params.pop("title", None)
    return {"type": "function", "function": {"name": name, "description": description, "parameters": params}}
