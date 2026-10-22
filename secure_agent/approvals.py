"""Human approval of email drafts (never callable by the LLM).

Rules: approver must be an authenticated ops_manager of the SAME tenant, must not be the
person who requested the draft (separation of duties), and the draft must be pending.
Approved drafts are written to the simulated outbox; there is no SMTP anywhere.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import audit
import config
from auth import Principal
from policy import authorize_human_action


def pending_drafts(p: Principal) -> list[tuple]:
    con = sqlite3.connect(config.DB_PATH)
    rows = con.execute(
        "SELECT draft_id, requested_by, to_addr, subject, body, created_at FROM email_drafts "
        "WHERE tenant_id = ? AND status = 'PENDING_APPROVAL' ORDER BY draft_id", (p.tenant_id,)).fetchall()
    con.close()
    return rows


def decide(p: Principal, draft_id: int, approve: bool) -> str:
    decision = authorize_human_action(p, "approve_email")
    if not decision.allowed:
        audit.log_event("EMAIL_APPROVAL_DENIED", p, draft_id=draft_id, reason=decision.reason)
        return decision.reason
    con = sqlite3.connect(config.DB_PATH)
    try:
        row = con.execute("SELECT tenant_id, requested_by, to_addr, subject, body, status FROM email_drafts WHERE draft_id = ?",
                          (draft_id,)).fetchone()
        if row is None or row[0] != p.tenant_id:
            reason = f"DENIED: draft #{draft_id} not found in your hospital"
        elif row[5] != "PENDING_APPROVAL":
            reason = f"DENIED: draft #{draft_id} is already {row[5]}"
        elif row[1] == p.username:
            reason = "DENIED: separation of duties, you cannot approve your own request"
        else:
            reason = ""
        if reason:
            audit.log_event("EMAIL_APPROVAL_DENIED", p, draft_id=draft_id, reason=reason)
            return reason

        status = "APPROVED_SENT" if approve else "REJECTED"
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        con.execute("UPDATE email_drafts SET status = ?, decided_by = ?, decided_at = ? WHERE draft_id = ?",
                    (status, p.username, now, draft_id))
        con.commit()
    finally:
        con.close()

    if approve:
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.OUTBOX_PATH, "a", encoding="utf-8") as f:
            f.write(f"--- {now} (SIMULATED, no SMTP) draft #{draft_id} requested by {row[1]}, approved by {p.username}\n"
                    f"TO: {row[2]}\nSUBJECT: {row[3]}\n{row[4]}\n\n")
    audit.log_event("EMAIL_APPROVED" if approve else "EMAIL_REJECTED", p, draft_id=draft_id, to=row[2], requested_by=row[1])
    return f"Draft #{draft_id} {status}."
