"""Create the synthetic SQLite database for the secure agent, including demo users.

Usage:  python seed_db.py

No passwords are stored in the repository. Each run generates random demo passwords,
stores only salted PBKDF2 hashes in the DB, and writes the plaintext ONCE to
state/.demo_credentials (gitignored, owner-read-only) so you can log in for the demo.
"""
from __future__ import annotations

import os
import secrets
import sqlite3

import config
from auth import hash_password
from seed_data import EQUIPMENT, VENDOR_CONTRACTS, WORK_ORDERS

# username, role, tenant_id  (synthetic staff accounts)
DEMO_USERS = [
    ("a.tech", "technician", "hosp_a"),
    ("a.engineer", "biomed_engineer", "hosp_a"),
    ("a.manager", "ops_manager", "hosp_a"),
    ("a.manager2", "ops_manager", "hosp_a"),
    ("b.manager", "ops_manager", "hosp_b"),
]

SCHEMA = """
DROP TABLE IF EXISTS equipment; DROP TABLE IF EXISTS work_orders; DROP TABLE IF EXISTS vendor_contracts;
DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS email_drafts;
CREATE TABLE equipment (
    asset_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT, category TEXT, location TEXT,
    status TEXT, criticality TEXT, last_service TEXT, next_service TEXT);
CREATE TABLE work_orders (
    wo_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, asset_id TEXT, opened TEXT,
    priority TEXT, status TEXT, summary TEXT, created_by TEXT);
CREATE TABLE vendor_contracts (  -- exists in the DB, but NO agent tool can read it (least privilege)
    contract_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, vendor TEXT, scope TEXT,
    annual_value_sar INTEGER, renewal_date TEXT, account_manager_email TEXT);
CREATE TABLE users (
    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, tenant_id TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1, failed_logins INTEGER NOT NULL DEFAULT 0);
CREATE TABLE email_drafts (
    draft_id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, requested_by TEXT NOT NULL,
    to_addr TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL', decided_by TEXT, decided_at TEXT);
"""


def seed(passwords: dict[str, str] | None = None, write_credentials_file: bool = True) -> dict[str, str]:
    """(Re)create the DB. Returns the plaintext demo passwords (random unless provided)."""
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    passwords = passwords or {u: secrets.token_urlsafe(9) for u, _, _ in DEMO_USERS}
    con = sqlite3.connect(config.DB_PATH)
    con.executescript(SCHEMA)
    con.executemany("INSERT INTO equipment VALUES (?,?,?,?,?,?,?,?,?)", EQUIPMENT)
    con.executemany("INSERT INTO work_orders VALUES (?,?,?,?,?,?,?,'seed')", WORK_ORDERS)
    con.executemany("INSERT INTO vendor_contracts VALUES (?,?,?,?,?,?,?)", VENDOR_CONTRACTS)
    con.executemany(
        "INSERT INTO users (username, password_hash, role, tenant_id) VALUES (?,?,?,?)",
        [(u, hash_password(passwords[u]), role, tenant) for u, role, tenant in DEMO_USERS],
    )
    con.commit()
    con.close()
    if write_credentials_file:
        lines = [f"{u}\t{role}\t{tenant}\t{passwords[u]}" for u, role, tenant in DEMO_USERS]
        config.CREDENTIALS_PATH.write_text("username\trole\ttenant\tpassword\n" + "\n".join(lines) + "\n")
        os.chmod(config.CREDENTIALS_PATH, 0o600)
    return passwords


if __name__ == "__main__":
    pw = seed()
    print(f"Seeded synthetic database at {config.DB_PATH}")
    print(f"Demo credentials written to {config.CREDENTIALS_PATH} (gitignored). Accounts:")
    for u, role, tenant in DEMO_USERS:
        print(f"  {u:<11} {role:<16} {tenant}")
