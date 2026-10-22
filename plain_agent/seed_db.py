"""Create (or recreate) the synthetic SQLite database for the plain agent.

Usage:  python seed_db.py
"""
import sqlite3

import config
from seed_data import EQUIPMENT, VENDOR_CONTRACTS, WORK_ORDERS

SCHEMA = """
DROP TABLE IF EXISTS equipment;
DROP TABLE IF EXISTS work_orders;
DROP TABLE IF EXISTS vendor_contracts;
CREATE TABLE equipment (
    asset_id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT, category TEXT, location TEXT,
    status TEXT, criticality TEXT, last_service TEXT, next_service TEXT);
CREATE TABLE work_orders (
    wo_id TEXT PRIMARY KEY, tenant_id TEXT, asset_id TEXT, opened TEXT,
    priority TEXT, status TEXT, summary TEXT);
CREATE TABLE vendor_contracts (
    contract_id TEXT PRIMARY KEY, tenant_id TEXT, vendor TEXT, scope TEXT,
    annual_value_sar INTEGER, renewal_date TEXT, account_manager_email TEXT);
"""


def seed() -> None:
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(config.DB_PATH)
    con.executescript(SCHEMA)
    con.executemany("INSERT INTO equipment VALUES (?,?,?,?,?,?,?,?,?)", EQUIPMENT)
    con.executemany("INSERT INTO work_orders VALUES (?,?,?,?,?,?,?)", WORK_ORDERS)
    con.executemany("INSERT INTO vendor_contracts VALUES (?,?,?,?,?,?,?)", VENDOR_CONTRACTS)
    con.commit()
    con.close()


if __name__ == "__main__":
    seed()
    print(f"Seeded synthetic database at {config.DB_PATH}")
