"""Append-only, hash-chained audit log (JSON Lines).

Every tool request, decision and outcome is written with the authenticated user, role and
tenant. Each record stores the SHA-256 of the previous record, so editing or deleting a line
breaks the chain and `python audit.py --verify` reports it.

Usage:  python audit.py            (print the last 20 events)
        python audit.py --verify   (check the hash chain)
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone

import config

GENESIS = "0" * 64


def _last_hash() -> str:
    if not config.AUDIT_PATH.exists():
        return GENESIS
    lines = config.AUDIT_PATH.read_text(encoding="utf-8").strip().splitlines()
    return json.loads(lines[-1])["hash"] if lines else GENESIS


def _digest(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def log_event(event: str, principal=None, **fields) -> dict:
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "user": getattr(principal, "username", None),
        "role": getattr(principal, "role", None),
        "tenant": getattr(principal, "tenant_id", None),
        **fields,
        "prev": _last_hash(),
    }
    record["hash"] = _digest(record)
    with open(config.AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def read_events() -> list[dict]:
    if not config.AUDIT_PATH.exists():
        return []
    return [json.loads(line) for line in config.AUDIT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def verify_chain() -> tuple[bool, str]:
    prev = GENESIS
    for i, rec in enumerate(read_events(), start=1):
        if rec.get("prev") != prev or rec.get("hash") != _digest(rec):
            return False, f"Audit chain BROKEN at record {i}"
        prev = rec["hash"]
    return True, "Audit chain intact"


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    if a.verify:
        print(verify_chain()[1])
    else:
        for r in read_events()[-20:]:
            extras = {k: v for k, v in r.items() if k not in {"ts", "event", "user", "role", "tenant", "prev", "hash"}}
            print(f"{r['ts']} {r['event']:<22} {r['user']}/{r['role']}/{r['tenant']} {json.dumps(extras, ensure_ascii=False)[:160]}")
