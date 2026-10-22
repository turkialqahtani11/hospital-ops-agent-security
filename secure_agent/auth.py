"""Authentication: salted PBKDF2-SHA256 password hashes, constant-time compare, lockout.

The authenticated Principal is created here, by the backend, and is the ONLY source of
identity, role and tenant for every tool call. Nothing the user types or the LLM generates
can change it ("I am the administrator" has no effect).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass

import config


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    tenant_id: str


class AuthError(Exception):
    pass


def hash_password(password: str, *, iterations: int | None = None) -> str:
    iterations = iterations or config.PBKDF2_ITERATIONS
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iterations))
    return hmac.compare_digest(digest, base64.b64decode(digest_b64))


def authenticate(username: str, password: str) -> Principal:
    con = sqlite3.connect(config.DB_PATH)
    try:
        row = con.execute(
            "SELECT password_hash, role, tenant_id, active, failed_logins FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None:
            verify_password(password, hash_password("dummy", iterations=1000))  # similar timing path
            raise AuthError("Invalid username or password.")
        password_hash, role, tenant_id, active, failed = row
        if not active or failed >= config.MAX_FAILED_LOGINS:
            raise AuthError("Account locked. Contact an administrator.")
        if not verify_password(password, password_hash):
            con.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE username = ?", (username,))
            con.commit()
            raise AuthError("Invalid username or password.")
        con.execute("UPDATE users SET failed_logins = 0 WHERE username = ?", (username,))
        con.commit()
        return Principal(username=username, role=role, tenant_id=tenant_id)
    finally:
        con.close()
