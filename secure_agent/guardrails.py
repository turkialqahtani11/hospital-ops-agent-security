"""Guardrails: input screening, retrieved-content quarantine, email DLP and output redaction.

Guardrails are a detection layer, not the security boundary. Pattern matching can be
bypassed, so every decision that matters (who, which tenant, which tool, which recipient)
is still enforced in backend code (auth.py, policy.py, schemas.py, tools.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import config

INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (name, severity, regex)
    ("override_instructions", "high", r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|all|your)\b.{0,20}\b(instructions?|rules?|prompt)"),
    ("fake_system_message", "high", r"\b(system (instruction|prompt|message)|developer mode|jailbreak)\b"),
    ("prompt_extraction", "high", r"\b(reveal|print|repeat|translate|show)\b.{0,40}\b(system prompt|original instructions|your instructions|hidden instructions)\b"),
    ("persistent_behavior_change", "medium", r"\b(from now on|always answer|answer only|in all future)\b"),
    ("tool_directive", "medium", r"\b(call|invoke|use)\s+(the\s+)?(send_email|run_sql|[a-z_]+_tool)\b"),
    ("identity_claim", "medium", r"\bi am (the |an? )?(store |hospital |system )?(admin|administrator|director|ceo|owner|root|it manager)\b"),
    ("concealment", "medium", r"\b(do not|don't) (tell|inform|notify) (the )?user\b"),
]


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str


def scan(text: str) -> list[Finding]:
    lowered = text.lower()
    return [Finding(n, s) for n, s, rx in INJECTION_PATTERNS if re.search(rx, lowered)]


def input_guard(text: str) -> tuple[bool, list[Finding], str]:
    """Returns (blocked, findings, message). Only high-severity input is blocked outright;
    medium findings are logged and the model is reminded that text cannot grant privileges."""
    if len(text) > config.MAX_USER_INPUT_CHARS:
        return True, [Finding("oversized_input", "high")], "Input too long."
    findings = scan(text)
    if any(f.severity == "high" for f in findings):
        return True, findings, ("Request blocked by input guardrail: it tries to override or reveal system "
                                "instructions. This attempt has been logged.")
    return False, findings, ""


def is_untrusted_instruction(chunk_text: str) -> bool:
    """Retrieved documents are data. Chunks that contain instructions aimed at the AI are quarantined."""
    return bool(scan(chunk_text))


ASSET_RX = re.compile(r"\b[A-Z]{3}-\d{3}\b")


def email_dlp(body: str) -> str | None:
    """Simple data-loss-prevention rule for drafts: no bulk inventory dumps."""
    assets = set(ASSET_RX.findall(body))
    if len(assets) > config.MAX_ASSET_IDS_PER_EMAIL:
        return f"BLOCKED by DLP: email references {len(assets)} assets (limit {config.MAX_ASSET_IDS_PER_EMAIL})"
    if scan(body):
        return "BLOCKED by DLP: email body contains instruction-like content"
    return None


def output_guard(text: str, allowed_asset_ids: set[str]) -> tuple[str, int]:
    """Redact any asset id that does not belong to the caller's tenant (defence in depth)."""
    count = 0

    def _sub(m: re.Match) -> str:
        nonlocal count
        if m.group(0) in allowed_asset_ids:
            return m.group(0)
        count += 1
        return "[REDACTED-ASSET]"

    return ASSET_RX.sub(_sub, text), count
