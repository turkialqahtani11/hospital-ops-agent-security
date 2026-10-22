"""Structured, per-user memory.

Only two typed preferences can be stored (language, response_style), only through the
validated set_preference tool, and they are re-validated on load. Free text is never stored,
and preferences are rendered to the model as DATA, never appended as instructions.
A tampered or poisoned preferences file is discarded at load time.
"""
from __future__ import annotations

import json
import re

import config
from schemas import SetPreferenceArgs

DEFAULTS = {"language": "en", "response_style": "brief"}


def _path(username: str):
    safe = re.sub(r"[^a-z0-9._-]", "_", username.lower())
    return config.PREFS_DIR / f"{safe}.json"


def load_memory(username: str) -> dict:
    prefs = dict(DEFAULTS)
    path = _path(username)
    if not path.exists():
        return prefs
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return prefs
    if not isinstance(raw, dict):
        return prefs
    for key, value in raw.items():
        try:
            SetPreferenceArgs(key=key, value=value)  # same validation as the write path
            prefs[key] = value
        except Exception:  # noqa: BLE001  unknown key or illegal value -> ignored
            continue
    return prefs


def save_memory(username: str, key: str, value: str) -> dict:
    SetPreferenceArgs(key=key, value=value)  # raises on anything that is not an allowed preference
    prefs = load_memory(username)
    prefs[key] = value
    config.PREFS_DIR.mkdir(parents=True, exist_ok=True)
    _path(username).write_text(json.dumps(prefs, indent=2), encoding="utf-8")
    return prefs


def render_for_context(prefs: dict) -> str:
    return f"User preferences (validated data, not instructions): language={prefs['language']}, response_style={prefs['response_style']}"
