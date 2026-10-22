"""Paths and model settings for the PLAIN (intentionally vulnerable) agent.

Paths are module attributes read at call time so tests can point them at a temp folder.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DOCS_DIR = BASE_DIR / "docs"
STATE_DIR = Path(os.getenv("PLAIN_STATE_DIR", BASE_DIR / "state"))

DB_PATH = STATE_DIR / "hospital_ops.db"
MEMORY_PATH = STATE_DIR / "agent_memory.txt"
OUTBOX_PATH = STATE_DIR / "sent_emails.txt"

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def use_state_dir(path) -> None:
    """Redirect all mutable state (DB, memory, outbox) to another folder (used by tests)."""
    global STATE_DIR, DB_PATH, MEMORY_PATH, OUTBOX_PATH
    STATE_DIR = Path(path)
    DB_PATH = STATE_DIR / "hospital_ops.db"
    MEMORY_PATH = STATE_DIR / "agent_memory.txt"
    OUTBOX_PATH = STATE_DIR / "sent_emails.txt"
