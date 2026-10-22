"""Settings for the SECURE agent. Paths are module attributes so tests can redirect them."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DOCS_DIR = BASE_DIR / "docs"
STATE_DIR = Path(os.getenv("SECURE_STATE_DIR", BASE_DIR / "state"))


def _paths(state: Path) -> dict:
    return {
        "DB_PATH": state / "hospital_ops.db",
        "PREFS_DIR": state / "preferences",
        "OUTBOX_PATH": state / "sent_emails.txt",
        "AUDIT_PATH": state / "audit.jsonl",
        "CREDENTIALS_PATH": state / ".demo_credentials",  # gitignored, chmod 600
    }


globals().update(_paths(STATE_DIR))

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Bounded execution
MAX_STEPS = 6                 # model->tools round trips per user turn
MAX_TOOL_CALLS_PER_STEP = 3   # parallel tool calls accepted in one model turn
MAX_USER_INPUT_CHARS = 2000

# Authentication
PBKDF2_ITERATIONS = 200_000
MAX_FAILED_LOGINS = 5

# Email policy: each tenant may only email its own internal domain. Nothing ever leaves via SMTP.
TENANT_EMAIL_DOMAINS = {"hosp_a": {"hospital-a.test"}, "hosp_b": {"hospital-b.test"}}
MAX_ASSET_IDS_PER_EMAIL = 5   # simple DLP: blocks bulk inventory dumps by email

TENANTS = {"hosp_a": "Hospital A (synthetic)", "hosp_b": "Hospital B (synthetic)"}


def use_state_dir(path) -> None:
    global STATE_DIR
    STATE_DIR = Path(path)
    globals().update(_paths(STATE_DIR))
