import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config  # noqa: E402
import seed_db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(tmp_path):
    """Every test gets its own synthetic DB, memory file and outbox."""
    config.use_state_dir(tmp_path)
    seed_db.seed()
    yield tmp_path
