import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config  # noqa: E402
import seed_db  # noqa: E402
from attacks import scenarios  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(tmp_path):
    """Each test: its own DB (random demo passwords), audit log, outbox and preferences."""
    config.use_state_dir(tmp_path)
    scenarios.PASSWORDS.clear()
    scenarios.PASSWORDS.update(seed_db.seed(write_credentials_file=False))
    yield tmp_path
