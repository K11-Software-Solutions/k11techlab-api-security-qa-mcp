import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BANK = ROOT / "demo" / "bank"
sys.path.insert(0, str(BANK))

from server import Bank  # noqa: E402


@pytest.fixture
def project(tmp_path):
    dest = tmp_path / "bank"
    shutil.copytree(BANK, dest, ignore=shutil.ignore_patterns("__pycache__", "server.py"))
    return dest


def _bank(secure, project, monkeypatch):
    b = Bank(0, secure)
    monkeypatch.setenv("BANK_URL", b.url)
    monkeypatch.setenv("ALICE_TOKEN", "alice-token")
    monkeypatch.setenv("BOB_TOKEN", "bob-token")
    monkeypatch.setenv("ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("QA_MCP_ROOT", str(project))
    return b


@pytest.fixture
def bank(project, monkeypatch):
    b = _bank(False, project, monkeypatch)
    yield b
    b.close()


@pytest.fixture
def secure_bank(project, monkeypatch):
    b = _bank(True, project, monkeypatch)
    yield b
    b.close()
