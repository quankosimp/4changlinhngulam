from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import database
from app.settings import get_settings


@pytest.fixture()
def temp_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_path = tmp_path / "test.db"
    storage_dir = tmp_path / "storage"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("STORAGE_DIR", str(storage_dir))
    get_settings.cache_clear()
    database.configure_database(os.environ["DATABASE_URL"])
    database.init_db()
    yield tmp_path
    database.engine.dispose()
    get_settings.cache_clear()
