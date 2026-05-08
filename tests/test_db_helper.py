"""Tests for DBHelper."""

import os
import tempfile

import pytest

from db_helper import DBHelper


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    DBHelper.reset_instance()
    yield path
    DBHelper.reset_instance()
    os.unlink(path)


class TestDBHelper:
    def test_save_and_get(self, temp_db: str) -> None:
        db = DBHelper.get_instance(db_path=temp_db)
        db.save_ip_change("1.1.1.1", "2.2.2.2")
        assert db.get_last_ip() == "2.2.2.2"

    def test_history(self, temp_db: str) -> None:
        db = DBHelper.get_instance(db_path=temp_db)
        db.save_ip_change("1.1.1.1", "2.2.2.2")
        db.save_ip_change("2.2.2.2", "3.3.3.3")
        history = db.get_history(limit=10)
        assert len(history) == 2
        assert history[0]["new_ip"] == "3.3.3.3"

    def test_none_last_ip(self, temp_db: str) -> None:
        db = DBHelper.get_instance(db_path=temp_db)
        assert db.get_last_ip() is None
