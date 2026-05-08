"""Tests for main CLI commands."""

import os
import tempfile

import pytest
import yaml
from click.testing import CliRunner

from conf_helper import ConfHelper
from db_helper import DBHelper
from main import cli


@pytest.fixture
def temp_config():
    data = {
        "plugins": {"ipv4": ["SocketTrick"]},
        "interval": 30,
        "aliyun": {"ak": "test-ak", "sk": "test-sk"},
        "securityGroup": [{"id": "sg-123", "region": "cn-hangzhou"}],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        path = f.name
    yield path
    os.unlink(path)
    ConfHelper.reset_instance()
    DBHelper.reset_instance()


@pytest.fixture
def temp_db(tmp_path):
    db_file = str(tmp_path / "test.db")
    DBHelper.reset_instance()
    db = DBHelper.get_instance(db_path=db_file)
    yield db
    DBHelper.reset_instance()


class TestHistoryCommand:
    def test_history_empty(self, temp_config, temp_db) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["history", "-c", temp_config])
        assert result.exit_code == 0
        assert "No IP change history found" in result.output

    def test_history_with_records(self, temp_config, temp_db) -> None:
        temp_db.save_ip_change("1.1.1.1", "2.2.2.2")
        temp_db.save_ip_change("2.2.2.2", "3.3.3.3")
        runner = CliRunner()
        result = runner.invoke(cli, ["history", "-c", temp_config])
        assert result.exit_code == 0
        assert "3.3.3.3" in result.output
        assert "2.2.2.2" in result.output

    def test_history_limit_option(self, temp_config, temp_db) -> None:
        for i in range(1, 6):
            temp_db.save_ip_change(f"{i}.{i}.{i}.{i}", f"{i+1}.{i+1}.{i+1}.{i+1}")
        runner = CliRunner()
        result = runner.invoke(cli, ["history", "-c", temp_config, "-n", "2"])
        assert result.exit_code == 0
        lines = [ln for ln in result.output.strip().splitlines() if "->" in ln]
        assert len(lines) == 2

    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "sgm" in result.output
