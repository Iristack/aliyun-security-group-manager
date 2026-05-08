"""Tests for ConfHelper."""

import os
import tempfile

import pytest
import yaml

from conf_helper import ConfHelper


@pytest.fixture
def temp_config():
    data = {
        "plugins": {"ipv4": ["SocketTrick"]},
        "interval": 30,
        "aliyun": {"ak": "test-ak", "sk": "test-sk"},
        "securityGroup": [
            {"id": "sg-123", "region": "cn-hangzhou"}
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        path = f.name
    yield path
    os.unlink(path)
    ConfHelper.reset_instance()


class TestConfHelper:
    def test_load_config(self, temp_config: str) -> None:
        helper = ConfHelper.get_instance(config_path=temp_config)
        assert helper.get("plugins.ipv4") == ["SocketTrick"]
        assert helper.get("interval") == 30

    def test_model_access(self, temp_config: str) -> None:
        helper = ConfHelper.get_instance(config_path=temp_config)
        assert helper.model.interval == 30
        assert helper.model.aliyun.ak == "test-ak"

    def test_dot_notation_get(self, temp_config: str) -> None:
        helper = ConfHelper.get_instance(config_path=temp_config)
        assert helper.get("aliyun.ak") == "test-ak"
        assert helper.get("missing.key", "default") == "default"

    def test_env_override_ak(self, temp_config: str, monkeypatch) -> None:
        monkeypatch.setenv("SGM_ALIYUN_AK", "env-ak")
        ConfHelper.reset_instance()
        helper = ConfHelper.get_instance(config_path=temp_config)
        assert helper.model.aliyun.ak == "env-ak"

    def test_env_override_interval(self, temp_config: str, monkeypatch) -> None:
        monkeypatch.setenv("SGM_INTERVAL", "120")
        ConfHelper.reset_instance()
        helper = ConfHelper.get_instance(config_path=temp_config)
        assert helper.model.interval == 120

    def test_missing_file(self) -> None:
        ConfHelper.reset_instance()
        with pytest.raises(FileNotFoundError):
            ConfHelper.get_instance(config_path="/nonexistent/path.yaml")
