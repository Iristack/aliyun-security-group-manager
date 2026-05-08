"""Tests for Pydantic configuration models."""

import pytest

from config import AppConfig, RuleConfig, SecurityGroupConfig


class TestRuleConfig:
    def test_default_proto(self) -> None:
        rule = RuleConfig(port=22)
        assert rule.proto == "tcp"

    def test_valid_proto(self) -> None:
        for proto in ("tcp", "udp", "icmp", "gre", "all"):
            rule = RuleConfig(proto=proto, port=22)
            assert rule.proto == proto

    def test_invalid_proto(self) -> None:
        with pytest.raises(ValueError):
            RuleConfig(proto="invalid", port=22)

    def test_port_range(self) -> None:
        with pytest.raises(ValueError):
            RuleConfig(port=0)
        with pytest.raises(ValueError):
            RuleConfig(port=70000)


class TestSecurityGroupConfig:
    def test_basic_creation(self) -> None:
        sg = SecurityGroupConfig(id="sg-123", region="cn-hangzhou")
        assert sg.id == "sg-123"
        assert sg.region == "cn-hangzhou"

    def test_strip_whitespace(self) -> None:
        sg = SecurityGroupConfig(id="  sg-123  ", region="  cn-hangzhou  ")
        assert sg.id == "sg-123"
        assert sg.region == "cn-hangzhou"


class TestAppConfig:
    def test_defaults(self) -> None:
        cfg = AppConfig()
        assert cfg.interval == 60
        assert cfg.plugins.ipv4 == []
        assert cfg.securityGroup == []

    def test_interval_bounds(self) -> None:
        with pytest.raises(ValueError):
            AppConfig(interval=3)
        with pytest.raises(ValueError):
            AppConfig(interval=90000)

    def test_interval_from_string(self) -> None:
        cfg = AppConfig(interval="120")
        assert cfg.interval == 120
