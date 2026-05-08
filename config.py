"""Pydantic configuration models for Security Group Manager."""

from typing import Any

from pydantic import BaseModel, Field, field_validator


class RuleConfig(BaseModel):
    """Security group rule configuration."""

    proto: str = Field(default="tcp", pattern=r"^(tcp|udp|icmp|gre|all)$")
    port: int = Field(..., ge=1, le=65535)


class DirectionConfig(BaseModel):
    """Ingress/egress/all direction configuration."""

    allow: list[RuleConfig] = []
    drop: list[RuleConfig] = []


class SecurityGroupConfig(BaseModel):
    """Single security group configuration."""

    id: str
    region: str
    ingress: DirectionConfig = DirectionConfig()
    egress: DirectionConfig = DirectionConfig()
    all: DirectionConfig = DirectionConfig()

    @field_validator("id", "region")
    @classmethod
    def _strip_string(cls, v: str) -> str:
        return v.strip()


class AliyunConfig(BaseModel):
    """Aliyun credentials configuration."""

    ak: str = ""
    sk: str = ""

    @field_validator("ak", "sk")
    @classmethod
    def _strip_string(cls, v: str) -> str:
        return v.strip()


class PluginConfig(BaseModel):
    """Plugin configuration."""

    ipv4: list[str] = []
    ipv6: list[str] = []


class AppConfig(BaseModel):
    """Application root configuration."""

    plugins: PluginConfig = PluginConfig()
    interval: int = Field(default=60, ge=5, le=86400)
    aliyun: AliyunConfig = AliyunConfig()
    securityGroup: list[SecurityGroupConfig] = Field(default_factory=list)

    @field_validator("interval", mode="before")
    @classmethod
    def _coerce_interval(cls, v: Any) -> int:
        if isinstance(v, str):
            return int(v)
        return v
