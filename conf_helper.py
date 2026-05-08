import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

import yaml

from config import AppConfig


class ConfHelper:
    """Thread-safe singleton configuration manager with Pydantic validation."""

    _instance: Optional["ConfHelper"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, config_path: str | Path = "./cfg/sgm.yaml") -> None:
        self._logger = logging.getLogger(self.__class__.__name__)
        self._cfg_path = Path(config_path)
        self._raw_cfg: dict[str, Any] = {}
        self._model: AppConfig = AppConfig()

        self._load()
        self._apply_env_overrides()

    @classmethod
    def get_instance(
        cls, config_path: str | Path = "./cfg/sgm.yaml"
    ) -> "ConfHelper":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(config_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton instance (useful for testing)."""
        with cls._lock:
            cls._instance = None

    def _load(self) -> None:
        if not self._cfg_path.exists():
            self._logger.error("Config file not found: %s", self._cfg_path)
            raise FileNotFoundError(f"Config file not found: {self._cfg_path}")

        try:
            with open(self._cfg_path, encoding="utf-8") as stream:
                self._raw_cfg = yaml.safe_load(stream) or {}
        except yaml.YAMLError as exc:
            self._logger.error("YAML parse error in %s: %s", self._cfg_path, exc)
            raise exc

        try:
            self._model = AppConfig.model_validate(self._raw_cfg)
            self._logger.info("Config loaded and validated: %s", self._cfg_path)
        except Exception as exc:
            self._logger.error("Config validation error: %s", exc)
            raise exc

    def _apply_env_overrides(self) -> None:
        """Allow environment variables to override config values.

        Each env var is mapped to a dot-separated key path. The raw config
        dict is updated and the Pydantic model is re-validated so type
        coercion (e.g. SGM_INTERVAL string -> int) is handled automatically.
        """
        env_map: dict[str, tuple[str, ...]] = {
            "SGM_ALIYUN_AK": ("aliyun", "ak"),
            "SGM_ALIYUN_SK": ("aliyun", "sk"),
            "SGM_INTERVAL": ("interval",),
        }

        overridden = False
        raw_override = self._raw_cfg.copy()

        for env_var, keys in env_map.items():
            value = os.environ.get(env_var)
            if value is None:
                continue

            self._logger.debug("Overriding config from env: %s", env_var)
            overridden = True

            # Walk/create nested dict path and set leaf value
            cfg_ref: dict[str, Any] = raw_override
            for k in keys[:-1]:
                if k not in cfg_ref or not isinstance(cfg_ref[k], dict):
                    cfg_ref[k] = {}
                cfg_ref = cfg_ref[k]  # type: ignore[assignment]
            cfg_ref[keys[-1]] = value

        if overridden:
            try:
                self._model = AppConfig.model_validate(raw_override)
            except Exception as exc:
                self._logger.error("Config validation error after env override: %s", exc)
                raise

    def reload(self) -> None:
        """Reload configuration from disk."""
        self._logger.info("Reloading configuration...")
        self._load()
        self._apply_env_overrides()

    def get(self, key: str, default: Any = None) -> Any:
        """Dot-notation config accessor for backward compatibility."""
        keys = key.split(".")
        value: Any = self._raw_cfg
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """Runtime config mutation (does not persist to disk)."""
        keys = key.split(".")
        cfg_ref: dict[str, Any] = self._raw_cfg
        for k in keys[:-1]:
            if k not in cfg_ref or not isinstance(cfg_ref[k], dict):
                cfg_ref[k] = {}
            cfg_ref = cfg_ref[k]
        cfg_ref[keys[-1]] = value
        self._logger.debug("Runtime config updated: %s = %s", key, value)

    @property
    def model(self) -> AppConfig:
        """Return the validated Pydantic config model."""
        return self._model

    def all(self) -> dict[str, Any]:
        return self._raw_cfg.copy()
