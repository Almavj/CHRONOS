import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging
import logging.config
from datetime import datetime

import yaml
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).parent
CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"


def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Configuration file not found: {CONFIG_PATH}")

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    _expand_env_vars(config)
    return config


def _expand_env_vars(config: Dict[str, Any]) -> None:
    """Recursively expand environment variables in config."""
    for key, value in config.items():
        if isinstance(value, dict):
            _expand_env_vars(value)
        elif isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            env_var_with_default = value[2:-1]
            if ":-" in env_var_with_default:
                env_var, default = env_var_with_default.split(":-", 1)
                config[key] = os.getenv(env_var, default)
            else:
                config[key] = os.getenv(env_var_with_default, "")


def setup_logging(config: Dict[str, Any]) -> None:
    """Configure logging for the application."""
    log_level = config.get("app", {}).get("log_level", "INFO")
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    logging.basicConfig(
        level=getattr(logging, log_level),
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


class Config:
    """Configuration singleton."""

    _instance: Optional["Config"] = None
    _config: Optional[Dict[str, Any]] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._config = load_config()
            setup_logging(cls._config)
        return cls._instance

    def __getitem__(self, key: str) -> Any:
        return self._config[key]  # type: ignore[index]

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value: Any = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value

    @property
    def kafka_config(self) -> Dict[str, Any]:
        return self._config.get("kafka", {}) or {}

    @property
    def elasticsearch_config(self) -> Dict[str, Any]:
        return self._config.get("elasticsearch", {}) or {}

    @property
    def neo4j_config(self) -> Dict[str, Any]:
        return self._config.get("neo4j", {}) or {}

    @property
    def services_config(self) -> Dict[str, Any]:
        return self._config.get("services") or {
            "kafka": {"enabled": False, "required": False},
            "elasticsearch": {"enabled": False, "required": False},
            "neo4j": {"enabled": False, "required": False},
            "redis": {"enabled": False, "required": False},
        }

    def is_service_enabled(self, service: str) -> bool:
        """Check if a service is enabled in configuration."""
        return self.services_config.get(service, {}).get("enabled", False)

    def is_service_required(self, service: str) -> bool:
        """Check if a service is required (system won't work without it)."""
        return self.services_config.get(service, {}).get("required", False)

    @property
    def demo_mode(self) -> bool:
        """Check if demo mode is enabled."""
        demo = self.get("data_sources.demo_mode") or {}
        return demo.get("enabled", True)

    @property
    def soar_config(self) -> Dict[str, Any]:
        return self._config.get("soar") or {}

    def is_soar_dry_run(self) -> bool:
        """Check if SOAR is in dry-run mode."""
        return self.soar_config.get("dry_run", True)

    def is_soar_enabled(self) -> bool:
        """Check if any SOAR auto-response is enabled."""
        auto_response = self.soar_config.get("auto_response") or {}
        return any(cfg.get("enabled", False) for cfg in auto_response.values())

    @property
    def enrichment_config(self) -> Dict[str, Any]:
        return self.soar_config.get("enrichment") or {}

    def is_enrichment_enabled(self, provider: str) -> bool:
        """Check if threat intelligence enrichment is enabled for a provider."""
        enrichment = self.enrichment_config.get(provider) or {}
        return enrichment.get("enabled", False) and bool(enrichment.get("api_key", ""))


config = Config()
