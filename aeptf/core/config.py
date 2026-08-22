"""Configuration loading from YAML with environment-variable overrides.

Precedence (highest wins): environment variables > configs/default.yml (or
a path given via AEPTF_CONFIG_FILE) > in-code defaults below.

Environment overrides use the prefix AEPTF__ with "__" as the nesting
separator, e.g. AEPTF__SAFETY__APPROVED_TARGETS=127.0.0.1,10.0.0.5
(comma-separated values are split into a list automatically).
"""
from __future__ import annotations

import os
import copy
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

ENV_PREFIX = "AEPTF__"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "default.yml"


class AppConfig(BaseModel):
    name: str = "AEPTF"
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000


class LoggingConfig(BaseModel):
    level: str = "INFO"
    json_format: bool = Field(default=False, alias="json")
    file: str | None = None

    model_config = {"populate_by_name": True}


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///./aeptf.db"
    echo: bool = False


class SafetyConfig(BaseModel):
    authorization_required: bool = True
    approved_targets: list[str] = Field(default_factory=list)
    max_scan_ports: int = 100
    network_timeout_seconds: int = 5
    nmap_timeout_seconds: int = 120
    # Minimum gap between two runs against the SAME target, regardless of
    # plugin. 0 disables the cooldown. This exists so a scripted client
    # (or an operator's overeager retry loop) can't hammer one host by
    # firing many /runs or /pipelines calls back to back; it is not a
    # substitute for approved_targets, which governs WHICH hosts, not how
    # often.
    min_seconds_between_runs: int = 0


class PluginsConfig(BaseModel):
    enabled: list[str] = Field(default_factory=list)


class ReportingConfig(BaseModel):
    output_dir: str = "reports"


class PipelinesConfig(BaseModel):
    """Named, ordered lists of plugin short-names.

    Pipelines are entirely configuration-driven: adding a new pipeline
    (or reordering/removing steps from an existing one) never requires a
    code change. `default` is used when a caller doesn't name one.
    """

    definitions: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "default": ["reconnaissance", "scanning", "enumeration"],
        }
    )
    default: str = "default"


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    pipelines: PipelinesConfig = Field(default_factory=PipelinesConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file {path} must contain a mapping at the top level")
    return data


def _coerce_scalar(raw: str) -> Any:
    lowered = raw.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if "," in raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _env_overrides(prefix: str = ENV_PREFIX) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for key, raw_value in os.environ.items():
        if not key.startswith(prefix):
            continue
        path = key[len(prefix):].lower().split("__")
        cursor = overrides
        for segment in path[:-1]:
            cursor = cursor.setdefault(segment, {})
        cursor[path[-1]] = _coerce_scalar(raw_value)
    return overrides


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Load settings from YAML plus environment overrides.

    config_path defaults to configs/default.yml, or the AEPTF_CONFIG_FILE
    environment variable if set.
    """
    path = Path(config_path or os.environ.get("AEPTF_CONFIG_FILE", DEFAULT_CONFIG_PATH))
    file_data = _load_yaml(path)
    merged = _deep_merge(file_data, _env_overrides())
    return Settings(**merged)


_settings_singleton: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    """Return a process-wide cached Settings instance."""
    global _settings_singleton
    if _settings_singleton is None or reload:
        _settings_singleton = load_settings()
    return _settings_singleton
