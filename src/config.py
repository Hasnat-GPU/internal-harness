"""Shared configuration access for the Internal Harness (config/harness_config.yaml)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "harness_config.yaml"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Parse the harness config with ``yaml.safe_load`` (never constructs arbitrary objects)."""
    cfg_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    with cfg_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if not isinstance(cfg, dict):
        raise ValueError(f"{cfg_path} must contain a YAML mapping")
    return cfg


def resolve_path(path: str | Path) -> Path:
    """Resolve a project-relative config path (e.g. ``data/episodic_buffer.db``)."""
    p = Path(path)
    return p if p.is_absolute() else PROJECT_ROOT / p
