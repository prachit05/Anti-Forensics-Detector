"""Load settings from config/settings.yaml, with environment-variable overrides.

Priority (highest first):
  1. Environment variable (AFD_EVIDENCE_DIR, AFD_CASES_DIR)
  2. config/settings.yaml
  3. Built-in default (C:\\forensics\\...)
"""
import os
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_ROOT / "config" / "settings.yaml"

DEFAULTS = {
    "evidence_dir": r"C:\forensics\evidence",
    "cases_dir": r"C:\forensics\cases",
}

# Folders that OneDrive backup commonly syncs; evidence should not live there.
_ONEDRIVE_HINTS = ("onedrive", "\\desktop", "\\documents", "\\pictures")


def load_settings(config_file: Path = CONFIG_FILE) -> dict:
    """Return the full settings dict (empty dict if the file is missing)."""
    if not config_file.exists():
        return {}
    with open(config_file, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _resolve(key: str, env_var: str, settings: dict) -> Path:
    value = os.environ.get(env_var) or settings.get("paths", {}).get(key) or DEFAULTS[key]
    return Path(value)


def get_paths(create: bool = True) -> dict:
    """Return {'evidence_dir': Path, 'cases_dir': Path}, creating them if asked."""
    settings = load_settings()
    paths = {
        "evidence_dir": _resolve("evidence_dir", "AFD_EVIDENCE_DIR", settings),
        "cases_dir": _resolve("cases_dir", "AFD_CASES_DIR", settings),
    }
    for path in paths.values():
        if create:
            path.mkdir(parents=True, exist_ok=True)
    return paths


def onedrive_warnings(paths: dict) -> list[str]:
    """Warn if a configured path looks like it sits inside an OneDrive-synced folder."""
    return [
        f"{name} '{p}' looks OneDrive-synced; evidence may be uploaded"
        for name, p in paths.items()
        if any(h in str(p).lower() for h in _ONEDRIVE_HINTS)
    ]


def detector_settings(name: str) -> dict:
    """Return the `detection: <name>:` section of settings.yaml ({} if absent)."""
    return (load_settings().get("detection") or {}).get(name) or {}


def merge_config(defaults: dict, *overrides: dict) -> dict:
    """Merge override dicts onto defaults. Nested dicts merge key by key; lists and
    scalars in an override replace the default completely."""
    out = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v)
           for k, v in defaults.items()}
    for override in overrides:
        for key, value in (override or {}).items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key] = merge_config(out[key], value)
            else:
                out[key] = value
    return out
