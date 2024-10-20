from pathlib import Path
import os
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent

def get_env_file():
    return PROJECT_ROOT / ".env"

def get_default_path():
    return get_env_file()

def load_env(file: Path):
    environments = {}
    with open(file, "r", encoding="utf-8") as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            if value.startswith("\"") and value.endswith("\""):
                value = value[1:-1]
            environments[key] = value
    update_env(environments)


def update_env(environment: dict[str, Any]):
    os.environ.update(environment)

def get_env(key: str, def_: Any = None):
    return os.environ.get(key) or def_