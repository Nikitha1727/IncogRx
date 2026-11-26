"""Policy and secret handling. The secret is read once and never printed or written."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_policy(path: Path) -> dict:
    """Tiny `key: value` reader for config/policy.yaml (no PyYAML dependency)."""
    policy: dict = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                policy[k] = int(v) if v.lstrip("-").isdigit() else v
    return policy


POLICY = load_policy(ROOT / "config" / "policy.yaml")
SECRET = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")
