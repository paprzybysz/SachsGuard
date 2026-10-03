"""Helpers for tests that need a modified copy of the single policy file."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "policy.yaml"


def policy_data() -> dict[str, Any]:
    """A fresh, mutable copy of policies/policy.yaml."""
    return yaml.safe_load(POLICY.read_text(encoding="utf-8"))


def write_policy(path: Path, data: dict[str, Any]) -> Path:
    """Write ``data`` as a policy file and bump its mtime so hot reload sees the change."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existed = path.exists()
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    if existed:
        stat = path.stat()
        os.utime(path, (stat.st_atime, stat.st_mtime + 1))
    return path
