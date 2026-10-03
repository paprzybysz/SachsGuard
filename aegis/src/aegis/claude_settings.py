"""Install / remove the Aegis hooks in a Claude Code settings file.

Only entries pointing at the Aegis hook endpoint are touched; every other setting
and hook in the file is kept.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HOOK_PATH = "/v1/hooks/claude-code"
EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse")
# Default: this project only, private to the user (Claude Code ignores it in git).
DEFAULT_SETTINGS = Path(".claude/settings.local.json")


def _is_aegis(entry: dict[str, Any]) -> bool:
    return any(HOOK_PATH in str(h.get("url", "")) for h in entry.get("hooks", []))


def hook_entries(url: str, token: str, *, timeout: int = 30) -> dict[str, list[dict[str, Any]]]:
    hook = {
        "type": "http",
        "url": url,
        "headers": {"Authorization": f"Bearer {token}"},
        "timeout": timeout,
        "statusMessage": "Aegis",
    }
    entries: dict[str, list[dict[str, Any]]] = {}
    for event in EVENTS:
        entry: dict[str, Any] = {"hooks": [dict(hook)]}
        if event != "UserPromptSubmit":
            entry = {"matcher": "*", **entry}
        entries[event] = [entry]
    return entries


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise TypeError(f"{path} is not a JSON object")
    return data


def _without_aegis(settings: dict[str, Any]) -> dict[str, Any]:
    hooks = settings.get("hooks") or {}
    for event in EVENTS:
        kept = [e for e in hooks.get(event, []) if not _is_aegis(e)]
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)
    return settings


def install(path: Path, url: str, token: str) -> Path:
    settings = _without_aegis(_load(path))
    hooks = settings.setdefault("hooks", {})
    for event, entries in hook_entries(url, token).items():
        hooks.setdefault(event, []).extend(entries)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return path


def uninstall(path: Path) -> bool:
    if not path.is_file():
        return False
    before = _load(path)
    after = _without_aegis(json.loads(json.dumps(before)))
    if after == before:
        return False
    path.write_text(json.dumps(after, indent=2) + "\n", encoding="utf-8")
    return True
