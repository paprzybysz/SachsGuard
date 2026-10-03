"""Load and hot-reload the centralized policy file."""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path

import yaml
from pydantic import ValidationError

from aegis.policy.models import Policy, PolicyFile

logger = logging.getLogger("aegis.policy")


class PolicyStore:
    """The single policy file, with mtime-based hot reload for judge edits.

    ``get()`` returns the effective policy of the active profile (``profile`` if
    given, e.g. from ``AEGIS_PROFILE``, else the file's ``active_profile``);
    ``get_for_tenant()`` honours the file's ``tenant_profiles``.

    A file that fails to parse or validate never replaces a good one: the last
    known-good version stays active and the error is kept in ``last_error`` (shown
    on ``/health``). Only the very first load raises, since there is nothing to
    fall back to.
    """

    def __init__(self, path: Path, *, profile: str | None = None) -> None:
        self.path = path.resolve()
        self.profile_override = profile or None
        self._lock = threading.Lock()
        self._mtime: float | None = None
        self._file: PolicyFile | None = None
        self._resolved: dict[str, Policy] = {}
        self.digest: str | None = None
        self.last_error: str | None = None

    @property
    def active_profile(self) -> str:
        return self.profile_override or self.file().active_profile

    def file(self) -> PolicyFile:
        with self._lock:
            return self._file_locked()

    def get(self) -> Policy:
        return self.get_profile(self.active_profile)

    def get_for_tenant(self, tenant: str) -> Policy:
        policy_file = self.file()
        return self.get_profile(policy_file.profile_for_tenant(tenant, self.active_profile))

    def get_profile(self, profile: str) -> Policy:
        with self._lock:
            policy_file = self._file_locked()
            policy = self._resolved.get(profile)
            if policy is None:
                policy = self._resolved[profile] = policy_file.resolve(profile)
            return policy

    def reload(self) -> Policy:
        with self._lock:
            self._mtime = None
        return self.get()

    def _file_locked(self) -> PolicyFile:
        if not self.path.is_file():
            if self._file is None:
                raise FileNotFoundError(f"policy not found: {self.path}")
            self.last_error = f"policy file missing: {self.path}"
            return self._file
        mtime = self.path.stat().st_mtime
        if self._file is not None and self._mtime == mtime:
            return self._file
        raw = self.path.read_bytes()
        try:
            policy_file = parse_policy_file(raw)
            if self.profile_override and self.profile_override not in policy_file.profiles:
                raise ValueError(
                    f"profile {self.profile_override!r} (AEGIS_PROFILE) is not one of "
                    f"{sorted(policy_file.profiles)}"
                )
        except (yaml.YAMLError, ValidationError, TypeError, ValueError) as exc:
            if self._file is None:
                raise
            # Remember the mtime so a broken file is not re-parsed on every request.
            self._mtime = mtime
            self.last_error = f"{type(exc).__name__}: {exc}"[:2000]
            logger.error("policy %s rejected, keeping last good policy: %s", self.path, self.last_error)
            return self._file
        self._file = policy_file
        self._resolved = {}
        self._mtime = mtime
        self.digest = hashlib.sha256(raw).hexdigest()
        self.last_error = None
        return policy_file


def parse_policy_file(raw: bytes | str) -> PolicyFile:
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise TypeError("policy root must be a mapping")
    return PolicyFile.model_validate(data)


def parse_policy(raw: bytes | str, profile: str | None = None) -> Policy:
    policy_file = parse_policy_file(raw)
    return policy_file.resolve(profile or policy_file.active_profile)


def load_policy(path: Path | str, profile: str | None = None) -> Policy:
    """Effective policy of ``profile`` (default: the file's active_profile)."""
    return parse_policy(Path(path).read_text(encoding="utf-8"), profile)
