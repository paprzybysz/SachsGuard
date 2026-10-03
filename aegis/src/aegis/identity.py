"""JWT identity gate mapping validated claims to role and tenant."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from aegis.controls.deterministic import AuthContext

DEFAULT_JWT_SECRET = "aegis-development-secret-change-me"
DEFAULT_JWT_ISSUER = "aegis"
DEFAULT_JWT_AUDIENCE = "aegis-api"
DEFAULT_JWT_TTL_SECONDS = 3600
# Fallback when no policy is passed; the policy's roles.control_plane is authoritative.
DEFAULT_CONTROL_PLANE_ROLES = ("admin", "security")


@dataclass(frozen=True)
class Principal:
    token: str
    subject: str
    role: str
    tenant: str

    def to_auth(self) -> AuthContext:
        return AuthContext(
            authenticated=True,
            role=self.role,
            subject=self.subject,
            tenant=self.tenant,
        )


class TokenRegistry:
    """Verify HS256 JWTs and derive identity only from validated claims."""

    def __init__(
        self,
        secret: str | None = None,
        *,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        self.secret = secret or os.environ.get("AEGIS_JWT_SECRET", DEFAULT_JWT_SECRET)
        self.issuer = issuer or os.environ.get("AEGIS_JWT_ISSUER", DEFAULT_JWT_ISSUER)
        self.audience = audience or os.environ.get("AEGIS_JWT_AUDIENCE", DEFAULT_JWT_AUDIENCE)

    def resolve_bearer(self, authorization: str | None) -> Principal | None:
        if not authorization:
            return None
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() != "bearer" or not credential.strip():
            return None
        token = credential.strip()
        try:
            claims = jwt.decode(
                token,
                self.secret,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "role", "tenant"]},
            )
        except jwt.InvalidTokenError:
            return None
        values = (claims.get("sub"), claims.get("role"), claims.get("tenant"))
        if not all(isinstance(value, str) and value for value in values):
            return None
        return Principal(token=token, subject=values[0], role=values[1], tenant=values[2])

    def resolve(self, authorization: str | None, *, token_query: str | None = None) -> Principal | None:
        principal = self.resolve_bearer(authorization)
        if principal:
            return principal
        if token_query:
            return self.resolve_bearer(f"Bearer {token_query.strip()}")
        return None

    def is_control_plane(
        self, principal: Principal | None, roles: list[str] | None = None
    ) -> bool:
        """``roles`` comes from ``policy.roles.control_plane``; default admin + security."""
        if principal is None:
            return False
        return principal.role in set(roles if roles is not None else DEFAULT_CONTROL_PLANE_ROLES)


REGISTRY = TokenRegistry()


def issue_token(
    subject: str,
    role: str,
    tenant: str = "default",
    *,
    ttl_seconds: int = DEFAULT_JWT_TTL_SECONDS,
    secret: str | None = None,
) -> str:
    """Issue a local/demo JWT using the gateway's configured signing settings."""
    now = datetime.now(UTC)
    issuer = os.environ.get("AEGIS_JWT_ISSUER", DEFAULT_JWT_ISSUER)
    audience = os.environ.get("AEGIS_JWT_AUDIENCE", DEFAULT_JWT_AUDIENCE)
    signing_secret = secret or os.environ.get("AEGIS_JWT_SECRET", DEFAULT_JWT_SECRET)
    claims: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "tenant": tenant,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
    }
    return jwt.encode(claims, signing_secret, algorithm="HS256")


def issue_demo_token(name: str, *, ttl_seconds: int = DEFAULT_JWT_TTL_SECONDS) -> str:
    """Create a local token for the named demo principal."""
    principals = {
        "demo": ("developer", "default"),
        "demo-teller": ("teller", "default"),
        "demo-admin": ("admin", "default"),
    }
    try:
        role, tenant = principals[name]
    except KeyError as exc:
        raise ValueError(f"unknown demo principal: {name}") from exc
    return issue_token(name, role, tenant, ttl_seconds=ttl_seconds)
