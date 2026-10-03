"""Thin SDK wrapper — drop-in helper for apps/agents calling through Aegis."""

from __future__ import annotations

from typing import Any, Self

import httpx

from aegis.identity import issue_token


class AegisClient:
    """Minimal client for evaluate / chat / MCP paths."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        *,
        role: str | None = "developer",
        tenant: str = "default",
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.role = role
        self.tenant = tenant
        token = api_key or issue_token("sdk", role or "developer", tenant)
        self._client = httpx.Client(
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def evaluate(self, text: str, **kwargs: Any) -> dict[str, Any]:
        payload = {"text": text, "tenant": self.tenant, **kwargs}
        response = self._client.post(f"{self.base_url}/v1/evaluate", json=payload)
        response.raise_for_status()
        return response.json()

    def chat(self, content: str, *, model: str = "demo-echo") -> dict[str, Any]:
        response = self._client.post(
            f"{self.base_url}/v1/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": content}]},
        )
        return {"status_code": response.status_code, "body": response.json()}

    def mcp_invoke(self, tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self._client.post(
            f"{self.base_url}/v1/mcp/invoke",
            json={
                "tool_name": tool_name,
                "arguments": arguments or {},
                "tenant": self.tenant,
            },
        )
        return {"status_code": response.status_code, "body": response.json()}
