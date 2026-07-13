"""ASGI defense-in-depth controls for the public Solslot API."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.exceptions import HTTPException

from .config import Settings


AsgiReceive = Callable[[], Awaitable[dict[str, Any]]]
AsgiSend = Callable[[dict[str, Any]], Awaitable[None]]


def documentation_urls(settings: Settings) -> dict[str, str | None]:
    enabled = settings.api_docs_enabled
    return {
        "docs_url": "/docs" if enabled else None,
        "redoc_url": "/redoc" if enabled else None,
        "openapi_url": "/openapi.json" if enabled else None,
    }


class ServerHardeningMiddleware:
    """Cap request work and attach browser-facing security headers.

    The reverse proxy remains the first line of defense. These checks make a
    proxy routing mistake bounded instead of turning it into an unprotected
    uvicorn listener.
    """

    def __init__(self, app: Any, *, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def hardened_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
                if self.settings.security_headers_enabled:
                    message["headers"] = self._security_headers(
                        list(message.get("headers") or []),
                    )
            await send(message)

        content_length = self._content_length(scope)
        if content_length is None:
            await self._json_error(
                hardened_send,
                status_code=400,
                detail="Invalid Content-Length header.",
            )
            return
        if content_length > self.settings.max_request_body_bytes:
            await self._json_error(
                hardened_send,
                status_code=413,
                detail="Request body exceeds the configured limit.",
            )
            return

        received_bytes = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body") or b"")
                if received_bytes > self.settings.max_request_body_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Request body exceeds the configured limit.",
                    )
            return message

        try:
            await asyncio.wait_for(
                self.app(scope, limited_receive, hardened_send),
                timeout=self.settings.request_timeout_seconds,
            )
        except TimeoutError:
            if not response_started:
                await self._json_error(
                    hardened_send,
                    status_code=504,
                    detail="Request processing timed out.",
                )

    def _security_headers(
        self,
        headers: list[tuple[bytes, bytes]],
    ) -> list[tuple[bytes, bytes]]:
        values = {
            b"cache-control": b"no-store",
            b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
            b"referrer-policy": b"no-referrer",
            b"x-content-type-options": b"nosniff",
            b"x-frame-options": b"DENY",
        }
        if not self.settings.api_docs_enabled:
            values[b"content-security-policy"] = (
                b"default-src 'none'; frame-ancestors 'none'; "
                b"base-uri 'none'; form-action 'none'"
            )
        if (
            self.settings.hsts_enabled
            and self.settings.runtime_environment in {"staging", "production"}
        ):
            values[b"strict-transport-security"] = (
                b"max-age=31536000; includeSubDomains"
            )

        names = set(values)
        hardened = [(name, value) for name, value in headers if name.lower() not in names]
        hardened.extend(values.items())
        return hardened

    @staticmethod
    def _content_length(scope: dict[str, Any]) -> int | None:
        values = [
            value
            for name, value in scope.get("headers") or []
            if name.lower() == b"content-length"
        ]
        if not values:
            return 0
        if len(values) != 1:
            return None
        try:
            length = int(values[0].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return None
        return length if length >= 0 else None

    @staticmethod
    async def _json_error(
        send: AsgiSend,
        *,
        status_code: int,
        detail: str,
    ) -> None:
        body = json.dumps(
            {"detail": detail},
            separators=(",", ":"),
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


__all__ = ["ServerHardeningMiddleware", "documentation_urls"]
