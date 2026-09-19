"""Optional bearer-token authentication (SECURITY.md §6: the token never appears
in a URL, a log line or an export).

Set `QAVACH_API_TOKEN` and every route except `/api/v1/meta` (which only tells a
client *whether* a token is needed) requires it. Unset, the API stays open and
`/api/v1/meta` says so - the UI then warns, and the API must only be bound to
localhost. This is a shared secret, not a user system: per-user identity and RBAC
are a later task (NOTE.md).

HTTP carries the token as `Authorization: Bearer <token>`. A browser WebSocket
cannot set headers, so the socket carries it as the subprotocol
`qavach.bearer.<token>` (never a query string, which lands in access logs); the
route echoes the subprotocol back so the handshake completes.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]

WS_SUBPROTOCOL_PREFIX = "qavach.bearer."
PUBLIC_PATHS = frozenset({"/api/v1/meta"})
# Agents do not hold the operator token. These routes authenticate themselves
# (enrolment token / request signature, `agent_routes`) and enforce that always.
AGENT_SELF_AUTH = re.compile(r"^/api/v1/agents/(enroll|[^/]+/(spec|results))$")


def _presented_token(scope: Scope) -> str | None:
    headers = {k.lower(): v for k, v in scope.get("headers", [])}
    if scope["type"] == "websocket":
        for proto in scope.get("subprotocols", []):
            if proto.startswith(WS_SUBPROTOCOL_PREFIX):
                return str(proto.removeprefix(WS_SUBPROTOCOL_PREFIX))
        return None
    value = headers.get(b"authorization", b"").decode("latin-1")
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def websocket_subprotocol(scope: Scope) -> str | None:
    """The subprotocol to echo on accept, if the client offered ours."""
    for proto in scope.get("subprotocols", []):
        if proto.startswith(WS_SUBPROTOCOL_PREFIX):
            return str(proto)
    return None


class BearerAuth:
    def __init__(self, app: Any, token: str) -> None:
        if len(token) < 16:
            raise ValueError("QAVACH_API_TOKEN must be at least 16 characters")
        self.app = app
        self._token = token.encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if (
            scope["type"] not in {"http", "websocket"}
            or path in PUBLIC_PATHS
            or (scope["type"] == "http" and AGENT_SELF_AUTH.match(path))
        ):
            await self.app(scope, receive, send)
            return
        presented = _presented_token(scope)
        if presented is not None and hmac.compare_digest(presented.encode(), self._token):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await receive()  # the connect message
            await send({"type": "websocket.close", "code": 4401})
            return
        body = b'{"detail":"authentication required"}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
