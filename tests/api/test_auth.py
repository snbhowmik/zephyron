"""Optional bearer-token auth (`qavach_api.auth`) over HTTP and WebSocket."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from qavach_api.auth import BearerAuth, websocket_subprotocol
from starlette.websockets import WebSocketDisconnect

TOKEN = "s3cret-token-0123456789abcdef"


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()

    @app.get("/api/v1/meta")
    def meta() -> dict[str, str]:
        return {"auth": "bearer"}

    @app.get("/api/v1/scans")
    def scans() -> list[str]:
        return []

    @app.websocket("/api/v1/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept(subprotocol=websocket_subprotocol(socket.scope))
        await socket.send_json({"ok": True})
        await socket.close()

    app.add_middleware(BearerAuth, token=TOKEN)
    return TestClient(app)


def test_meta_is_public_so_a_client_can_learn_a_token_is_needed(client: TestClient) -> None:
    assert client.get("/api/v1/meta").status_code == 200


def test_missing_wrong_and_malformed_credentials_are_401(client: TestClient) -> None:
    assert client.get("/api/v1/scans").status_code == 401
    assert client.get("/api/v1/scans", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/v1/scans", headers={"Authorization": TOKEN}).status_code == 401
    assert (
        client.get("/api/v1/scans", headers={"Authorization": "Basic " + TOKEN}).status_code == 401
    )
    assert client.get("/api/v1/scans").headers["www-authenticate"] == "Bearer"


def test_right_token_passes(client: TestClient) -> None:
    ok = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200


def test_token_in_a_query_string_is_not_accepted(client: TestClient) -> None:
    assert client.get(f"/api/v1/scans?token={TOKEN}").status_code == 401


def test_websocket_needs_the_subprotocol_token(client: TestClient) -> None:
    """Refused at the handshake (the ASGI spec turns a close-before-accept into an
    HTTP 403), so the handler is never reached."""
    with pytest.raises(WebSocketDisconnect), client.websocket_connect("/api/v1/ws"):
        pass
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/api/v1/ws", subprotocols=["qavach.bearer.wrong-token-value"]),
    ):
        pass
    with client.websocket_connect("/api/v1/ws", subprotocols=[f"qavach.bearer.{TOKEN}"]) as socket:
        assert socket.receive_json() == {"ok": True}


def test_short_token_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="16"):
        BearerAuth(FastAPI(), token="short")
