"""BoundaryMiddleware, TrustedHost and response hardening."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, MutableMapping
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from insight.main import MAX_BODY_BYTES, SECURITY_HEADERS, BoundaryMiddleware


@pytest.mark.parametrize('path', ['/health', '/login', '/api/documents', '/does-not-exist'])
def test_security_headers_on_every_response(client: TestClient, path: str) -> None:
    response = client.get(path)
    for name, value in SECURITY_HEADERS:
        assert response.headers[name.decode()] == value.decode()


def test_untrusted_host_is_rejected(client: TestClient) -> None:
    assert client.get('/health', headers={'Host': 'evil.example'}).status_code == 400


def test_cross_origin_requests_are_rejected(authed: TestClient) -> None:
    assert authed.post('/api/demo', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert authed.get('/api/stats', headers={'Origin': 'null'}).status_code == 403
    assert authed.post('/api/demo', headers={'Origin': 'http://testserver'}).status_code == 200


def test_content_length_limits(client: TestClient) -> None:
    assert client.post('/login', headers={'Content-Length': str(MAX_BODY_BYTES + 1)}).status_code == 413
    assert client.post('/login', headers={'Content-Length': 'not-a-number'}).status_code == 413


@pytest.mark.parametrize('method', ['POST', 'PUT', 'PATCH'])
def test_streamed_body_limit_without_content_length(client: TestClient, method: str) -> None:
    def body() -> Iterator[bytes]:
        for _ in range(20):
            yield b'x' * 100_000
        yield b'x'

    request = client.build_request(
        method, '/login', content=body(), headers={'Content-Type': 'application/octet-stream'}
    )
    assert 'content-length' not in request.headers
    assert request.headers['transfer-encoding'] == 'chunked'
    response = client.send(request)
    assert (response.status_code, response.text) == (413, 'Request too large')


def test_streamed_small_json_body_reaches_api(authed: TestClient) -> None:
    encoded = b'{"title": "Streamed", "body": "CVE-2024-12345", "source_name": "Fixture"}'

    def body() -> Iterator[bytes]:
        yield encoded[:20]
        yield encoded[20:]

    request = authed.build_request(
        'POST', '/api/documents', content=body(), headers={'Content-Type': 'application/json'}
    )
    assert 'content-length' not in request.headers
    response = authed.send(request)
    assert response.status_code == 200
    assert response.json()['body'] == 'CVE-2024-12345'


def test_unauthenticated_nicegui_socket_polling_is_forbidden(client: TestClient) -> None:
    assert client.get('/_nicegui_ws/socket.io/?EIO=4&transport=polling').status_code == 403


# --------------------------------------------------------------------------- direct ASGI tests


class Recorder:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.called = False

    async def app(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.called = True
        if scope['type'] == 'http':
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'ok'})

    async def send(self, message: MutableMapping[str, Any]) -> None:
        self.messages.append(dict(message))


async def receive() -> dict[str, Any]:
    return {'type': 'http.request', 'body': b''}


def run(scope: dict[str, Any], *, authenticated: bool = False) -> Recorder:
    recorder = Recorder()
    owner = SimpleNamespace(state=SimpleNamespace(is_authenticated=lambda _session: authenticated))
    middleware = BoundaryMiddleware(recorder.app, owner)  # type: ignore[arg-type]
    asyncio.run(middleware(scope, receive, recorder.send))
    return recorder


def http_scope(*headers: tuple[bytes, bytes]) -> dict[str, Any]:
    return {
        'type': 'http',
        'method': 'GET',
        'path': '/health',
        'scheme': 'http',
        'headers': [(b'host', b'localhost'), *headers],
    }


def test_non_utf8_header_bytes_do_not_crash() -> None:
    """Regression: a single obs-text byte (valid HTTP) in any header caused a 500 on every route."""
    recorder = run(http_scope((b'user-agent', b'caf\xe9')))
    assert recorder.messages[0]['status'] == 200


def test_websocket_requires_authentication() -> None:
    scope = {
        'type': 'websocket',
        'path': '/_nicegui_ws/socket.io/',
        'scheme': 'ws',
        'headers': [(b'host', b'localhost')],
    }
    denied = run(scope, authenticated=False)
    assert denied.messages == [{'type': 'websocket.close', 'code': 1008}]
    assert not denied.called
    allowed = run(scope, authenticated=True)
    assert allowed.called


def test_websocket_cross_origin_rejected_even_when_authenticated() -> None:
    scope = {
        'type': 'websocket',
        'path': '/_nicegui_ws/socket.io/',
        'scheme': 'ws',
        'headers': [(b'host', b'localhost'), (b'origin', b'https://evil.example')],
    }
    recorder = run(scope, authenticated=True)
    assert recorder.messages == [{'type': 'websocket.close', 'code': 1008}]


def test_https_scheme_expects_https_origin() -> None:
    scope = {**http_scope((b'origin', b'https://localhost')), 'scheme': 'https'}
    assert run(scope).messages[0]['status'] == 200
    scope = {**http_scope((b'origin', b'http://localhost')), 'scheme': 'https'}
    assert run(scope).messages[0]['status'] == 403


def test_lifespan_scope_passes_through() -> None:
    recorder = run({'type': 'lifespan'})
    assert recorder.called
    assert recorder.messages == []


def test_client_disconnect_during_upload_stops_processing() -> None:
    recorder = Recorder()
    owner = SimpleNamespace(state=SimpleNamespace(is_authenticated=lambda _session: False))
    middleware = BoundaryMiddleware(recorder.app, owner)  # type: ignore[arg-type]
    stream: list[dict[str, Any]] = [
        {'type': 'http.request', 'body': b'x', 'more_body': True},
        {'type': 'http.disconnect'},
    ]
    messages = iter(stream)

    async def disconnecting() -> dict[str, Any]:
        return next(messages)

    scope = {**http_scope(), 'method': 'POST'}
    asyncio.run(middleware(scope, disconnecting, recorder.send))
    assert not recorder.called
    assert recorder.messages == []


def test_buffered_body_is_replayed_then_falls_through_to_the_server() -> None:
    received: list[dict[str, Any]] = []
    stream: list[dict[str, Any]] = [
        {'type': 'http.request', 'body': b'abc', 'more_body': False},
        {'type': 'http.disconnect'},
    ]
    messages = iter(stream)

    async def source() -> dict[str, Any]:
        return next(messages)

    async def reading_app(scope: Any, receive: Any, send: Any) -> None:
        received.append(await receive())  # replayed from the buffer
        received.append(await receive())  # delegated to the real receive channel
        await send({'type': 'http.response.start', 'status': 204, 'headers': []})
        await send({'type': 'http.response.body', 'body': b''})

    recorder = Recorder()
    owner = SimpleNamespace(state=SimpleNamespace(is_authenticated=lambda _session: False))
    middleware = BoundaryMiddleware(reading_app, owner)  # type: ignore[arg-type]
    asyncio.run(middleware({**http_scope(), 'method': 'POST'}, source, recorder.send))
    assert [m['type'] for m in received] == ['http.request', 'http.disconnect']
    assert received[0]['body'] == b'abc'
    assert recorder.messages[0]['status'] == 204


def test_referrer_policy_lets_browsers_send_a_real_origin(client: TestClient) -> None:
    """Regression (found by the browser gate): with `Referrer-Policy: no-referrer`, Chromium and Firefox send
    `Origin: null` on same-origin form POSTs, the Origin check rejected it, and no browser could sign in."""
    assert client.get('/login').headers['referrer-policy'] == 'same-origin'


def test_same_origin_browser_form_post_is_accepted(client: TestClient) -> None:
    page = client.get('/login')
    token = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        '/login',
        data={'csrf_token': token, 'password': 'longtestpassword'},
        headers={'Origin': 'http://testserver'},  # what a browser sends under the fixed policy
    )
    assert response.status_code == 303


def test_null_origin_stays_forbidden(client: TestClient) -> None:
    """`Origin: null` also comes from sandboxed iframes and data: URLs; never treat it as same-origin."""
    assert client.post('/login', headers={'Origin': 'null'}).status_code == 403


def test_security_headers_never_duplicate_or_override_application_headers() -> None:
    """Regression: `no-store` was appended to NiceGUI's immutable assets as a second Cache-Control header,
    so browsers re-downloaded ~1 MB of framework JavaScript on every page load."""

    async def asset_app(scope: Any, receive: Any, send: Any) -> None:
        headers = [(b'cache-control', b'public, max-age=31536000, immutable')]
        await send({'type': 'http.response.start', 'status': 200, 'headers': headers})
        await send({'type': 'http.response.body', 'body': b''})

    recorder = Recorder()
    owner = SimpleNamespace(state=SimpleNamespace(is_authenticated=lambda _session: False))
    asyncio.run(BoundaryMiddleware(asset_app, owner)(http_scope(), receive, recorder.send))  # type: ignore[arg-type]
    headers = recorder.messages[0]['headers']
    names = [name for name, _ in headers]
    assert len(names) == len(set(names)), 'duplicate response headers'
    assert dict(headers)[b'cache-control'] == b'public, max-age=31536000, immutable'
    assert dict(headers)[b'x-frame-options'] == b'DENY'


def test_sensitive_responses_are_still_not_cached(authed: TestClient) -> None:
    for path in ('/api/stats', '/api/documents', '/login', '/static/app.css'):
        assert authed.get(path).headers['cache-control'] == 'no-store', path
