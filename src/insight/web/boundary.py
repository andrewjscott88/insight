"""The ASGI boundary: body-size limit, authentication gate, CSRF and rate limits, security headers."""

from __future__ import annotations

import hmac
from typing import Any, Final
from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_BYTES: Final = 2_000_000

SAFE_METHODS: Final = frozenset({'GET', 'HEAD', 'OPTIONS'})

#: Routes only a signed-in browser session may use (an API key has no CSRF token to fetch). The demo loads
#: synthetic reports: a script must not add practice data to a production dataset (code review L4).
SESSION_ONLY_ROUTES: Final = frozenset({'/api/session', '/api/demo'})

#: Settings only a signed-in browser session (or the host's CLI) may change: how often Insight goes online by
#: itself is the operator's decision, not a script's.
SESSION_ONLY_WRITE_PREFIXES: Final = ('/api/schedules',)

#: Routes a TLP-limited key may not use: the audit log and CVE enrichment reveal things about reports the
#: key cannot see (audit details, whether a CVE is mentioned anywhere), and watch terms often name clients,
#: internal host names or sensitive projects (code review L3).
UNLIMITED_READER_PREFIXES: Final = ('/api/audit', '/api/enrichment/', '/api/watch-terms')

HSTS: Final = (b'strict-transport-security', b'max-age=31536000')

SECURITY_HEADERS: Final = (
    (b'x-content-type-options', b'nosniff'),
    (b'x-frame-options', b'DENY'),
    # Not 'no-referrer': under that policy browsers send `Origin: null` on same-origin form POSTs, which the
    # Origin check below (correctly) rejects, so nobody could sign in from a real browser (0.1.0 bug, found
    # by the Playwright gate). 'same-origin' still never leaks URLs to other sites.
    (b'referrer-policy', b'same-origin'),
    (b'cache-control', b'no-store'),
)


def tokens_match(supplied: object, expected: object) -> bool:
    """Constant-time CSRF comparison that fails closed when either token is absent or empty."""
    if not isinstance(supplied, str) or not isinstance(expected, str) or not supplied or not expected:
        return False
    return hmac.compare_digest(supplied.encode(), expected.encode())


def _mcp_origin_valid(origin: str) -> bool:
    """A present MCP Origin must be one serialized HTTP origin, not an empty/null or malformed URL."""
    if not origin or any(ord(char) < 33 or ord(char) > 126 for char in origin):
        return False
    try:
        parsed = urlsplit(origin)
        port = parsed.port  # Reject malformed and out-of-range ports.
        return (
            parsed.scheme in ('http', 'https')
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not (parsed.path or parsed.query or parsed.fragment)
            and not parsed.netloc.endswith(':')
            and (port is None or port > 0)
        )
    except ValueError:
        return False


class BoundaryMiddleware:
    """Same-origin, socket-authentication and request-size boundary; adds defensive response headers."""

    def __init__(self, app: ASGIApp, owner: FastAPI) -> None:
        self.app, self.owner = app, owner

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] not in ('http', 'websocket'):
            await self.app(scope, receive, send)
            return
        # ASGI header values are raw bytes; HTTP permits obs-text (0x80-0xFF), so decode as latin-1.
        headers = {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in scope.get('headers', [])}
        origin = headers.get('origin')
        if scope['type'] == 'http' and scope.get('path') == '/mcp' and origin is not None:
            origins = [value for name, value in scope.get('headers', []) if name.lower() == b'origin']
            if len(origins) != 1 or not _mcp_origin_valid(origin):
                await Response('Forbidden', status_code=403)(scope, receive, send)
                return
        scheme = 'https' if scope.get('scheme') in ('https', 'wss') else 'http'
        expected = f'{scheme}://{headers.get("host", "")}'
        is_socket = scope['type'] == 'websocket' or '_nicegui_ws' in scope.get('path', '')
        if (origin and origin != expected) or (
            is_socket and not self.owner.state.is_authenticated(scope.get('session', {}))
        ):
            if scope['type'] == 'websocket':
                await send({'type': 'websocket.close', 'code': 1008})
                return
            await Response('Forbidden', status_code=403)(scope, receive, send)
            return
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        try:
            size = int(headers.get('content-length', '0'))
        except ValueError:
            size = MAX_BODY_BYTES + 1
        if size > MAX_BODY_BYTES:
            await Response('Request too large', status_code=413)(scope, receive, send)
            return
        if scope.get('method') in ('POST', 'PUT', 'PATCH'):
            chunks: list[Message] = []
            total = 0
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                total += len(message.get('body', b''))
                if total > MAX_BODY_BYTES:
                    await Response('Request too large', status_code=413)(scope, receive, send)
                    return
                chunks.append(message)
                if not message.get('more_body', False):
                    break
            original_receive = receive

            async def buffered_receive() -> Message:
                if chunks:
                    return chunks.pop(0)
                return await original_receive()

            receive = buffered_receive

        # Created here so the route's `request.state` and this middleware share one dict.
        state: dict[str, Any] = scope.setdefault('state', {})
        settings = getattr(self.owner.state, 'settings', None)
        secure = bool(getattr(settings, 'secure_cookies', False))

        async def secure_send(message: Message) -> None:
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                present = {name.lower() for name, _ in headers}
                # Rate-limit status for the caller (set by the auth dependency on every limited API request).
                for name, value in state.get('rate_limit_headers', {}).items():
                    if name.lower().encode() not in present:
                        headers.append((name.lower().encode('latin-1'), value.encode('latin-1')))
                # Never override a header the application set itself. NiceGUI serves its versioned assets
                # with `Cache-Control: immutable`; also appending `no-store` made browsers re-download ~1 MB
                # of JavaScript on every page load (0.1.0 bug). Sensitive pages and API responses set no
                # Cache-Control of their own, so they still get `no-store`.
                headers.extend((name, value) for name, value in SECURITY_HEADERS if name not in present)
                # HSTS only when the deployment says it is HTTPS-only; browsers ignore it over plain HTTP.
                if secure and HSTS[0] not in present:
                    headers.append(HSTS)
                message['headers'] = headers
            await send(message)

        await self.app(scope, receive, secure_send)
