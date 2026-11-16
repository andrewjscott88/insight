"""The outbound fetcher: registry allow-list, public-DNS check, redirect refusal and size limits."""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

from insight import connectors
from insight.connectors import MAX_BYTES, download

KEV_URL = connectors.SOURCES['cisa-kev'].url
PUBLIC_V4 = '8.8.8.8'
PUBLIC_V6 = '2001:4860:4860::8888'


def resolver(*addresses: str) -> Callable[..., list[Any]]:
    def fake_getaddrinfo(host: str, port: int, *_args: Any, **_kwargs: Any) -> list[Any]:
        return [
            (socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port))
            for a in addresses
        ]

    return fake_getaddrinfo


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, 'getaddrinfo', resolver(PUBLIC_V4, PUBLIC_V6))


def transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.usefixtures('public_dns')
async def test_successful_download_sends_safe_headers_and_params() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'{"ok": true}')

    url = connectors.PROVIDERS['epss']
    body = await download(url, {'cve': 'CVE-2024-12345'}, transport=transport(handler))
    assert body == b'{"ok": true}'
    (request,) = seen
    assert request.url.params['cve'] == 'CVE-2024-12345'
    assert request.headers['user-agent'].startswith('Insight/')
    assert request.headers['accept-encoding'] == 'identity'


@pytest.mark.parametrize(
    'url',
    [
        'http://www.cisa.gov/file',  # plain HTTP
        'https://127.0.0.1/',  # not in registry
        'https://evil.example/',
        'https://user:pass@www.cisa.gov/',  # credentials
        'https://user@www.cisa.gov/',
        'https://www.cisa.gov:444/',  # non-standard port
        'https://www.cisa.gov:notaport/',  # malformed port
        'ftp://www.cisa.gov/',
    ],
)
async def test_registry_rejections_happen_before_any_network(url: str) -> None:
    # The autouse network guard would raise OSError if DNS or a socket were touched.
    with pytest.raises(ValueError, match='registry'):
        await download(url)


@pytest.mark.parametrize(
    'addresses',
    [('127.0.0.1',), ('10.0.0.5',), ('169.254.169.254',), ('::1',), (PUBLIC_V4, '192.168.1.1'), ()],
)
async def test_non_public_resolution_is_refused(
    monkeypatch: pytest.MonkeyPatch, addresses: tuple[str, ...]
) -> None:
    monkeypatch.setattr(socket, 'getaddrinfo', resolver(*addresses))
    with pytest.raises(ValueError, match='non-public'):
        await download(KEV_URL, transport=transport(lambda _: httpx.Response(200)))


@pytest.mark.usefixtures('public_dns')
@pytest.mark.parametrize('status', [301, 302, 307, 308])
async def test_redirects_are_refused_with_a_clear_message(status: int) -> None:
    # Regression: raise_for_status() ran first, so this message was unreachable dead code.
    redirect = transport(lambda _: httpx.Response(status, headers={'Location': 'https://evil.example/'}))
    with pytest.raises(ValueError, match='Redirects are disabled'):
        await download(KEV_URL, transport=redirect)


@pytest.mark.usefixtures('public_dns')
@pytest.mark.parametrize('status', [403, 404, 429, 500, 503])
async def test_http_errors_raise(status: int) -> None:
    with pytest.raises(httpx.HTTPStatusError):
        await download(KEV_URL, transport=transport(lambda _: httpx.Response(status)))


@pytest.mark.usefixtures('public_dns')
async def test_payload_size_limit_is_enforced_while_streaming() -> None:
    produced: list[int] = []

    async def endless() -> AsyncIterator[bytes]:
        while True:  # An unbounded body: the client must stop reading on its own.
            produced.append(1)
            yield b'x' * 1_000_000

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=endless())

    with pytest.raises(ValueError, match='8 MB'):
        await download(KEV_URL, transport=transport(handler))
    assert len(produced) == MAX_BYTES // 1_000_000 + 1  # stopped as soon as the limit was crossed


@pytest.mark.usefixtures('public_dns')
async def test_payload_at_limit_is_accepted() -> None:
    body = await download(
        KEV_URL, transport=transport(lambda _: httpx.Response(200, content=b'x' * MAX_BYTES))
    )
    assert len(body) == MAX_BYTES


async def test_dns_failure_propagates() -> None:
    # The autouse guard makes getaddrinfo raise OSError, exactly like a resolver outage.
    with pytest.raises(OSError, match='disabled'):
        await download(KEV_URL)
