"""Review L1 (TIP 0.4): outbound requests go to the address Insight checked, never to a second DNS answer."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Collection
from typing import Any

import httpx
import pytest

from insight import alerts, connectors, egress
from insight.alerts import AlertError, check_address
from insight.connectors import download
from insight.models import AlertTarget

PUBLIC = '93.184.216.34'
OTHER_PUBLIC = '93.184.216.35'
EPSS_URL = connectors.PROVIDERS['epss']


def rebinding(*answers: list[str]) -> tuple[Callable[..., list[Any]], list[str]]:
    """A resolver that gives each answer in turn (the last one from then on), and records the lookups."""
    asked: list[str] = []

    def fake(host: str, port: int, *_: Any, **__: Any) -> list[Any]:
        answer = answers[min(len(asked), len(answers) - 1)]
        asked.append(host)
        return [
            (socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port))
            for a in answer
        ]

    return fake, asked


def recorder(seen: list[httpx.Request], fail_hosts: Collection[str] = ()) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host in fail_hosts:
            raise httpx.ConnectError('refused', request=request)
        seen.append(request)
        return httpx.Response(200, content=b'{}')

    return httpx.MockTransport(handler)


@pytest.mark.parametrize(
    ('address', 'public', 'never'),
    [
        ('::ffff:127.0.0.1', False, False),
        ('::ffff:169.254.169.254', False, True),
        ('::ffff:10.0.0.1', False, False),
        ('::ffff:93.184.216.34', True, False),
        ('169.254.169.254', False, True),
        ('fe80::1', False, True),
        ('2001:4860:4860::8888', True, False),
    ],
)
def test_mapped_ipv4_addresses_are_judged_by_the_address_they_reach(
    address: str, public: bool, never: bool
) -> None:
    parsed = ipaddress.ip_address(address)
    assert (egress.is_public(parsed), egress.never_allowed(parsed)) == (public, never)


@pytest.mark.parametrize(
    ('address', 'private'),
    [
        ('10.0.0.1', True),
        ('172.16.5.4', True),
        ('192.168.1.1', True),
        ('100.64.0.1', True),  # shared address space (carrier-grade NAT)
        ('fd00::1', True),
        ('::ffff:10.0.0.1', True),
        ('127.0.0.1', False),
        ('::1', False),
        ('::ffff:127.0.0.1', False),
        ('169.254.169.254', False),
        ('fe80::1', False),
        ('0.0.0.0', False),
        ('8.8.8.8', False),  # public, not private
    ],
)
def test_the_private_network_opt_in_never_covers_loopback_or_metadata(address: str, private: bool) -> None:
    assert egress.is_private_network(ipaddress.ip_address(address)) is private


async def test_downloads_stay_public_unless_one_call_opts_in(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str, port: int) -> list[egress.IPAddress]:
        return [ipaddress.ip_address('10.0.0.9')]

    monkeypatch.setattr(egress, 'resolve', resolve)
    seen: list[httpx.Request] = []
    url = 'https://misp.internal.example/x'
    with pytest.raises(connectors.NonPublicDestination, match='non-public destination'):
        await connectors.download(
            url, allowed_hosts=frozenset({'misp.internal.example'}), transport=recorder(seen)
        )
    assert seen == []
    await connectors.download(
        url, allowed_hosts=frozenset({'misp.internal.example'}), allow_private=True, transport=recorder(seen)
    )
    assert [r.url.host for r in seen] == ['10.0.0.9']


def test_pin_keeps_the_host_name_for_tls_and_the_host_header() -> None:
    v4 = egress.pin('https://api.first.org/data/v1/epss?cve=X', ipaddress.ip_address(PUBLIC))
    assert v4 == egress.Pinned(
        f'https://{PUBLIC}/data/v1/epss?cve=X', {'Host': 'api.first.org'}, {'sni_hostname': 'api.first.org'}
    )
    v6 = egress.pin('https://Hooks.Example.org:8443/x', ipaddress.ip_address('2001:db8::1'))
    assert v6.url == 'https://[2001:db8::1]:8443/x'
    assert v6.headers == {'Host': 'hooks.example.org:8443'}


@pytest.mark.parametrize(
    ('authority', 'host_header', 'tls_host'),
    [
        ('feeds.example.org', 'feeds.example.org', 'feeds.example.org'),
        ('192.0.2.7:443', '192.0.2.7', '192.0.2.7'),
        ('[2001:db8::a]:443', '[2001:db8::a]', '2001:db8::a'),
        ('[2001:db8::a]:8443', '[2001:db8::a]:8443', '2001:db8::a'),
    ],
)
def test_pinned_http_authority_and_tls_host(authority: str, host_header: str, tls_host: str) -> None:
    target = egress.pin(f'https://{authority}/feed', ipaddress.ip_address('2001:db8::a'))
    assert target.headers['Host'] == host_header
    assert target.extensions['sni_hostname'] == tls_host


async def test_resolve_lists_ipv4_first_without_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, _ = rebinding(['2001:4860:4860::8888', PUBLIC, PUBLIC])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    assert [str(a) for a in await egress.resolve('example.org', 443)] == [PUBLIC, '2001:4860:4860::8888']


async def test_regression_l1_a_download_goes_to_the_checked_address(monkeypatch: pytest.MonkeyPatch) -> None:
    """Public on the first lookup, loopback on any later one: the request must still go to the public one."""
    fake, asked = rebinding([PUBLIC], ['127.0.0.1'])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    seen: list[httpx.Request] = []
    await download(EPSS_URL, {'cve': 'CVE-2024-12345'}, transport=recorder(seen))
    (request,) = seen
    assert asked == ['api.first.org']  # one lookup only
    assert request.url.host == PUBLIC
    assert request.headers['host'] == 'api.first.org'
    assert request.extensions['sni_hostname'] == 'api.first.org'
    assert request.url.params['cve'] == 'CVE-2024-12345'


@pytest.mark.parametrize(
    'answer', [['::ffff:127.0.0.1'], ['::ffff:169.254.169.254'], [PUBLIC, '::ffff:10.0.0.1']]
)
async def test_regression_l1_downloads_refuse_mapped_private_addresses(
    monkeypatch: pytest.MonkeyPatch, answer: list[str]
) -> None:
    fake, _ = rebinding(answer)
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    with pytest.raises(ValueError, match='non-public destination'):
        await download(EPSS_URL, transport=recorder([]))


async def test_a_download_tries_the_next_checked_address_when_one_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake, _ = rebinding([PUBLIC, OTHER_PUBLIC])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    seen: list[httpx.Request] = []
    await download(EPSS_URL, transport=recorder(seen, {PUBLIC}))
    assert [r.url.host for r in seen] == [OTHER_PUBLIC]
    with pytest.raises(httpx.ConnectError):
        await download(EPSS_URL, transport=recorder([], {PUBLIC, OTHER_PUBLIC}))


async def test_failed_answers_name_the_host_not_the_address(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, _ = rebinding([PUBLIC])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    transport = httpx.MockTransport(lambda request: httpx.Response(404))
    with pytest.raises(httpx.HTTPStatusError) as caught:
        await download(EPSS_URL, transport=transport)
    assert str(caught.value) == f"Client error '404 Not Found' for url '{EPSS_URL}'"
    assert caught.value.response.status_code == 404


async def test_regression_l1_a_webhook_goes_to_the_checked_address(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, asked = rebinding([PUBLIC], ['169.254.169.254'])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    seen: list[httpx.Request] = []
    target = AlertTarget(name='Chat', kind='webhook', style='chat', address='https://hooks.example.org/x')
    message = alerts.Message('CLEAR', 'Subject', ('TLP:CLEAR', 'Line'), {})
    await alerts.send_webhook(target, message, allow_private=False, transport=recorder(seen))
    (request,) = seen
    assert asked == ['hooks.example.org']
    assert (request.url.host, request.headers['host']) == (PUBLIC, 'hooks.example.org')
    assert request.extensions['sni_hostname'] == 'hooks.example.org'


@pytest.mark.parametrize('mapped', ['::ffff:127.0.0.1', '::ffff:169.254.169.254'])
async def test_regression_l1_webhooks_refuse_mapped_private_addresses(
    monkeypatch: pytest.MonkeyPatch, mapped: str
) -> None:
    fake, _ = rebinding([mapped])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    with pytest.raises(AlertError):
        await check_address('https://hooks.example.org/x', allow_private=False)


async def test_a_mapped_metadata_address_is_refused_even_for_private_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake, _ = rebinding(['::ffff:169.254.169.254'])
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    with pytest.raises(AlertError, match='never go to'):
        await check_address('https://hooks.example.org/x', allow_private=True)
