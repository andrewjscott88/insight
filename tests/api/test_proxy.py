"""Running behind a TLS-terminating reverse proxy (INSIGHT_TRUSTED_PROXIES).

The proxy connects from its own address over plain HTTP and forwards the browser's scheme and address in
``X-Forwarded-Proto``/``X-Forwarded-For``. Those headers are believed only from the configured proxy.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from insight.config import Settings
from insight.main import create_app

PROXY = ('10.0.0.2', 40000)
STRANGER = ('198.51.100.7', 40000)
BROWSER = {'Origin': 'https://testserver', 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.5'}


def make_app(settings: Settings, *proxies: str) -> FastAPI:
    return create_app(dataclasses.replace(settings, trusted_proxies=proxies), with_ui=False)


def browser_sign_in(app: FastAPI, peer: tuple[str, int], csrf_token_from: Callable[[str], str]) -> int:
    """A browser's sign-in form POST as it arrives through the proxy; returns the status code."""
    with TestClient(app, client=peer, follow_redirects=False) as client:
        # Browsers send no Origin on a top-level page load, only on the form POST.
        page = client.get('/login', headers={k: v for k, v in BROWSER.items() if k != 'Origin'})
        token = csrf_token_from(page.text)
        data = {'csrf_token': token, 'password': 'longtestpassword'}
        return client.post('/login', data=data, headers=BROWSER).status_code


def test_without_the_setting_browsers_behind_an_https_proxy_cannot_sign_in(
    settings: Settings, csrf_token_from: Callable[[str], str]
) -> None:
    """The bug this setting fixes: the app sees http, the browser's Origin says https, so the POST is 403."""
    assert browser_sign_in(make_app(settings), PROXY, csrf_token_from) == 403


def test_with_the_proxy_trusted_browsers_sign_in(
    settings: Settings, csrf_token_from: Callable[[str], str]
) -> None:
    assert browser_sign_in(make_app(settings, '10.0.0.2'), PROXY, csrf_token_from) == 303
    assert browser_sign_in(make_app(settings, '10.0.0.0/24'), PROXY, csrf_token_from) == 303


def test_other_clients_cannot_forge_the_headers(
    settings: Settings, csrf_token_from: Callable[[str], str]
) -> None:
    assert browser_sign_in(make_app(settings, '10.0.0.2'), STRANGER, csrf_token_from) == 403


def test_a_cross_site_origin_is_still_refused_through_the_proxy(settings: Settings) -> None:
    with TestClient(make_app(settings, '10.0.0.2'), client=PROXY) as client:
        response = client.post('/login', headers={**BROWSER, 'Origin': 'https://evil.example'})
        assert response.status_code == 403


def bad_key(client: TestClient, forwarded_for: str) -> int:
    headers = {'Authorization': 'Bearer wrong', 'X-Forwarded-For': forwarded_for}
    return client.get('/api/stats', headers=headers).status_code


def test_invalid_key_limit_applies_per_real_client_behind_the_proxy(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger='insight.auth')
    with TestClient(make_app(settings, '10.0.0.2'), client=PROXY) as client:
        assert [bad_key(client, '203.0.113.5') for _ in range(11)] == [401] * 10 + [429]
        assert bad_key(client, '203.0.113.6') == 401  # another client behind the same proxy is unaffected
        # A client cannot claim another address: the proxy appends the real one, which is what counts.
        assert bad_key(client, '192.0.2.99, 203.0.113.5') == 429
    assert 'Rejected API key (malformed) from 203.0.113.5' in caplog.text
    assert 'from 10.0.0.2' not in caplog.text


def test_forged_addresses_from_untrusted_clients_share_one_bucket(settings: Settings) -> None:
    with TestClient(make_app(settings, '10.0.0.2'), client=STRANGER) as client:
        statuses = [bad_key(client, f'203.0.113.{n}') for n in range(11)]
    assert statuses == [401] * 10 + [429]


def test_proxy_headers_are_read_before_every_other_check(settings: Settings) -> None:
    configured: list[object] = [m.cls for m in make_app(settings, '10.0.0.2').user_middleware]
    unconfigured: list[object] = [m.cls for m in make_app(settings).user_middleware]
    assert configured[0] is ProxyHeadersMiddleware  # outermost
    assert ProxyHeadersMiddleware not in unconfigured


def test_startup_logs_the_trusted_proxies_and_warns_about_insecure_cookies(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger='insight.auth')
    make_app(settings, '10.0.0.2', '172.18.0.0/16')
    assert 'Trusting X-Forwarded-For/-Proto from: 10.0.0.2, 172.18.0.0/16' in caplog.text
    assert 'set INSIGHT_SECURE_COOKIES=1' in caplog.text
    caplog.clear()
    create_app(
        dataclasses.replace(settings, trusted_proxies=('10.0.0.2',), secure_cookies=True), with_ui=False
    )
    assert 'INSIGHT_SECURE_COOKIES' not in caplog.text
