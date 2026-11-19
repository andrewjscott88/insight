"""The sign-in and sign-out pages render in this device's theme (cookie), else the instance default."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from insight.appearance import TEXT_SIZE_COOKIE, THEME_COOKIE
from insight.config import Settings
from insight.main import create_app


def rendered_theme(html: str) -> str:
    match = re.search(r'<html lang="en" data-theme="([^"]*)" data-text="(?:standard|large)">', html)
    assert match, 'page has no data-theme'
    return match.group(1)


def theme_colours(html: str) -> list[tuple[str, str]]:
    """``(media, content)`` of every ``<meta name="theme-color">``."""
    metas = re.findall(r'<meta name="theme-color"(?: media="([^"]*)")? content="([^"]*)">', html)
    return [(media, content) for media, content in metas]


def test_sign_in_follows_the_device_by_default(client: TestClient) -> None:
    page = client.get('/login')
    assert rendered_theme(page.text) == 'system'
    assert theme_colours(page.text) == [
        ('(prefers-color-scheme: light)', '#f3f5f7'),
        ('(prefers-color-scheme: dark)', '#0b121c'),
    ]
    assert '<meta name="viewport" content="width=device-width,initial-scale=1">' in page.text


@pytest.mark.parametrize(('theme', 'colour'), [('light', '#f3f5f7'), ('dark', '#0b121c'), ('system', None)])
def test_sign_in_uses_the_theme_this_device_picked(
    client: TestClient, theme: str, colour: str | None
) -> None:
    client.cookies.set(THEME_COOKIE, theme)
    page = client.get('/login')
    assert rendered_theme(page.text) == theme
    if colour:
        assert theme_colours(page.text) == [('', colour)]


@pytest.mark.parametrize('cookie', ['"><script>alert(1)</script>', 'purple', 'DARKER'])
def test_an_unexpected_cookie_is_ignored_and_never_echoed(client: TestClient, cookie: str) -> None:
    client.cookies.set(THEME_COOKIE, cookie)
    page = client.get('/login')
    assert rendered_theme(page.text) == 'system'
    assert 'script>alert' not in page.text
    assert 'purple' not in page.text


def test_the_instance_default_applies_until_a_device_picks_a_theme(settings: Settings) -> None:
    dark_default = dataclasses.replace(settings, theme='dark')
    with TestClient(create_app(dark_default, with_ui=False)) as client:
        assert rendered_theme(client.get('/login').text) == 'dark'
        client.cookies.set(THEME_COOKIE, 'system')
        assert rendered_theme(client.get('/login').text) == 'system'


def test_sign_out_page_uses_the_theme_and_the_shared_stylesheet(
    client: TestClient, login: Callable[..., str]
) -> None:
    login(client)
    client.cookies.set(THEME_COOKIE, 'light')
    page = client.get('/logout')
    assert page.status_code == 200
    assert rendered_theme(page.text) == 'light'
    assert '<link rel="stylesheet" href="/static/app.css">' in page.text
    assert 'style=' not in page.text, 'inline colours would ignore the theme'
    assert 'Sign out of Insight?' in page.text


def test_the_theme_cookie_is_not_a_credential(client: TestClient) -> None:
    client.cookies.set(THEME_COOKIE, 'dark')
    assert client.get('/api/stats').status_code == 401
    assert client.get('/logout').headers['location'] == '/login'


def test_theme_pages_keep_the_security_headers(client: TestClient) -> None:
    client.cookies.set(THEME_COOKIE, 'light')
    headers = client.get('/login').headers
    assert headers['cache-control'] == 'no-store'
    assert headers['x-frame-options'] == 'DENY'


def rendered_text_size(html: str) -> str:
    match = re.search(r'<html lang="en" data-theme="[^"]*" data-text="([^"]*)">', html)
    assert match, 'page has no data-text'
    return match.group(1)


@pytest.mark.parametrize(
    ('cookie', 'expected'), [(None, 'standard'), ('large', 'large'), ('huge"><b>', 'standard')]
)
def test_sign_in_uses_this_devices_text_size(client: TestClient, cookie: str | None, expected: str) -> None:
    if cookie is not None:
        client.cookies.set(TEXT_SIZE_COOKIE, cookie)
    page = client.get('/login')
    assert rendered_text_size(page.text) == expected
    assert '<b>' not in page.text
