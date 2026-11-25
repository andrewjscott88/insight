"""Environment parsing and fail-closed credential requirements."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from insight.config import DEFAULT_ALLOWED_HOSTS, DEFAULT_MAX_TLP, Settings, parse_max_tlp

GOOD = {'INSIGHT_PASSWORD': 'p' * 12, 'INSIGHT_SESSION_SECRET': 's' * 32}


@pytest.mark.parametrize(
    'env',
    [
        {},
        {'INSIGHT_PASSWORD': 'p' * 11, 'INSIGHT_SESSION_SECRET': 's' * 32},
        {'INSIGHT_PASSWORD': 'p' * 12, 'INSIGHT_SESSION_SECRET': 's' * 31},
        {'INSIGHT_PASSWORD': 'p' * 12},
    ],
)
def test_missing_or_short_credentials_fail_closed(env: dict[str, str]) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_PASSWORD'):
        Settings.from_env(env)


def test_defaults_create_data_dir(tmp_path: Path) -> None:
    data = tmp_path / 'nested' / 'data'
    settings = Settings.from_env({**GOOD, 'INSIGHT_DATA_DIR': str(data)})
    assert data.is_dir()
    assert settings.database_url == f'sqlite:///{data / "insight.db"}'
    assert settings.allowed_hosts == DEFAULT_ALLOWED_HOSTS
    assert settings.secure_cookies is False
    assert 'testserver' not in settings.allowed_hosts


def test_explicit_database_url_does_not_touch_filesystem(tmp_path: Path) -> None:
    data = tmp_path / 'unused'
    settings = Settings.from_env(
        {**GOOD, 'INSIGHT_DATA_DIR': str(data), 'INSIGHT_DATABASE_URL': 'postgresql+psycopg://db/insight'}
    )
    assert settings.database_url == 'postgresql+psycopg://db/insight'
    assert not data.exists()


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        ('example.test', ('example.test',)),
        (' a.test , b.test ,', ('a.test', 'b.test')),
        ('', DEFAULT_ALLOWED_HOSTS),
        (' , ', DEFAULT_ALLOWED_HOSTS),
    ],
)
def test_allowed_hosts_parsing(tmp_path: Path, raw: str, expected: tuple[str, ...]) -> None:
    env = {**GOOD, 'INSIGHT_DATA_DIR': str(tmp_path), 'INSIGHT_ALLOWED_HOSTS': raw}
    assert Settings.from_env(env).allowed_hosts == expected


@pytest.mark.parametrize(('raw', 'expected'), [('1', True), ('true', True), ('0', False), ('no', False)])
def test_secure_cookie_flag(tmp_path: Path, raw: str, expected: bool) -> None:
    env = {**GOOD, 'INSIGHT_DATA_DIR': str(tmp_path), 'INSIGHT_SECURE_COOKIES': raw}
    assert Settings.from_env(env).secure_cookies is expected


def test_reads_process_environment_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {**GOOD, 'INSIGHT_DATA_DIR': str(tmp_path)}.items():
        monkeypatch.setenv(key, value)
    assert Settings.from_env().password == GOOD['INSIGHT_PASSWORD']


def test_settings_are_immutable() -> None:
    settings = Settings(database_url='sqlite://', password='p' * 12, session_secret='s' * 32)
    with pytest.raises(AttributeError):
        settings.password = 'changed'  # type: ignore[misc]


# --------------------------------------------------------------------------- reverse proxy and TLP limit


def test_public_deployment_settings_default_to_safe_values() -> None:
    settings = Settings.from_env(GOOD)
    assert settings.trusted_proxies == ()  # forwarded headers are ignored unless a proxy is named
    assert settings.max_tlp == 'AMBER+STRICT'  # TLP:RED is refused unless explicitly allowed
    assert settings.dev_no_auth is False
    assert Settings(database_url='sqlite://', password='p', session_secret='s').max_tlp == 'AMBER+STRICT'


@pytest.mark.parametrize(('value', 'expected'), [('', False), ('off', False), ('ON', True), (' on ', True)])
def test_password_free_development_access_requires_explicit_opt_in(value: str, expected: bool) -> None:
    settings = Settings.from_env({**GOOD, 'INSIGHT_DEV_NO_AUTH': value})
    assert settings.dev_no_auth is expected
    assert settings.password == GOOD['INSIGHT_PASSWORD']
    assert settings.session_secret == GOOD['INSIGHT_SESSION_SECRET']


@pytest.mark.parametrize('value', ['true', 'yes', '1', 'onn', 'disabled'])
def test_password_free_setting_typos_fail_closed(value: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_DEV_NO_AUTH'):
        Settings.from_env({**GOOD, 'INSIGHT_DEV_NO_AUTH': value})


def test_password_free_access_cannot_claim_to_require_mfa() -> None:
    with pytest.raises(RuntimeError, match='requires INSIGHT_MFA=off'):
        Settings.from_env({**GOOD, 'INSIGHT_DEV_NO_AUTH': 'on', 'INSIGHT_MFA': 'on'})
    with pytest.raises(RuntimeError, match='requires INSIGHT_MFA=off'):
        Settings(
            database_url='sqlite://', password='p' * 12, session_secret='s' * 32, mfa=True, dev_no_auth=True
        )


def test_password_free_access_keeps_credentials_required_for_restoration() -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_PASSWORD'):
        Settings.from_env({**GOOD, 'INSIGHT_DEV_NO_AUTH': 'on', 'INSIGHT_PASSWORD': ''})


def test_trusted_proxies_and_max_tlp_from_env() -> None:
    settings = Settings.from_env(
        {**GOOD, 'INSIGHT_TRUSTED_PROXIES': ' 127.0.0.1, 172.18.0.0/16 ,, ::1 ', 'INSIGHT_MAX_TLP': ' red '}
    )
    assert settings.trusted_proxies == ('127.0.0.1', '172.18.0.0/16', '::1')
    assert settings.max_tlp == 'RED'


@pytest.mark.parametrize(
    ('value', 'message'),
    [
        ('*', 'any client forge its address'),
        ('127.0.0.1, *', 'any client forge its address'),
        ('10.0.0.1/8', "'10.0.0.1/8' is not an IP address or network"),  # host bits set: uvicorn ignores it
        ('proxy.internal', "'proxy.internal' is not an IP address or network"),
        ('300.1.1.1', "'300.1.1.1' is not an IP address"),
    ],
)
def test_invalid_trusted_proxies_fail_closed(value: str, message: str) -> None:
    with pytest.raises(RuntimeError, match=re.escape(message)):
        Settings.from_env({**GOOD, 'INSIGHT_TRUSTED_PROXIES': value})


@pytest.mark.parametrize('value', ['WHITE', 'AMBER STRICT', 'TLP:RED', 'secret'])
def test_invalid_max_tlp_fails_closed(value: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_MAX_TLP must be one of'):
        Settings.from_env({**GOOD, 'INSIGHT_MAX_TLP': value})


@pytest.mark.parametrize('value', ['', '   '])
def test_empty_max_tlp_means_the_default(value: str) -> None:
    assert parse_max_tlp(value) == DEFAULT_MAX_TLP


# --------------------------------------------------------------------------- MFA switch


def test_mfa_is_off_by_default() -> None:
    assert Settings.from_env(GOOD).mfa is False


@pytest.mark.parametrize(('value', 'expected'), [('on', True), ('ON', True), (' 1 ', True), ('yes', True),
                                                 ('true', True), ('off', False), ('0', False), ('no', False),
                                                 ('false', False), ('', False)])  # fmt: skip
def test_mfa_switch(value: str, expected: bool) -> None:
    assert Settings.from_env({**GOOD, 'INSIGHT_MFA': value}).mfa is expected


@pytest.mark.parametrize('value', ['onn', 'enabled', '2', 'totp'])
def test_an_invalid_mfa_switch_fails_closed(value: str) -> None:
    """A typo must stop start-up, never leave sign-in silently password-only."""
    with pytest.raises(RuntimeError, match='INSIGHT_MFA must be "on" or "off"'):
        Settings.from_env({**GOOD, 'INSIGHT_MFA': value})


# ------------------------------------------------------------------- hardened public deployments (TIP 0.3)

HARDENED = {**GOOD, 'INSIGHT_SECURE_COOKIES': '1', 'INSIGHT_MFA': 'on'}


def test_loopback_defaults_are_unchanged() -> None:
    settings = Settings.from_env(GOOD)
    assert settings.require_hardened is False
    assert settings.internet_facing() is False
    assert settings.public_hosts() == []


@pytest.mark.parametrize(
    ('env', 'facing'),
    [
        ({'INSIGHT_ALLOWED_HOSTS': 'localhost,127.0.0.1,::1'}, False),
        ({'INSIGHT_ALLOWED_HOSTS': 'insight.example.org'}, True),
        ({'INSIGHT_ALLOWED_HOSTS': '*'}, True),
        ({'INSIGHT_TRUSTED_PROXIES': '172.18.0.1'}, True),
    ],
)
def test_internet_facing_means_a_public_host_name_or_a_proxy(env: dict[str, str], facing: bool) -> None:
    assert Settings.from_env({**GOOD, **env}).internet_facing() is facing


@pytest.mark.parametrize(
    ('value', 'expected'),
    [('on', True), (' 1 ', True), ('YES', True), ('true', True), ('off', False), ('0', False), ('', False)],
)
def test_require_hardened_switch(value: str, expected: bool) -> None:
    assert Settings.from_env({**HARDENED, 'INSIGHT_REQUIRE_HARDENED': value}).require_hardened is expected


@pytest.mark.parametrize('value', ['onn', 'enabled', '2', 'strict'])
def test_an_invalid_require_hardened_switch_fails_closed(value: str) -> None:
    """A typo must stop start-up, never silently drop the check."""
    with pytest.raises(RuntimeError, match='INSIGHT_REQUIRE_HARDENED must be "on" or "off"'):
        Settings.from_env({**HARDENED, 'INSIGHT_REQUIRE_HARDENED': value})


@pytest.mark.parametrize(
    ('missing', 'named'),
    [
        ({'INSIGHT_SECURE_COOKIES': '0'}, 'INSIGHT_SECURE_COOKIES is off'),
        ({'INSIGHT_MFA': 'off'}, 'INSIGHT_MFA is off'),
    ],
)
def test_require_hardened_refuses_to_start_without_secure_cookies_and_mfa(
    missing: dict[str, str], named: str
) -> None:
    env = {**HARDENED, 'INSIGHT_REQUIRE_HARDENED': 'on', **missing}
    with pytest.raises(
        RuntimeError, match=f'INSIGHT_REQUIRE_HARDENED is on, so Insight will not start: {named}'
    ):
        Settings.from_env(env)


def test_require_hardened_names_every_gap_and_refuses_password_free_access() -> None:
    with pytest.raises(RuntimeError) as refused:
        Settings(
            database_url='sqlite://',
            password='p' * 12,
            session_secret='s' * 32,
            dev_no_auth=True,
            require_hardened=True,
        )
    message = str(refused.value)
    for gap in ('INSIGHT_SECURE_COOKIES is off', 'INSIGHT_MFA is off', 'INSIGHT_DEV_NO_AUTH is on'):
        assert gap in message


def test_require_hardened_starts_with_secure_cookies_and_mfa() -> None:
    settings = Settings.from_env({**HARDENED, 'INSIGHT_REQUIRE_HARDENED': 'on'})
    assert settings.require_hardened is True
    assert settings.hardening_gaps() == []


# --------------------------------------------------------------------------- default colour theme


def test_theme_follows_the_device_by_default() -> None:
    assert Settings.from_env(GOOD).theme == 'system'
    assert Settings(database_url='sqlite://', password='p' * 12, session_secret='s' * 32).theme == 'system'


@pytest.mark.parametrize(('value', 'expected'), [('light', 'light'), ('Dark', 'dark'), (' system ', 'system'),
                                                 ('', 'system')])  # fmt: skip
def test_theme_setting(value: str, expected: str) -> None:
    assert Settings.from_env({**GOOD, 'INSIGHT_THEME': value}).theme == expected


@pytest.mark.parametrize('value', ['drak', 'auto', 'night'])
def test_an_invalid_theme_stops_start_up(value: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_THEME must be one of system, light, dark'):
        Settings.from_env({**GOOD, 'INSIGHT_THEME': value})


# --------------------------------------------------------------------------- scheduled syncs (job runner)


def test_insight_serve_runs_scheduled_syncs_unless_switched_off() -> None:
    assert Settings.from_env(GOOD).run_jobs is True
    assert Settings.from_env({**GOOD, 'INSIGHT_RUN_JOBS': 'OFF'}).run_jobs is False
    assert Settings.from_env({**GOOD, 'INSIGHT_RUN_JOBS': ' on '}).run_jobs is True
    # Settings built in code (tests, tools) never start a runner by accident.
    assert Settings(database_url='sqlite://', password='x', session_secret='y').run_jobs is False


@pytest.mark.parametrize('value', ['1', 'yes', 'true', 'onn'])
def test_an_unclear_run_jobs_switch_stops_start_up(value: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_RUN_JOBS must be "on" or "off"'):
        Settings.from_env({**GOOD, 'INSIGHT_RUN_JOBS': value})


def test_a_wrong_alert_setting_stops_start_up() -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_SMTP_SECURITY'):
        Settings.from_env({**GOOD, 'INSIGHT_SMTP_SECURITY': 'ssl'})


@pytest.mark.parametrize(('value', 'expected'), [('', False), ('off', False), ('on', True), (' ON ', True)])
def test_the_public_view_needs_an_explicit_on(value: str, expected: bool) -> None:
    settings = Settings.from_env({**GOOD, 'INSIGHT_PUBLIC_VIEW': value, 'INSIGHT_MAX_TLP': 'CLEAR'})
    assert settings.public_view is expected


@pytest.mark.parametrize('value', ['1', 'true', 'yes', 'onn'])
def test_public_view_typos_fail_closed(value: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_PUBLIC_VIEW'):
        Settings.from_env({**GOOD, 'INSIGHT_PUBLIC_VIEW': value, 'INSIGHT_MAX_TLP': 'CLEAR'})


@pytest.mark.parametrize('limit', ['', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'])
def test_the_public_view_refuses_to_start_unless_only_clear_is_stored(limit: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_MAX_TLP=CLEAR'):
        Settings.from_env({**GOOD, 'INSIGHT_PUBLIC_VIEW': 'on', 'INSIGHT_MAX_TLP': limit})


def test_the_public_view_replaces_open_access() -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_DEV_NO_AUTH'):
        Settings.from_env(
            {**GOOD, 'INSIGHT_PUBLIC_VIEW': 'on', 'INSIGHT_MAX_TLP': 'CLEAR', 'INSIGHT_DEV_NO_AUTH': 'on'}
        )


def test_the_public_view_works_with_a_hardened_instance() -> None:
    settings = Settings.from_env(
        {
            **GOOD,
            'INSIGHT_PUBLIC_VIEW': 'on',
            'INSIGHT_MAX_TLP': 'CLEAR',
            'INSIGHT_SECURE_COOKIES': '1',
            'INSIGHT_MFA': 'on',
            'INSIGHT_REQUIRE_HARDENED': 'on',
        }
    )
    assert (settings.public_view, settings.hardening_gaps()) == (True, [])
