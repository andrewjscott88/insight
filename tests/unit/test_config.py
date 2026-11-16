"""Environment parsing and fail-closed credential requirements."""

from __future__ import annotations

from pathlib import Path

import pytest

from insight.config import DEFAULT_ALLOWED_HOSTS, Settings

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
