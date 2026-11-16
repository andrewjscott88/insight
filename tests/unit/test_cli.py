"""Command-line behaviour: credential bootstrap safety and server wiring."""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from insight import __version__, cli


@pytest.fixture(autouse=True)
def _isolated_insight_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    """``serve``/``migrate`` configure the process-wide ``insight`` logger; restore it after each test.

    Without this, later tests that capture ``insight.*`` records saw nothing (found when mutmut ran tests in a
    different order under pytest 8).
    """
    logger = logging.getLogger('insight')
    monkeypatch.setattr(logger, 'handlers', list(logger.handlers))
    monkeypatch.setattr(logger, 'propagate', logger.propagate)
    monkeypatch.setattr(logger, 'level', logger.level)


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_init_creates_private_env_file(in_tmp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['init']) == 0
    env = in_tmp / '.env'
    values = dict(line.split('=', 1) for line in env.read_text().splitlines())
    assert set(values) == {'INSIGHT_PASSWORD', 'INSIGHT_SESSION_SECRET'}
    assert len(values['INSIGHT_PASSWORD']) >= 12
    assert len(values['INSIGHT_SESSION_SECRET']) >= 32
    if sys.platform != 'win32':
        assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert 'Created .env' in capsys.readouterr().out


def test_init_never_overwrites_credentials(in_tmp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = in_tmp / '.env'
    env.write_text('INSIGHT_PASSWORD=keep-me\n')
    # Regression: this used to crash with an unhandled FileExistsError traceback.
    assert cli.main(['init']) == 1
    assert env.read_text() == 'INSIGHT_PASSWORD=keep-me\n'
    assert 'refusing to overwrite' in capsys.readouterr().err


def test_init_generates_unique_secrets(tmp_path: Path) -> None:
    a, b = tmp_path / 'a.env', tmp_path / 'b.env'
    assert cli.init_env(a)
    assert cli.init_env(b)
    assert a.read_text() != b.read_text()


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(['--version'])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f'insight {__version__}'


@pytest.mark.parametrize(
    ('argv', 'host', 'port'),
    [([], '127.0.0.1', 8080), (['serve', '--host', '0.0.0.0', '--port', '9000'], '0.0.0.0', 9000)],
)
def test_serve_wires_uvicorn_safely(
    monkeypatch: pytest.MonkeyPatch, in_tmp: Path, argv: list[str], host: str, port: int
) -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr('uvicorn.run', lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr('dotenv.load_dotenv', lambda *a, **k: True)
    assert cli.main(argv) == 0
    ((args, kwargs),) = calls
    assert args == ('insight.main:create_app',)
    assert kwargs['factory'] is True
    assert (kwargs['host'], kwargs['port']) == (host, port)
    # Single worker (in-memory sessions) and no trust of client-supplied proxy headers.
    assert kwargs['workers'] == 1
    assert kwargs['proxy_headers'] is False


def test_invalid_command_exits_with_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(['destroy'])
    assert exc.value.code == 2
    assert 'invalid choice' in capsys.readouterr().err


def test_serve_loads_env_file_from_working_directory(monkeypatch: pytest.MonkeyPatch, in_tmp: Path) -> None:
    """Regression: bare load_dotenv() searched from the installed module's directory, not the CWD."""
    monkeypatch.setattr(os, 'environ', {k: v for k, v in os.environ.items() if not k.startswith('INSIGHT_')})
    (in_tmp / '.env').write_text('INSIGHT_PASSWORD=from-dotenv-file\nINSIGHT_SESSION_SECRET=s\n')
    seen: dict[str, str] = {}
    monkeypatch.setattr('uvicorn.run', lambda *a, **k: seen.update(os.environ))
    assert cli.main(['serve']) == 0
    assert seen['INSIGHT_PASSWORD'] == 'from-dotenv-file'


def test_real_environment_takes_precedence_over_env_file(
    monkeypatch: pytest.MonkeyPatch, in_tmp: Path
) -> None:
    monkeypatch.setattr(os, 'environ', {**os.environ, 'INSIGHT_PASSWORD': 'from-environment'})
    (in_tmp / '.env').write_text('INSIGHT_PASSWORD=from-dotenv-file\n')
    seen: dict[str, str] = {}
    monkeypatch.setattr('uvicorn.run', lambda *a, **k: seen.update(os.environ))
    cli.main(['serve'])
    assert seen['INSIGHT_PASSWORD'] == 'from-environment'


def test_migrate_upgrades_a_0_1_0_database_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = Path(__file__).parent.parent / 'fixtures' / 'releases' / 'insight-0.1.0.sqlite3'
    database = in_tmp / 'legacy.db'
    database.write_bytes(fixture.read_bytes())
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': f'sqlite:///{database}'})
    assert cli.main(['migrate']) == 0
    assert 'upgraded unversioned -> ' in capsys.readouterr().out
    assert cli.main(['migrate']) == 0
    assert 'already at revision' in capsys.readouterr().out


def test_migrate_does_not_require_credentials(
    monkeypatch: pytest.MonkeyPatch, in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATA_DIR': str(in_tmp / 'data')})
    assert cli.main(['migrate']) == 0
    assert (in_tmp / 'data' / 'insight.db').is_file()
    assert 'upgraded unversioned' in capsys.readouterr().out


def test_migrate_hides_database_passwords(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeURL:
        def render_as_string(self, *, hide_password: bool) -> str:
            assert hide_password
            return 'postgresql://insight:***@db/insight'

    class FakeEngine:
        url = FakeURL()

        def dispose(self) -> None:
            return None

    monkeypatch.setattr('insight.models.database', lambda *a, **k: (FakeEngine(), None))
    monkeypatch.setattr('insight.migrations.current_revision', lambda _e: '0002')
    monkeypatch.setattr('insight.migrations.upgrade', lambda _e: None)
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': 'postgresql://insight:hunter2@db/insight'})
    assert cli.main(['migrate']) == 0
    out = capsys.readouterr().out
    assert 'hunter2' not in out
    assert '***' in out


@pytest.fixture
def sqlite_env(monkeypatch: pytest.MonkeyPatch, in_tmp: Path) -> Path:
    data = in_tmp / 'data'
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATA_DIR': str(data)})
    assert cli.main(['migrate']) == 0
    return data


def test_backup_writes_a_consistent_private_copy(
    sqlite_env: Path, in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = in_tmp / 'backup.db'
    assert cli.main(['backup', str(target)]) == 0
    assert 'integrity ok' in capsys.readouterr().out
    assert target.stat().st_size > 0
    if sys.platform != 'win32':
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_backup_never_overwrites(sqlite_env: Path, in_tmp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = in_tmp / 'backup.db'
    target.write_text('keep me')
    assert cli.main(['backup', str(target)]) == 1
    assert target.read_text() == 'keep me'
    assert 'Backup failed' in capsys.readouterr().err


def test_backup_requires_a_destination(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['backup']) == 2


def test_backup_refuses_postgresql(monkeypatch: pytest.MonkeyPatch, in_tmp: Path) -> None:
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': 'postgresql://db/insight'})
    assert cli.main(['backup', str(in_tmp / 'x.db')]) == 1
    assert not (in_tmp / 'x.db').exists()


def test_backup_requires_an_existing_database(monkeypatch: pytest.MonkeyPatch, in_tmp: Path) -> None:
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': f'sqlite:///{in_tmp / "missing.db"}'})
    assert cli.main(['backup', str(in_tmp / 'x.db')]) == 1


def test_serve_configures_insight_logging(monkeypatch: pytest.MonkeyPatch, in_tmp: Path) -> None:
    """Regression: INFO records from insight.* (sign-ins, migrations) were silently dropped under uvicorn."""
    monkeypatch.setattr('uvicorn.run', lambda *a, **k: None)
    monkeypatch.setattr(os, 'environ', {})
    cli.main(['serve'])
    cli.main(['serve'])  # idempotent: no duplicate handlers
    logger = logging.getLogger('insight')
    handlers = [h for h in logger.handlers if getattr(h, 'insight_handler', False)]
    assert len(handlers) == 1
    assert logger.getEffectiveLevel() == logging.INFO
    assert logging.getLogger('insight.auth').isEnabledFor(logging.INFO)
