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


# --------------------------------------------------------------------------- api-key


def key_from(output: str) -> str:
    [token] = [line for line in output.splitlines() if line.startswith('insk_')]
    return token


def test_api_key_lifecycle(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from insight import apikeys

    assert cli.main(['api-key', 'status']) == 0
    assert 'No active API key' in capsys.readouterr().out

    assert cli.main(['api-key', 'create', '--name', 'siem']) == 0
    out = capsys.readouterr().out
    token = key_from(out)
    key_id = apikeys.parse_key_id(token)
    assert f'Created API key {key_id} "siem" (read-only; sees every label stored; expires ' in out
    assert 'shown only once' in out
    assert 'Authorization: Bearer' in out

    assert cli.main(['api-key', 'status']) == 0
    status = capsys.readouterr().out
    assert f'Active API key {key_id} "siem" (read-only;' in status
    assert 'last used never' in status
    assert token not in status

    assert cli.main(['api-key', 'create', '--name', 'second']) == 1
    assert f'API key {key_id} is already active; rotate or revoke it first' in capsys.readouterr().err

    assert cli.main(['api-key', 'rotate', '--access', 'read-write', '--expires-days', '7']) == 0
    rotated = capsys.readouterr().out
    assert key_from(rotated) != token
    assert 'Rotated to API key' in rotated
    assert '"siem" (read-write;' in rotated

    assert cli.main(['api-key', 'revoke']) == 0
    assert 'Revoked API key' in capsys.readouterr().out
    assert cli.main(['api-key', 'revoke']) == 0
    assert 'nothing to revoke' in capsys.readouterr().out
    assert cli.main(['api-key', 'rotate']) == 1
    assert 'No active API key to rotate' in capsys.readouterr().err


@pytest.mark.parametrize(
    ('argv', 'message'),
    [
        (['api-key'], 'usage: insight api-key {create,rotate,revoke,status}'),
        (['api-key', 'delete'], 'usage: insight api-key {create,rotate,revoke,status}'),
        (['api-key', 'create'], 'usage: insight api-key create --name NAME'),
    ],
)
def test_api_key_usage_errors(argv: list[str], message: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(argv) == 2
    assert message in capsys.readouterr().err


def test_api_key_rejects_invalid_expiry(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['api-key', 'create', '--name', 'siem', '--expires-days', '400']) == 1
    assert 'between 1 and 365 days' in capsys.readouterr().err


def test_api_key_requires_an_existing_current_database(
    monkeypatch: pytest.MonkeyPatch, in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATA_DIR': str(in_tmp / 'data')})
    assert cli.main(['api-key', 'status']) == 1
    assert 'run `insight migrate` or start Insight first' in capsys.readouterr().err
    assert cli.main(['migrate']) == 0
    monkeypatch.setattr('insight.migrations.head_revision', lambda: '9999')
    assert cli.main(['api-key', 'status']) == 1
    assert 'schema is not current' in capsys.readouterr().err


def test_api_key_status_shows_last_use(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from insight import services
    from insight.config import database_url_from_env
    from insight.models import database

    assert cli.main(['api-key', 'create', '--name', 'siem']) == 0
    token = key_from(capsys.readouterr().out)
    engine, sessions = database(database_url_from_env(), migrate=False)
    with sessions.begin() as db:
        services.verify_api_key(db, token)
    engine.dispose()
    assert cli.main(['api-key', 'status']) == 0
    assert 'last used 20' in capsys.readouterr().out


def test_api_key_with_a_tlp_limit(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['api-key', 'create', '--name', 'siem', '--max-tlp', 'green']) == 0
    assert '(read-only; sees TLP:GREEN and below;' in capsys.readouterr().out
    assert cli.main(['api-key', 'rotate']) == 0
    assert 'sees TLP:GREEN and below' in capsys.readouterr().out  # kept on rotation
    assert cli.main(['api-key', 'rotate', '--max-tlp', 'RED']) == 0  # RED hides nothing: the limit is lifted
    assert 'sees every label stored' in capsys.readouterr().out
    assert cli.main(['api-key', 'rotate']) == 0
    assert 'sees every label stored' in capsys.readouterr().out  # and stays lifted
    assert cli.main(['api-key', 'revoke']) == 0
    assert cli.main(['api-key', 'create', '--name', 'x', '--max-tlp', 'WHITE']) == 1
    assert 'TLP limit must be one of' in capsys.readouterr().err


# --------------------------------------------------------------------------- mfa

MFA_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'


def answer_codes(monkeypatch: pytest.MonkeyPatch, *codes: str) -> list[str]:
    """Typed codes for `insight mfa setup`; returns the prompts shown."""
    from insight import totp

    monkeypatch.setattr(totp, 'generate_secret', lambda: MFA_SECRET)
    prompts: list[str] = []
    pending = list(codes)

    def typed(prompt: str) -> str:
        prompts.append(prompt)
        if not pending:
            raise EOFError
        return pending.pop(0)

    monkeypatch.setattr('builtins.input', typed)
    return prompts


def test_mfa_setup_confirms_a_code_before_pairing(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insight import totp

    good = totp.code_at(MFA_SECRET, totp.time_step())
    wrong = '000000' if good != '000000' else '111111'
    prompts = answer_codes(monkeypatch, wrong, good)
    assert cli.main(['mfa', 'setup']) == 0
    captured = capsys.readouterr()
    assert 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP' in captured.out
    assert 'otpauth://totp/Insight%3Aoperator?secret=' + MFA_SECRET in captured.out
    # MFA stays off: pairing alone does not switch it on (INSIGHT_MFA does).
    assert 'Authenticator app paired. MFA is still off until INSIGHT_MFA=on' in captured.out
    assert 'does not match' in captured.err
    assert prompts == ['Code shown by the app: '] * 2


def test_mfa_setup_is_idempotent(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`make mfa-enable` runs setup every time: an already paired app is kept, and that is not an error."""
    from insight import totp

    answer_codes(monkeypatch, totp.code_at(MFA_SECRET, totp.time_step()))
    assert cli.main(['mfa', 'setup']) == 0
    capsys.readouterr()
    prompts = answer_codes(monkeypatch)
    assert cli.main(['mfa', 'setup']) == 0
    assert 'already paired; keeping it' in capsys.readouterr().out
    assert prompts == []  # no new secret, no prompt


@pytest.mark.parametrize(
    ('switch', 'paired', 'expected'),
    [
        (
            '',
            False,
            'MFA is off (INSIGHT_MFA=off). No authenticator app is paired: sign-in needs the password only',
        ),
        (
            'off',
            True,
            'MFA is off (INSIGHT_MFA=off). An authenticator app is paired: sign-in needs the password',
        ),
        (
            'on',
            True,
            'MFA is on (INSIGHT_MFA=on). An authenticator app is paired: sign-in needs the password and',
        ),
        ('on', False, 'MFA is on (INSIGHT_MFA=on). No authenticator app is paired: sign-in is LOCKED'),
    ],
)
def test_mfa_status(
    sqlite_env: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    switch: str,
    paired: bool,
    expected: str,
) -> None:
    from insight import totp

    if paired:
        answer_codes(monkeypatch, totp.code_at(MFA_SECRET, totp.time_step()))
        assert cli.main(['mfa', 'setup']) == 0
        capsys.readouterr()
    os.environ['INSIGHT_MFA'] = switch
    assert cli.main(['mfa', 'status']) == 0
    assert expected in capsys.readouterr().out


def test_mfa_status_rejects_an_invalid_switch(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    os.environ['INSIGHT_MFA'] = 'onn'
    assert cli.main(['mfa', 'status']) == 1
    assert 'INSIGHT_MFA must be "on" or "off"' in capsys.readouterr().err


@pytest.mark.parametrize(('switch', 'message'), [('off', 'MFA is off'), ('on', 'sign-in is locked')])
def test_mfa_reset(
    sqlite_env: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    switch: str,
    message: str,
) -> None:
    from insight import totp

    assert cli.main(['mfa', 'reset']) == 0
    assert 'nothing to reset' in capsys.readouterr().out
    answer_codes(monkeypatch, totp.code_at(MFA_SECRET, totp.time_step()))
    assert cli.main(['mfa', 'setup']) == 0
    capsys.readouterr()
    os.environ['INSIGHT_MFA'] = switch
    assert cli.main(['mfa', 'reset']) == 0
    out = capsys.readouterr().out
    assert 'Authenticator app forgotten' in out
    assert message in out


def test_mfa_setup_saves_nothing_without_a_matching_code(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answer_codes(monkeypatch, 'nope', '123', 'abcdef')
    assert cli.main(['mfa', 'setup']) == 1
    assert 'no authenticator app was paired (nothing was saved)' in capsys.readouterr().err
    assert cli.main(['mfa', 'status']) == 0
    assert 'No authenticator app is paired' in capsys.readouterr().out


def test_mfa_setup_can_be_cancelled(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answer_codes(monkeypatch)  # end of input at the first prompt (Ctrl-D)
    assert cli.main(['mfa', 'setup']) == 1
    assert 'Cancelled; no authenticator app was paired' in capsys.readouterr().err


def test_mfa_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['mfa']) == 2
    assert 'usage: insight mfa {setup,reset,status}' in capsys.readouterr().err


# --------------------------------------------------------------------------- scheduled syncs


def test_schedule_lists_and_sets_schedules(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['schedule']) == 0
    out = capsys.readouterr().out
    assert 'cisa-kev: off (syncs only when asked)' in out
    assert 'INSIGHT_RUN_JOBS' in out
    assert cli.main(['schedule', 'all', '--every', '24h']) == 0
    out = capsys.readouterr().out
    assert out.count('every 24h; next sync ') == 4
    assert cli.main(['schedule', 'ncsc', '--every', 'off']) == 0
    assert 'ncsc: off (syncs only when asked)' in capsys.readouterr().out

    from insight import services
    from insight.models import AuditEvent, database

    engine, sessions = database(f'sqlite:///{sqlite_env / "insight.db"}', migrate=False)
    try:
        with sessions() as db:
            assert services.list_schedules(db)['cisa-kev'].interval_minutes == 1440
            actors = {e.actor for e in db.query(AuditEvent).filter(AuditEvent.action == 'schedule.update')}
            assert actors == {'cli'}
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ('argv', 'message'),
    [
        (['schedule', 'nope', '--every', '6h'], "unknown source 'nope'"),
        (['schedule', 'ncsc'], 'say how often: --every off|1h|6h|24h'),
    ],
)
def test_schedule_usage_errors(
    sqlite_env: Path, argv: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(argv) == 1
    assert message in capsys.readouterr().err


def test_schedule_at_a_time_of_day(sqlite_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['schedule', 'all', '--every', '24h', '--at', '00:00']) == 0
    out = capsys.readouterr().out
    assert out.count(' 00:00 UTC') == 4
    assert cli.main(['schedule', 'ncsc', '--every', '6h', '--at', '25:00']) == 1
    assert 'HH:MM in UTC' in capsys.readouterr().err


def _seed_report(data: Path, body: str = 'Beacons to evil-one.net') -> str:
    from insight import services
    from insight.models import database
    from insight.schemas import DocumentInput

    engine, sessions = database(f'sqlite:///{data / "insight.db"}', migrate=False)
    try:
        with sessions.begin() as db:
            doc, _ = services.ingest(db, DocumentInput(title='Victim report', body=body, source_name='S'))
            return doc.id
    finally:
        engine.dispose()


def _stored(data: Path, document_id: str) -> tuple[bool, set[str]]:
    from insight.models import AuditEvent, Document, database

    engine, sessions = database(f'sqlite:///{data / "insight.db"}', migrate=False)
    try:
        with sessions() as db:
            actors = {e.actor for e in db.query(AuditEvent).filter(AuditEvent.action == 'document.delete')}
            return db.get(Document, document_id) is not None, actors
    finally:
        engine.dispose()


def test_delete_report_shows_what_goes_and_asks_first(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    doc_id = _seed_report(sqlite_env)
    prompts: list[str] = []

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return 'delete'

    monkeypatch.setattr('builtins.input', answer)
    assert cli.main(['delete-report', doc_id, '--reason', 'ticket 9']) == 0
    out = capsys.readouterr().out
    assert 'This deletes, with no undo:' in out
    assert 'Victim report' in out
    assert '1 observation' in out
    assert prompts == ['Type delete to go ahead: ']
    assert f'Deleted report {doc_id}' in out
    assert 'Audited as document.delete' in out
    assert 'Backups taken before now still contain the report' in out
    assert _stored(sqlite_env, doc_id) == (False, {'cli'})


@pytest.mark.parametrize('answer', ['', 'no', 'y'])
def test_delete_report_can_be_cancelled(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], answer: str
) -> None:
    doc_id = _seed_report(sqlite_env)
    monkeypatch.setattr('builtins.input', lambda _prompt: answer)
    assert cli.main(['delete-report', doc_id, '--reason', 'ticket 9']) == 0
    assert 'Cancelled; nothing was deleted.' in capsys.readouterr().out
    assert _stored(sqlite_env, doc_id) == (True, set())


def test_delete_report_yes_skips_the_question(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    doc_id = _seed_report(sqlite_env)

    def no_questions(_prompt: str) -> str:
        raise AssertionError('--yes must not ask')

    monkeypatch.setattr('builtins.input', no_questions)
    assert cli.main(['delete-report', doc_id, '--reason', 'ticket 9', '--yes']) == 0
    assert _stored(sqlite_env, doc_id)[0] is False


def test_delete_report_cancelled_by_end_of_input(
    sqlite_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    doc_id = _seed_report(sqlite_env)

    def end_of_input(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr('builtins.input', end_of_input)
    assert cli.main(['delete-report', doc_id, '--reason', 'ticket 9']) == 1
    assert 'Cancelled; nothing was deleted.' in capsys.readouterr().err
    assert _stored(sqlite_env, doc_id)[0] is True


@pytest.mark.parametrize(
    ('argv', 'code', 'message'),
    [
        (['delete-report'], 2, 'usage: insight delete-report ID --reason TEXT'),
        (['delete-report', 'some-id'], 2, 'usage: insight delete-report ID --reason TEXT'),
        (['delete-report', 'nope', '--reason', 'r', '--yes'], 1, 'no report with ID nope'),
        (['delete-report', 'nope', '--reason', '   ', '--yes'], 1, 'say why'),
    ],
)
def test_delete_report_usage_errors(
    sqlite_env: Path, capsys: pytest.CaptureFixture[str], argv: list[str], code: int, message: str
) -> None:
    assert cli.main(argv) == code
    assert message in capsys.readouterr().err
