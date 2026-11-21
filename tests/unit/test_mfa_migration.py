"""Revision 0017 preserves operator pairing and replay protection across SQLite and PostgreSQL upgrades."""

from __future__ import annotations

import logging
import sqlite3
import traceback
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from sqlalchemy import Engine, create_engine, event, inspect, text

from insight import migrations
from insight.mfa_crypto import decrypt_seed

KEY = 'synthetic-local-migration-key-for-tests'
OTHER_KEY = 'different-local-migration-key-for-tests'
SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
STAMP = '2026-01-02T03:04:05.000000+00:00'


@pytest.fixture
def legacy_engine(empty_database_url: str) -> Iterator[Engine]:
    engine = create_engine(empty_database_url)
    try:
        migrations.upgrade(engine, '0016')
        yield engine
    finally:
        engine.dispose()


def _pair(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text('INSERT INTO operator_mfa(id,secret,created_at,last_step) VALUES(:id,:secret,:at,:step)'),
            {'id': 'operator', 'secret': SEED, 'at': STAMP, 'step': 987654},
        )


def _stored(engine: Engine) -> tuple[str, str, str, int]:
    with engine.connect() as conn:
        row = conn.execute(text('SELECT id, secret, created_at, last_step FROM operator_mfa')).one()
        return row[0], row[1], row[2], row[3]


def _secret_type(engine: Engine) -> str:
    return str(
        next(col['type'] for col in inspect(engine).get_columns('operator_mfa') if col['name'] == 'secret')
    )


def test_empty_mfa_table_needs_no_secret_in_either_direction(
    legacy_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv('INSIGHT_SESSION_SECRET', raising=False)
    migrations.upgrade(legacy_engine)
    assert _secret_type(legacy_engine) == 'TEXT'
    migrations.downgrade(legacy_engine, '0016')
    assert _secret_type(legacy_engine) == 'VARCHAR(64)'


def test_conversion_preserves_pairing_and_replay_step_and_refuses_wrong_keys(
    legacy_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv('INSIGHT_SESSION_SECRET', raising=False)
    _pair(legacy_engine)
    before = _stored(legacy_engine)
    with pytest.raises(ValueError, match='INSIGHT_SESSION_SECRET'):
        migrations.upgrade(legacy_engine)
    assert migrations.current_revision(legacy_engine) == '0016'
    assert _stored(legacy_engine) == before
    assert _secret_type(legacy_engine) == 'VARCHAR(64)'

    # An explicit key wins over the environment. Retrying reaches 0017 without losing any pairing metadata.
    monkeypatch.setenv('INSIGHT_SESSION_SECRET', OTHER_KEY)
    migrations.upgrade(legacy_engine, session_secret=KEY)
    row_id, envelope, created, step = encrypted = _stored(legacy_engine)
    assert (row_id, created, step) == ('operator', STAMP, 987654)
    assert SEED not in envelope
    assert decrypt_seed(envelope, KEY) == SEED
    assert _secret_type(legacy_engine) == 'TEXT'

    for wrong in ('', OTHER_KEY):
        with pytest.raises(ValueError, match='INSIGHT_SESSION_SECRET') as err:
            migrations.downgrade(legacy_engine, '0016', session_secret=wrong)
        assert all(value not in str(err.value) for value in (KEY, OTHER_KEY, envelope, SEED))
        assert migrations.current_revision(legacy_engine) == '0017'
        assert _secret_type(legacy_engine) == 'TEXT'
        assert _stored(legacy_engine) == encrypted

    # A direct Alembic invocation has the environment but no explicit configuration attribute.
    monkeypatch.setenv('INSIGHT_SESSION_SECRET', KEY)
    command.downgrade(migrations.alembic_config(legacy_engine), '0016')
    assert _stored(legacy_engine) == before
    assert _secret_type(legacy_engine) == 'VARCHAR(64)'
    command.upgrade(migrations.alembic_config(legacy_engine), '0017')
    assert decrypt_seed(_stored(legacy_engine)[1], KEY) == SEED


def test_failed_database_write_rolls_back_schema_and_seed(legacy_engine: Engine) -> None:
    _pair(legacy_engine)

    def interrupt(_conn: Any, _cursor: Any, statement: str, _params: Any, _context: Any, _many: bool) -> None:
        if statement.startswith('ALTER TABLE') and (
            'RENAME TO operator_mfa' in statement or 'ALTER COLUMN secret TYPE TEXT' in statement
        ):
            raise RuntimeError('simulated storage failure')

    event.listen(legacy_engine, 'after_cursor_execute', interrupt)
    try:
        with pytest.raises(RuntimeError, match='simulated storage failure'):
            migrations.upgrade(legacy_engine, session_secret=KEY)
    finally:
        event.remove(legacy_engine, 'after_cursor_execute', interrupt)
    assert migrations.current_revision(legacy_engine) == '0016'
    assert _secret_type(legacy_engine) == 'VARCHAR(64)'
    assert _stored(legacy_engine) == ('operator', SEED, STAMP, 987654)
    if legacy_engine.dialect.name == 'sqlite':
        with legacy_engine.connect() as conn:
            assert conn.exec_driver_sql('PRAGMA foreign_keys').scalar_one() == 1
    migrations.upgrade(legacy_engine, session_secret=KEY)
    assert decrypt_seed(_stored(legacy_engine)[1], KEY) == SEED


def test_normal_migrated_sqlite_binary_backup_excludes_legacy_seed(tmp_path: Path) -> None:
    path = tmp_path / 'mfa.db'
    backup = tmp_path / 'backup.db'
    engine = create_engine(f'sqlite:///{path}')
    try:
        migrations.upgrade(engine, '0016')
        with engine.connect() as conn:
            conn.exec_driver_sql('PRAGMA secure_delete=OFF')
        _pair(engine)
        assert SEED.encode() in path.read_bytes()
        migrations.upgrade(engine, session_secret=KEY)
        with engine.connect() as conn:
            assert conn.exec_driver_sql('PRAGMA secure_delete').scalar_one() == 0
    finally:
        engine.dispose()
    with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(backup)) as target:
        source.backup(target)
        assert SEED not in '\n'.join(target.iterdump())
    assert SEED.encode() not in backup.read_bytes()


def test_database_failure_and_verbose_sql_logs_redact_the_plaintext(
    legacy_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    _pair(legacy_engine)
    with caplog.at_level(logging.DEBUG, logger='sqlalchemy.engine'):
        migrations.upgrade(legacy_engine, session_secret=KEY)
    assert SEED not in caplog.text
    before = _stored(legacy_engine)
    assert before[1] != SEED
    with legacy_engine.begin() as conn:
        if legacy_engine.dialect.name == 'sqlite':
            conn.exec_driver_sql(
                'CREATE TRIGGER refuse_seed BEFORE UPDATE ON operator_mfa '
                "BEGIN SELECT RAISE(ABORT, 'Synthetic update failure'); END"
            )
        else:
            conn.exec_driver_sql(
                """CREATE FUNCTION refuse_seed() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION USING MESSAGE = 'Synthetic update failure: ' || NEW.secret; END; $$"""
            )
            conn.exec_driver_sql(
                'CREATE TRIGGER refuse_seed BEFORE UPDATE ON operator_mfa FOR EACH ROW '
                'EXECUTE FUNCTION refuse_seed()'
            )
    caplog.clear()
    with (
        caplog.at_level(logging.DEBUG, logger='sqlalchemy.engine'),
        pytest.raises(ValueError, match='Cannot write') as err,
    ):
        migrations.downgrade(legacy_engine, '0016', session_secret=KEY)
    diagnostic = caplog.text + ''.join(traceback.format_exception(err.value))
    assert all(value not in diagnostic for value in (SEED, before[1], KEY))
    assert migrations.current_revision(legacy_engine) == '0017'
    assert _stored(legacy_engine) == before
