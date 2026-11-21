"""An Insight backup must exclude legacy SQLite pages while preserving the enrolled authenticator."""

from __future__ import annotations

import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from insight import cli, migrations, totp
from insight.mfa_crypto import decrypt_seed


def test_migrated_sqlite_backup_omits_historical_seed_and_restores_pairing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / 'live.db'
    destination = tmp_path / 'backup.db'
    url = f'sqlite:///{source}'
    seed = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    key = 'synthetic-local-backup-key-for-tests'
    step = 123456
    joined = '2026-01-01T00:00:00+00:00'
    engine = create_engine(url)
    try:
        migrations.upgrade(engine, '0016')
        with engine.begin() as conn:
            conn.exec_driver_sql('PRAGMA secure_delete=OFF')
            conn.exec_driver_sql(
                'INSERT INTO operator_mfa(id, secret, created_at, last_step) VALUES(?, ?, ?, ?)',
                ('operator', seed, joined, step),
            )
            # A dropped legacy index leaves its old key on a free page. Other freed pages let the
            # 0017 table rebuild allocate space without reusing that particular page.
            conn.exec_driver_sql('CREATE INDEX old_seed_index ON operator_mfa(secret)')
            conn.exec_driver_sql('CREATE TABLE old_scratch(data BLOB)')
            conn.exec_driver_sql('INSERT INTO old_scratch VALUES(zeroblob(65536))')
            conn.exec_driver_sql('DROP INDEX old_seed_index')
            conn.exec_driver_sql('DROP TABLE old_scratch')
        migrations.upgrade(engine, '0017', session_secret=key)
    finally:
        engine.dispose()

    assert seed.encode() in source.read_bytes()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('INSIGHT_DATABASE_URL', url)
    assert cli.main(['backup', str(destination)]) == 0
    if sys.platform != 'win32':
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert seed.encode() not in destination.read_bytes()
    assert seed.encode() in source.read_bytes()
    with closing(sqlite3.connect(destination)) as restored:
        assert seed not in '\n'.join(restored.iterdump())
        identity, envelope, created, last_step = restored.execute(
            'SELECT id, secret, created_at, last_step FROM operator_mfa'
        ).fetchone()
    assert (identity, created, last_step) == ('operator', joined, step)
    recovered = decrypt_seed(envelope, key)
    next_step = step + 1
    code = totp.code_at(seed, next_step)
    assert totp.matching_step(recovered, code, at=next_step * totp.PERIOD, after=last_step) == next_step
