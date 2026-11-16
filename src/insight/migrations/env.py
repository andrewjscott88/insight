"""Alembic environment. Uses the engine handed over by ``insight.migrations.upgrade`` when present,
otherwise ``INSIGHT_DATABASE_URL`` (developer CLI usage via the repository's ``alembic.ini``)."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import Connection, create_engine

from insight.models import Base

config = context.config
target_metadata = Base.metadata


def _run(connection: Connection) -> None:
    is_sqlite = connection.dialect.name == 'sqlite'
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=is_sqlite,  # SQLite cannot ALTER most things; batch mode recreates tables instead.
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = config.attributes.get('engine')
    if engine is None:
        url = os.environ.get('INSIGHT_DATABASE_URL') or 'sqlite:///data/insight.db'
        engine = create_engine(url)
    with engine.connect() as connection:
        if connection.dialect.name != 'sqlite':
            _run(connection)
            connection.commit()
            return
        # Batch mode rebuilds tables (copy, drop, rename). With foreign keys enforced, dropping a referenced
        # table fails, so SQLite's documented procedure is: disable, migrate, verify integrity, re-enable.
        connection.exec_driver_sql('PRAGMA foreign_keys=OFF')
        try:
            _run(connection)
            violations = connection.exec_driver_sql('PRAGMA foreign_key_check').fetchall()
            if violations:
                connection.rollback()
                raise RuntimeError(f'Migration left foreign-key violations: {violations[:5]}')
            connection.commit()
        finally:
            connection.exec_driver_sql('PRAGMA foreign_keys=ON')


if context.is_offline_mode():
    raise SystemExit('Offline (SQL script) migrations are not supported; run against a database.')
run_migrations_online()
