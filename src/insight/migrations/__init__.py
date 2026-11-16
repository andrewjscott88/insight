"""Alembic schema migrations, shipped inside the package so installed copies can upgrade themselves.

``upgrade(engine)`` is called on every start-up. It handles three cases:

* empty database        -> create everything from the baseline onwards;
* 0.1.0 database         -> tables exist but were created by ``create_all`` without Alembic, so the
                            database is first *stamped* at the baseline revision and then upgraded;
* migrated database      -> apply any newer revisions.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect

BASELINE_REVISION = '0001'
log = logging.getLogger('insight.migrations')
HERE = Path(__file__).parent


def alembic_config(engine: Engine | None = None) -> Config:
    config = Config()
    config.set_main_option('script_location', str(HERE))
    if engine is not None:
        config.attributes['engine'] = engine
    return config


def head_revision() -> str:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:  # pragma: no cover - only possible if the versions directory is missing.
        raise RuntimeError('No migration revisions found')
    return head


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def _is_unversioned_legacy_database(engine: Engine) -> bool:
    tables = set(inspect(engine).get_table_names())
    return 'documents' in tables and 'alembic_version' not in tables


def upgrade(engine: Engine, revision: str = 'head') -> None:
    """Bring the database schema up to ``revision`` (default: latest), logging what changed."""
    config = alembic_config(engine)
    if _is_unversioned_legacy_database(engine):
        log.warning('Unversioned (0.1.0) database detected: stamping it at baseline %s', BASELINE_REVISION)
        command.stamp(config, BASELINE_REVISION)
    before = current_revision(engine)
    command.upgrade(config, revision)
    after = current_revision(engine)
    if before != after:
        log.warning('Database schema upgraded %s -> %s', before or 'empty', after)
    else:
        log.info('Database schema at revision %s (up to date)', after)


def downgrade(engine: Engine, revision: str) -> None:
    command.downgrade(alembic_config(engine), revision)
