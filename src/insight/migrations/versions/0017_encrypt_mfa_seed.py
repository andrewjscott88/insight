"""Encrypt existing authenticator seeds with the operator's session secret.

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager

import sqlalchemy as sa
from alembic import context, op

from insight.mfa_crypto import decrypt_seed, encrypt_seed

revision = '0017'
down_revision = '0016'
branch_labels = None
depends_on = None

_MFA = sa.table('operator_mfa', sa.column('id', sa.String(36)), sa.column('secret', sa.Text()))


@contextmanager
def _erase_replaced_cells(conn: sa.Connection, *, encrypt: bool) -> Iterator[None]:
    """Wipe freed SQLite cells for live binary backups. Historical snapshots require separate handling."""
    if not encrypt or conn.dialect.name != 'sqlite':
        yield
        return
    previous = conn.exec_driver_sql('PRAGMA secure_delete').scalar_one()
    conn.exec_driver_sql('PRAGMA secure_delete=ON')
    try:
        yield
    finally:
        restore = ('PRAGMA secure_delete=OFF', 'PRAGMA secure_delete=ON', 'PRAGMA secure_delete=FAST')
        conn.exec_driver_sql(restore[previous])


def _convert(convert: Callable[[str, str], str], *, encrypt: bool) -> None:
    conn = op.get_bind()
    if conn.dialect.name == 'sqlite':
        # The sqlite3 legacy driver does not BEGIN for DDL. A write, even with no matching rows, starts a
        # write transaction before the table rebuild and locks out pairing/reset until the revision commits.
        conn.execute(_MFA.update().where(sa.false()).values(secret=_MFA.c.secret))
    else:
        conn.exec_driver_sql('LOCK TABLE operator_mfa IN ACCESS EXCLUSIVE MODE')

    # There is normally one enrollment. Convert all existing rows successfully before any data or DDL
    # changes, so a missing key or failed authentication can be retried with the original database intact.
    # SQLAlchemy's debug output includes fetched rows, and its DBAPI errors can include bound values.
    # Use the same transactional connection directly for the two statements that handle credentials.
    with closing(conn.connection.cursor()) as cursor:
        cursor.execute('SELECT id, secret FROM operator_mfa')
        rows = cursor.fetchall()
    converted: list[tuple[str, str]] = []
    if rows:
        secret = context.config.attributes.get('session_secret')
        if secret is None:
            secret = os.environ.get('INSIGHT_SESSION_SECRET')
        if not secret:
            raise ValueError('Set INSIGHT_SESSION_SECRET to migrate enrolled authenticator credentials.')
        try:
            converted = [(row_id, convert(value, secret)) for row_id, value in rows]
        except ValueError:
            if encrypt:
                raise ValueError(
                    'Cannot encrypt the enrolled authenticator credential. '
                    'Check INSIGHT_SESSION_SECRET and the existing pairing.'
                ) from None
            raise ValueError(
                'Cannot decrypt the enrolled authenticator credential. '
                'Restore the original INSIGHT_SESSION_SECRET and retry.'
            ) from None

    old, new = (sa.String(64), sa.Text()) if encrypt else (sa.Text(), sa.String(64))

    def resize() -> None:
        with op.batch_alter_table('operator_mfa') as batch:
            batch.alter_column('secret', existing_type=old, type_=new, existing_nullable=False)

    with _erase_replaced_cells(conn, encrypt=encrypt and bool(rows)):
        if encrypt:
            resize()
        # sqlite3 and psycopg have different DB-API parameter styles. Both bind the values separately.
        write = (
            'UPDATE operator_mfa SET secret = ? WHERE id = ?'
            if conn.dialect.name == 'sqlite'
            else 'UPDATE operator_mfa SET secret = %s WHERE id = %s'
        )
        try:
            with closing(conn.connection.cursor()) as cursor:
                for row_id, value in converted:
                    cursor.execute(write, (value, row_id))
        except conn.dialect.loaded_dbapi.Error:
            # Database diagnostics (including PostgreSQL trigger errors) can contain the entire failing row.
            raise ValueError(
                'Cannot write the migrated authenticator credential. Transaction rolled back.'
            ) from None
        if not encrypt:
            resize()


def upgrade() -> None:
    _convert(encrypt_seed, encrypt=True)


def downgrade() -> None:
    _convert(decrypt_seed, encrypt=False)
