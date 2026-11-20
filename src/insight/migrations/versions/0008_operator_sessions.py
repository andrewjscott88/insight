"""Signed-in sessions in the database, so a restart no longer signs the operator out (review B4).

* ``operator_sessions``: one row per signed-in browser: a keyed hash of its session ID (never the ID itself),
  when it started and when it expires. No data moves: sessions held in memory before the upgrade end with the
  restart that runs this migration, as they always did.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'operator_sessions',
        sa.Column('id_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.String(length=40), nullable=False),
        sa.Column('expires_at', sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint('id_hash'),
    )
    op.create_index('ix_operator_sessions_expires_at', 'operator_sessions', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_operator_sessions_expires_at', table_name='operator_sessions')
    op.drop_table('operator_sessions')
