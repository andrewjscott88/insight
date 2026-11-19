"""Audit actor, per-key TLP limit and the operator's TOTP second factor.

* ``audit_events.actor``: who performed the action (empty for events recorded before this revision).
* ``api_keys.max_tlp``: most restrictive label the key may read or write (``NULL``: the instance limit).
* ``operator_mfa``: at most one row holding the TOTP secret and the last accepted time step.

Revision ID: 0005
Revises: 0004
Create Date: 2026-12-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('audit_events') as batch:
        batch.add_column(sa.Column('actor', sa.String(length=80), nullable=False, server_default=''))
    with op.batch_alter_table('api_keys') as batch:
        batch.add_column(sa.Column('max_tlp', sa.String(length=20), nullable=True))
    op.create_table(
        'operator_mfa',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('secret', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.String(length=40), nullable=False),
        sa.Column('last_step', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('operator_mfa')
    with op.batch_alter_table('api_keys') as batch:
        batch.drop_column('max_tlp')
    with op.batch_alter_table('audit_events') as batch:
        batch.drop_column('actor')
