"""API keys for scripts and SIEM integrations (hash-only storage).

Revision ID: 0004
Revises: 0003
Create Date: 2026-12-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('key_id', sa.String(length=12), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('access', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.String(length=40), nullable=False),
        sa.Column('expires_at', sa.String(length=40), nullable=False),
        sa.Column('last_used_at', sa.String(length=40), nullable=True),
        sa.Column('revoked_at', sa.String(length=40), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_id'),
    )


def downgrade() -> None:
    op.drop_table('api_keys')
