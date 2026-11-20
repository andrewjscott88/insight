"""Analyst verdicts on indicators, with their own TLP label and an optional expiry (review Design 1).

* ``entity_assessments``: one row per assessed entity: ``benign``, ``suspicious`` or ``malicious``, a reason,
  the reason's TLP label, ``valid_until`` (NULL: no expiry), when and by whom. No row: the verdict is unknown.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'entity_assessments',
        sa.Column('entity_id', sa.String(length=36), nullable=False),
        sa.Column('verdict', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(length=20), nullable=False),
        sa.Column('valid_until', sa.String(length=40), nullable=True),
        sa.Column('decided_at', sa.String(length=40), nullable=False),
        sa.Column('actor', sa.String(length=80), nullable=False),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id']),
        sa.PrimaryKeyConstraint('entity_id'),
    )


def downgrade() -> None:
    op.drop_table('entity_assessments')
