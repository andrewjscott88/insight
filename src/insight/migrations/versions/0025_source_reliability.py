"""Source reliability and report credibility (TIP 4.2, ADR 0033): the analyst's Admiralty grades. Existing
reports start at credibility 6 (cannot be judged) and every source counts as F until rated.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0025'
down_revision: str | None = '0024'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('documents', sa.Column('credibility', sa.Integer(), nullable=False, server_default='6'))
    op.create_table(
        'source_ratings',
        sa.Column('source_name', sa.String(160), primary_key=True),
        sa.Column('reliability', sa.String(1), nullable=False),
        sa.Column('half_life_days', sa.Integer(), nullable=True),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column(
            'updated_at',
            sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql'),
            nullable=False,
        ),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint("reliability IN ('A', 'B', 'C', 'D', 'E', 'F')", name='source_reliability'),
        sa.CheckConstraint(
            'half_life_days IS NULL OR half_life_days BETWEEN 1 AND 3650', name='source_half_life'
        ),
    )


def downgrade() -> None:
    op.drop_table('source_ratings')
    with op.batch_alter_table('documents') as batch:
        batch.drop_column('credibility')
