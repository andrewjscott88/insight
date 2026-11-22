"""Explicit actor/campaign associations for activity timelines (TIP 4.7)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0028'
down_revision: str | None = '0027'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    timestamp = sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql')
    with op.batch_alter_table('campaigns') as batch:
        batch.add_column(sa.Column('updated_at', timestamp, nullable=True))
    op.execute('UPDATE campaigns SET updated_at = created_at')
    with op.batch_alter_table('campaigns') as batch:
        batch.alter_column('updated_at', existing_type=timestamp, nullable=False)
    op.create_table(
        'actor_campaigns',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('group_ref', sa.String(36), nullable=False),
        sa.Column(
            'campaign_id', sa.String(36), sa.ForeignKey('campaigns.id', ondelete='CASCADE'), nullable=False
        ),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column(
            'created_at',
            sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql'),
            nullable=False,
        ),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('group_ref', 'campaign_id'),
    )
    op.create_index('ix_actor_campaigns_group_ref', 'actor_campaigns', ['group_ref'])
    op.create_index('ix_actor_campaigns_campaign_id', 'actor_campaigns', ['campaign_id'])


def downgrade() -> None:
    op.drop_table('actor_campaigns')
    with op.batch_alter_table('campaigns') as batch:
        batch.drop_column('updated_at')
