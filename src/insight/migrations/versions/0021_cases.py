"""Lightweight case management (TIP 3.8, ADR 0029): cases and the reports, indicators, actors, campaigns and
notes they hold. Deleting a report, indicator, actor or campaign removes it from every case.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0021'
down_revision: str | None = '0020'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'cases',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('updated_at', sa.String(40), nullable=False),
        sa.Column('closed_at', sa.String(40), nullable=True),
        sa.Column('close_note', sa.Text(), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint("status IN ('open', 'closed')", name='case_status'),
    )
    op.create_index('ix_cases_status', 'cases', ['status'])
    op.create_table(
        'case_items',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(12), nullable=False),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id', ondelete='CASCADE')),
        sa.Column('entity_id', sa.String(36), sa.ForeignKey('entities.id', ondelete='CASCADE')),
        sa.Column('actor_id', sa.String(36), sa.ForeignKey('threat_actors.id', ondelete='CASCADE')),
        sa.Column('campaign_id', sa.String(36), sa.ForeignKey('campaigns.id', ondelete='CASCADE')),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('added_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint(
            "kind IN ('document', 'indicator', 'actor', 'campaign', 'note')", name='case_item_kind'
        ),
        sa.CheckConstraint(
            '(CASE WHEN document_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN actor_id IS NULL THEN 0 ELSE 1 END + '
            "CASE WHEN campaign_id IS NULL THEN 0 ELSE 1 END) = CASE WHEN kind = 'note' THEN 0 ELSE 1 END",
            name='one_case_target',
        ),
        sa.UniqueConstraint('case_id', 'document_id'),
        sa.UniqueConstraint('case_id', 'entity_id'),
        sa.UniqueConstraint('case_id', 'actor_id'),
        sa.UniqueConstraint('case_id', 'campaign_id'),
    )
    for column in ('case_id', 'document_id', 'entity_id', 'actor_id', 'campaign_id'):
        op.create_index(f'ix_case_items_{column}', 'case_items', [column])


def downgrade() -> None:
    op.drop_table('case_items')
    op.drop_index('ix_cases_status', table_name='cases')
    op.drop_table('cases')
