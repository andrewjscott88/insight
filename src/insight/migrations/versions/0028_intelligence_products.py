"""Finished intelligence products (TIP 4.4, ADR 0036): cases gain a product type, an audience, a bottom
line up front and publication; key judgements with their evidence, intelligence gaps and published versions
get their own tables. Existing cases become unpublished assessments; nothing else changes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0028'
down_revision: str | None = '0027'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _at(name: str, *, nullable: bool = False) -> sa.Column[str]:
    kind = sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql')
    return sa.Column(name, kind, nullable=nullable)


def upgrade() -> None:
    with op.batch_alter_table('cases') as batch:
        batch.add_column(
            sa.Column('product_type', sa.String(12), nullable=False, server_default='assessment')
        )
        batch.add_column(sa.Column('audience', sa.String(200), nullable=False, server_default=''))
        batch.add_column(sa.Column('bluf', sa.Text(), nullable=False, server_default=''))
        batch.add_column(sa.Column('version', sa.Integer(), nullable=False, server_default='0'))
        batch.add_column(_at('published_at', nullable=True))
    op.create_table(
        'case_judgements',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
        sa.Column('statement', sa.Text(), nullable=False),
        sa.Column('likelihood', sa.String(20), nullable=False),
        sa.Column('confidence', sa.String(10), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('created_at'),
        _at('updated_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint(
            "likelihood IN ('almost-no-chance', 'very-unlikely', 'unlikely', 'roughly-even-chance', "
            "'likely', 'very-likely', 'almost-certain')",
            name='judgement_likelihood',
        ),
        sa.CheckConstraint("confidence IN ('low', 'moderate', 'high')", name='judgement_confidence'),
    )
    op.create_index('ix_case_judgements_case_id', 'case_judgements', ['case_id'])
    op.create_table(
        'case_judgement_items',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column(
            'judgement_id',
            sa.String(36),
            sa.ForeignKey('case_judgements.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column(
            'item_id', sa.String(36), sa.ForeignKey('case_items.id', ondelete='CASCADE'), nullable=False
        ),
        sa.UniqueConstraint('judgement_id', 'item_id'),
    )
    op.create_index('ix_case_judgement_items_judgement_id', 'case_judgement_items', ['judgement_id'])
    op.create_index('ix_case_judgement_items_item_id', 'case_judgement_items', ['item_id'])
    op.create_table(
        'case_gaps',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('question', sa.Text(), nullable=False),
        sa.Column(
            'requirement_id',
            sa.String(36),
            sa.ForeignKey('requirements.id', ondelete='SET NULL'),
            nullable=True,
        ),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('created_at'),
        sa.Column('actor', sa.String(80), nullable=False),
    )
    op.create_index('ix_case_gaps_case_id', 'case_gaps', ['case_id'])
    op.create_index('ix_case_gaps_requirement_id', 'case_gaps', ['requirement_id'])
    op.create_table(
        'case_versions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('published_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.Column('snapshot', sa.Text(), nullable=False),
        sa.UniqueConstraint('case_id', 'version'),
    )
    op.create_index('ix_case_versions_case_id', 'case_versions', ['case_id'])


def downgrade() -> None:
    op.drop_table('case_versions')
    op.drop_table('case_gaps')
    op.drop_table('case_judgement_items')
    op.drop_table('case_judgements')
    with op.batch_alter_table('cases') as batch:
        for column in ('published_at', 'version', 'bluf', 'audience', 'product_type'):
            batch.drop_column(column)
