"""Intelligence requirements and requests for information (TIP 4.1, ADR 0032): requirements, the criteria that
make a report relevant to one, and the reports cited as evidence. Timestamps are ``timestamptz`` on PostgreSQL
and ISO strings elsewhere, like every other ``*_at`` column since migration 0022.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0024'
down_revision: str | None = '0023'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _at(name: str, *, nullable: bool = False) -> sa.Column[str]:
    kind = sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql')
    return sa.Column(name, kind, nullable=nullable)


def upgrade() -> None:
    op.create_table(
        'requirements',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('kind', sa.String(4), nullable=False),
        sa.Column('parent_id', sa.String(36), sa.ForeignKey('requirements.id'), nullable=True),
        sa.Column('question', sa.String(300), nullable=False),
        sa.Column('context', sa.Text(), nullable=False),
        sa.Column('stakeholder', sa.String(120), nullable=False),
        sa.Column('priority', sa.String(6), nullable=False),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('due_at', nullable=True),
        sa.Column('answer', sa.Text(), nullable=False),
        _at('answered_at', nullable=True),
        sa.Column('external_ref', sa.String(200), nullable=False),
        _at('created_at'),
        _at('updated_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint("kind IN ('pir', 'ir', 'rfi')", name='requirement_kind'),
        sa.CheckConstraint("status IN ('open', 'answered', 'retired')", name='requirement_status'),
        sa.CheckConstraint("priority IN ('high', 'medium', 'low')", name='requirement_priority'),
        sa.CheckConstraint("kind = 'ir' OR parent_id IS NULL", name='only_irs_have_parents'),
    )
    op.create_index('ix_requirements_parent_id', 'requirements', ['parent_id'])
    op.create_index('ix_requirements_status', 'requirements', ['status'])
    op.create_table(
        'requirement_criteria',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column(
            'requirement_id',
            sa.String(36),
            sa.ForeignKey('requirements.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('value', sa.String(120), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('added_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint(
            "kind IN ('term', 'cve', 'technique', 'group', 'campaign')", name='requirement_criterion_kind'
        ),
        sa.UniqueConstraint('requirement_id', 'kind', 'value'),
    )
    op.create_index('ix_requirement_criteria_requirement_id', 'requirement_criteria', ['requirement_id'])
    op.create_table(
        'requirement_evidence',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column(
            'requirement_id',
            sa.String(36),
            sa.ForeignKey('requirements.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column(
            'document_id', sa.String(36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False
        ),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('added_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('requirement_id', 'document_id'),
    )
    for column in ('requirement_id', 'document_id'):
        op.create_index(f'ix_requirement_evidence_{column}', 'requirement_evidence', [column])


def downgrade() -> None:
    op.drop_table('requirement_evidence')
    op.drop_table('requirement_criteria')
    op.drop_index('ix_requirements_status', table_name='requirements')
    op.drop_index('ix_requirements_parent_id', table_name='requirements')
    op.drop_table('requirements')
