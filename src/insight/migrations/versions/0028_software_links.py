"""Explicit software/report and actor/campaign/software links (TIP 4.7 part 2)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0028'
down_revision: str | None = '0027'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_TARGET = (
    '(CASE WHEN document_id IS NULL THEN 0 ELSE 1 END + '
    'CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END + '
    'CASE WHEN technique_id IS NULL THEN 0 ELSE 1 END) = 1'
)
_NEW_TARGET = _OLD_TARGET.replace(') = 1', ' + CASE WHEN software_id IS NULL THEN 0 ELSE 1 END) = 1')


def upgrade() -> None:
    op.create_table(
        'software_documents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('software_id', sa.String(16), nullable=False),
        sa.Column('software_name', sa.Text(), nullable=False),
        sa.Column('software_type', sa.String(10), nullable=False),
        sa.Column(
            'document_id', sa.String(36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False
        ),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column(
            'created_at',
            sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql'),
            nullable=False,
        ),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.Column(
            'updated_at',
            sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql'),
            nullable=False,
        ),
        sa.UniqueConstraint('software_id', 'document_id'),
    )
    for column in ('software_id', 'document_id'):
        op.create_index(f'ix_software_documents_{column}', 'software_documents', [column])
    with op.batch_alter_table('threat_links') as batch:
        batch.add_column(sa.Column('software_id', sa.String(16), nullable=True))
        batch.add_column(sa.Column('software_name', sa.Text(), nullable=False, server_default=''))
        batch.add_column(sa.Column('software_type', sa.String(10), nullable=False, server_default=''))
        batch.add_column(
            sa.Column(
                'updated_at',
                sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql'),
                nullable=True,
            )
        )
        batch.create_index('ix_threat_links_software_id', ['software_id'])
        batch.drop_constraint('one_threat_target', type_='check')
        batch.create_check_constraint('one_threat_target', _NEW_TARGET)
        for owner in ('actor_id', 'campaign_id'):
            batch.create_unique_constraint(f'uq_threat_links_{owner}_software_id', [owner, 'software_id'])
    op.execute('UPDATE threat_links SET updated_at = created_at')
    with op.batch_alter_table('threat_links') as batch:
        batch.alter_column('updated_at', nullable=False)


def downgrade() -> None:
    op.execute('DELETE FROM threat_links WHERE software_id IS NOT NULL')
    with op.batch_alter_table('threat_links') as batch:
        batch.drop_constraint('one_threat_target', type_='check')
        batch.create_check_constraint('one_threat_target', _OLD_TARGET)
        for owner in ('actor_id', 'campaign_id'):
            batch.drop_constraint(f'uq_threat_links_{owner}_software_id', type_='unique')
        batch.drop_index('ix_threat_links_software_id')
        for column in ('software_type', 'software_name', 'software_id', 'updated_at'):
            batch.drop_column(column)
    op.drop_table('software_documents')
