"""Hunt packages (TIP 4.3, ADR 0034): a hypothesis to hunt for, with the ATT&CK techniques, indicators,
detection rules and reports behind it, served over TAXII once published. Rules may now also be Suricata or
Snort rules; their ``kind`` column already holds any of the four names, so it needs no change.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0026'
down_revision: str | None = '0025'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _at(name: str, *, nullable: bool = False) -> sa.Column[str]:
    kind = sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql')
    return sa.Column(name, kind, nullable=nullable)


def upgrade() -> None:
    op.create_table(
        'hunt_packages',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('hypothesis', sa.Text(), nullable=False),
        sa.Column('group_ref', sa.String(36), nullable=True),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('publication', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('created_at'),
        _at('updated_at'),
        _at('published_at', nullable=True),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint("status IN ('draft', 'published', 'retired')", name='hunt_package_status'),
    )
    op.create_index('ix_hunt_packages_status', 'hunt_packages', ['status'])
    op.create_table(
        'hunt_package_items',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column(
            'package_id', sa.String(36), sa.ForeignKey('hunt_packages.id', ondelete='CASCADE'), nullable=False
        ),
        sa.Column('kind', sa.String(12), nullable=False),
        sa.Column('technique_id', sa.String(16), nullable=True),
        sa.Column(
            'entity_id', sa.String(36), sa.ForeignKey('entities.id', ondelete='CASCADE'), nullable=True
        ),
        sa.Column(
            'rule_id', sa.String(36), sa.ForeignKey('detection_rules.id', ondelete='CASCADE'), nullable=True
        ),
        sa.Column(
            'document_id', sa.String(36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=True
        ),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('added_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint(
            "kind IN ('technique', 'indicator', 'rule', 'document')", name='hunt_package_item_kind'
        ),
        sa.CheckConstraint(
            '(CASE WHEN technique_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN rule_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN document_id IS NULL THEN 0 ELSE 1 END) = 1',
            name='one_hunt_package_target',
        ),
        sa.UniqueConstraint('package_id', 'technique_id'),
        sa.UniqueConstraint('package_id', 'entity_id'),
        sa.UniqueConstraint('package_id', 'rule_id'),
        sa.UniqueConstraint('package_id', 'document_id'),
    )
    for column in ('package_id', 'entity_id', 'rule_id', 'document_id'):
        op.create_index(f'ix_hunt_package_items_{column}', 'hunt_package_items', [column])


def downgrade() -> None:
    op.drop_table('hunt_package_items')
    op.drop_index('ix_hunt_packages_status', table_name='hunt_packages')
    op.drop_table('hunt_packages')
