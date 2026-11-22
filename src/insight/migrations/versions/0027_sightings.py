"""Sightings (TIP 4.2, ADR 0035): a hunt tool saw a known indicator in its own data. The unreleased
``read-rfi`` API key access level becomes ``read-feedback``, which may also send sightings.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0027'
down_revision: str | None = '0026'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _at(name: str) -> sa.Column[str]:
    return sa.Column(
        name, sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql'), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        'sightings',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column(
            'entity_id', sa.String(36), sa.ForeignKey('entities.id', ondelete='CASCADE'), nullable=False
        ),
        sa.Column(
            'hunt_package_id',
            sa.String(36),
            sa.ForeignKey('hunt_packages.id', ondelete='SET NULL'),
            nullable=True,
        ),
        _at('first_seen'),
        _at('last_seen'),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('location', sa.String(120), nullable=False),
        sa.Column('observer', sa.String(120), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('external_ref', sa.String(200), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        _at('created_at'),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint('count >= 1', name='sighting_count'),
    )
    op.create_index('ix_sightings_entity_id', 'sightings', ['entity_id'])
    op.create_index('ix_sightings_hunt_package_id', 'sightings', ['hunt_package_id'])
    op.execute("UPDATE api_keys SET access = 'read-feedback' WHERE access = 'read-rfi'")


def downgrade() -> None:
    op.execute("UPDATE api_keys SET access = 'read-rfi' WHERE access = 'read-feedback'")
    op.drop_index('ix_sightings_hunt_package_id', table_name='sightings')
    op.drop_index('ix_sightings_entity_id', table_name='sightings')
    op.drop_table('sightings')
