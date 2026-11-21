"""Industry threat profiles and actor threat guides (TIP 2.10, ADR 0025), with the minimum of TIP 2.5 and 2.7.

* ``threat_actors``: actors the analyst created (never inferred), optionally linked to an ATT&CK group.
* ``actor_documents``: reports the analyst linked to a group or actor.
* ``industry_claims``: the analyst's own industry mappings (added with a citation, or removed with a reason).
* ``detection_rules`` and ``rule_links``: YARA and Sigma rules carried as text and linked to groups,
  techniques or reports. Never executed.
* ``hunts`` and ``hunt_checks``: hunt records kept with a guide, one check per hypothesis (technique).

The ATT&CK groups themselves are not in the database: they come from the bundled or synced threat library.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0014'
down_revision: str | None = '0013'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'threat_actors',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('aliases', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('attack_group_id', sa.String(10), nullable=True),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('updated_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
    )
    op.create_table(
        'actor_documents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('group_ref', sa.String(36), nullable=False),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('group_ref', 'document_id'),
    )
    op.create_index('ix_actor_documents_group_ref', 'actor_documents', ['group_ref'])
    op.create_index('ix_actor_documents_document_id', 'actor_documents', ['document_id'])
    op.create_table(
        'industry_claims',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('group_ref', sa.String(36), nullable=False),
        sa.Column('industry', sa.String(40), nullable=False),
        sa.Column('decision', sa.String(10), nullable=False),
        sa.Column('citation_url', sa.Text(), nullable=False),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('group_ref', 'industry'),
    )
    op.create_index('ix_industry_claims_group_ref', 'industry_claims', ['group_ref'])
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('licence', sa.String(120), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('content_hash'),
    )
    op.create_table(
        'rule_links',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('rule_id', sa.String(36), sa.ForeignKey('detection_rules.id'), nullable=False),
        sa.Column('target_kind', sa.String(12), nullable=False),
        sa.Column('target_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('rule_id', 'target_kind', 'target_id'),
    )
    op.create_index('ix_rule_links_rule_id', 'rule_links', ['rule_id'])
    op.create_index('ix_rule_links_target_id', 'rule_links', ['target_id'])
    op.create_table(
        'hunts',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('group_ref', sa.String(36), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('updated_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
    )
    op.create_index('ix_hunts_group_ref', 'hunts', ['group_ref'])
    op.create_table(
        'hunt_checks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('hunt_id', sa.String(36), sa.ForeignKey('hunts.id'), nullable=False),
        sa.Column('technique_id', sa.String(16), nullable=False),
        sa.Column('result', sa.String(20), nullable=False),
        sa.Column('data_checked', sa.Text(), nullable=False),
        sa.Column('period_start', sa.String(40), nullable=False),
        sa.Column('period_end', sa.String(40), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('updated_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.UniqueConstraint('hunt_id', 'technique_id'),
    )
    op.create_index('ix_hunt_checks_hunt_id', 'hunt_checks', ['hunt_id'])


def downgrade() -> None:
    op.drop_index('ix_hunt_checks_hunt_id', table_name='hunt_checks')
    op.drop_table('hunt_checks')
    op.drop_index('ix_hunts_group_ref', table_name='hunts')
    op.drop_table('hunts')
    op.drop_index('ix_rule_links_target_id', table_name='rule_links')
    op.drop_index('ix_rule_links_rule_id', table_name='rule_links')
    op.drop_table('rule_links')
    op.drop_table('detection_rules')
    op.drop_index('ix_industry_claims_group_ref', table_name='industry_claims')
    op.drop_table('industry_claims')
    op.drop_index('ix_actor_documents_document_id', table_name='actor_documents')
    op.drop_index('ix_actor_documents_group_ref', table_name='actor_documents')
    op.drop_table('actor_documents')
    op.drop_table('threat_actors')
