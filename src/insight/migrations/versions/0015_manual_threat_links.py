"""Manual campaigns and scoped actor/campaign links.

Revision ID: 0015
Revises: 0014
"""

import re

import sqlalchemy as sa
from alembic import op

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


_LABELS = ('CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED')
_MARKING = re.compile(r'\bTLP\s*:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)\b', re.IGNORECASE)


def _backfill_labels() -> None:
    """Preserve sharing markings already written in local actor records and report-link notes."""
    conn = op.get_bind()
    actors = sa.table(
        'threat_actors', *(sa.column(k) for k in ('id', 'tlp', 'name', 'aliases', 'description'))
    )
    docs = sa.table('documents', sa.column('id'), sa.column('tlp'))
    links = sa.table(
        'actor_documents', *(sa.column(k) for k in ('id', 'tlp', 'group_ref', 'document_id', 'note'))
    )
    rows = sa.select(actors.c.id, actors.c.tlp, actors.c.name, actors.c.aliases, actors.c.description)
    last = ''
    while batch := conn.execute(rows.where(actors.c.id > last).order_by(actors.c.id).limit(500)).all():
        for last, stored, name, aliases, description in batch:
            raised = _label(stored, 'CLEAR', f'{name} {aliases} {description}')
            if raised != stored:
                conn.execute(actors.update().where(actors.c.id == last).values(tlp=raised))
    link_rows = sa.select(links.c.id, docs.c.tlp, actors.c.tlp, links.c.note).select_from(
        links.join(docs, docs.c.id == links.c.document_id).outerjoin(actors, actors.c.id == links.c.group_ref)
    )
    last = ''
    while link_batch := conn.execute(
        link_rows.where(links.c.id > last).order_by(links.c.id).limit(500)
    ).all():
        for last, doc_tlp, actor_tlp, note in link_batch:
            raised = _label(doc_tlp, actor_tlp or 'CLEAR', note)
            if raised != 'CLEAR':
                conn.execute(links.update().where(links.c.id == last).values(tlp=raised))


def _label(subject: str, target: str, text: str) -> str:
    marked = ['CLEAR' if m.upper() == 'WHITE' else m.upper() for m in _MARKING.findall(text)]
    return max((subject, target, *marked), key=_LABELS.index)


def upgrade() -> None:
    op.add_column('actor_documents', sa.Column('tlp', sa.String(20), nullable=False, server_default='CLEAR'))
    _backfill_labels()
    op.create_table(
        'campaigns',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('aliases', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
    )
    op.create_table(
        'threat_links',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('actor_id', sa.String(36), sa.ForeignKey('threat_actors.id', ondelete='CASCADE')),
        sa.Column('campaign_id', sa.String(36), sa.ForeignKey('campaigns.id', ondelete='CASCADE')),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id', ondelete='CASCADE')),
        sa.Column('entity_id', sa.String(36), sa.ForeignKey('entities.id', ondelete='CASCADE')),
        sa.Column('technique_id', sa.String(16)),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.CheckConstraint('(actor_id IS NULL) <> (campaign_id IS NULL)', name='one_threat_subject'),
        sa.CheckConstraint(
            '(CASE WHEN document_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN technique_id IS NULL THEN 0 ELSE 1 END) = 1',
            name='one_threat_target',
        ),
        sa.CheckConstraint('actor_id IS NULL OR document_id IS NULL', name='existing_actor_reports'),
        sa.UniqueConstraint('actor_id', 'entity_id'),
        sa.UniqueConstraint('actor_id', 'technique_id'),
        sa.UniqueConstraint('campaign_id', 'document_id'),
        sa.UniqueConstraint('campaign_id', 'entity_id'),
        sa.UniqueConstraint('campaign_id', 'technique_id'),
    )
    for col in ('actor_id', 'campaign_id', 'document_id', 'entity_id', 'technique_id'):
        op.create_index(f'ix_threat_links_{col}', 'threat_links', [col])


def downgrade() -> None:
    op.drop_table('threat_links')
    op.drop_table('campaigns')
    op.drop_column('actor_documents', 'tlp')
