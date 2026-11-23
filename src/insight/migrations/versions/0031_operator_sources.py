"""Operator-defined feeds and their sharing policy (TIP 4.5)."""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0031'
down_revision: str | None = '0030'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    timestamp = sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql')
    op.add_column('documents', sa.Column('reuse_changed_at', timestamp, nullable=True))
    op.create_table(
        'operator_sources',
        sa.Column('key', sa.String(35), primary_key=True),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('kind', sa.String(20), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('reuse', sa.String(20), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('created_at', timestamp, nullable=False),
        sa.Column('updated_at', timestamp, nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.Column('history_visible_since', timestamp, nullable=True),
    )


def downgrade() -> None:
    # Release 0030 recognizes this publisher key as restricted. Keep revisions together while
    # namespacing publisher item ids by feed. This also covers reports whose feed was already deleted.
    docs = sa.table('documents', sa.column('id'), sa.column('source_key'), sa.column('external_id'))
    own = docs.c.source_key.like('op-%')
    scoped = docs.c.source_key.concat(':id:').concat(docs.c.external_id)
    restricted = 'stix-import-metadata'
    conn = op.get_bind()
    # RSS identities are short hashes; handle other stored item IDs up to the existing 500-character limit.
    while rows := conn.execute(
        sa.select(docs.c.source_key, docs.c.external_id)
        .where(own, sa.func.length(scoped) > 500)
        .distinct()
        .limit(200)
    ).all():
        for key, item in rows:
            digest = hashlib.sha256(item.encode()).hexdigest()
            conn.execute(
                docs.update()
                .where(docs.c.source_key == key, docs.c.external_id == item)
                .values(source_key=restricted, external_id=f'{key}:sha256:{digest}')
            )
    conn.execute(
        docs.update()
        .where(own)
        .values(
            source_key=restricted,
            external_id=sa.case(
                (docs.c.external_id.is_(None), docs.c.source_key.concat(':doc:').concat(docs.c.id)),
                else_=scoped,
            ),
        )
    )
    for table, column in (
        ('schedules', 'source_key'),
        ('source_switches', 'source_key'),
        ('fetch_state', 'url'),
        ('source_runs', 'source_key'),
    ):
        target = sa.table(table, sa.column(column))
        conn.execute(target.delete().where(target.c[column].like('op-%')))
    jobs = sa.table('jobs', sa.column('kind'), sa.column('key'))
    conn.execute(jobs.delete().where(jobs.c.kind == 'source.sync', jobs.c.key.like('op-%')))
    op.drop_table('operator_sources')
    with op.batch_alter_table('documents') as batch:
        batch.drop_column('reuse_changed_at')
