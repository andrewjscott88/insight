"""Domain services: ingestion, revisions, search, read models and analyst actions (no HTTP)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from contextlib import AbstractContextManager

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, KEVRecord, Note, Observation
from insight.schemas import DocumentInput
from insight.services import DocumentQuery, SourceRef, detail, fingerprint, ingest, summary

CountQueries = Callable[[Engine], AbstractContextManager[list[str]]]
KEV = SourceRef('cisa-kev', 'CVE-2024-12345')


def item(**changes: str) -> DocumentInput:
    base = {'title': 'T', 'body': 'CVE-2024-12345 at 192.0.2.8', 'source_name': 'S'}
    return DocumentInput(**{**base, **changes})


def count(db: Session, model: type) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0


def titles(docs: list[Document]) -> list[str]:
    return [d.title for d in docs]


# --------------------------------------------------------------------------- ingestion


def test_fingerprint_is_stable_across_releases() -> None:
    """Golden value computed with the 0.1.0 code: changing it silently breaks de-duplication."""
    assert (
        fingerprint(item(tlp='CLEAR')) == '2c21dbf46ff2c161af3c0fd7d58335102074b67cfe8b2cc95f0a204c15553a19'
    )


def test_ingest_creates_document_entities_observations_and_audit(db: Session) -> None:
    doc, created = ingest(db, item())
    assert created
    assert doc.content_hash == hashlib.sha256(b'CVE-2024-12345 at 192.0.2.8').hexdigest()
    assert (doc.source_key, doc.external_id, doc.is_current, doc.supersedes_id) == (None, None, True, None)
    assert count(db, Entity) == 2
    assert count(db, Observation) == 2
    event = db.scalar(select(AuditEvent))
    assert event is not None
    assert (event.action, event.object_id, event.detail) == ('document.ingest', doc.id, doc.content_hash)


def test_exact_resubmission_is_idempotent(db: Session) -> None:
    first, _ = ingest(db, item())
    again, created = ingest(db, item())
    assert not created
    assert again.id == first.id
    assert count(db, Observation) == 2
    assert count(db, AuditEvent) == 1


def test_distinct_provenance_is_retained_and_entities_shared(db: Session) -> None:
    a, _ = ingest(db, item())
    b, _ = ingest(db, item(source_name='Other publisher'))
    c, _ = ingest(db, item(tlp='RED'))
    assert len({a.id, b.id, c.id}) == 3
    assert a.content_hash == b.content_hash == c.content_hash
    assert count(db, Entity) == 2
    assert count(db, Observation) == 6


def test_repeated_mentions_are_distinct_observations_of_one_entity(db: Session) -> None:
    ingest(db, item(body='CVE-2024-1111 and again cve-2024-1111'))
    assert count(db, Entity) == 1
    assert count(db, Observation) == 2


# --------------------------------------------------------------------------- revisions (decision 6)


def test_keyed_item_unchanged_content_is_a_no_op(db: Session) -> None:
    first, created = ingest(db, item(), ref=KEV)
    again, created_again = ingest(db, item(), ref=KEV)
    assert created
    assert not created_again
    assert again.id == first.id
    assert (first.source_key, first.external_id) == ('cisa-kev', 'CVE-2024-12345')


def test_changed_content_creates_a_superseding_revision(db: Session) -> None:
    v1, _ = ingest(db, item(body='v1 CVE-2024-12345'), ref=KEV)
    v2, created = ingest(db, item(body='v2 CVE-2024-12345 edited by publisher'), ref=KEV)
    assert created
    assert (v1.is_current, v2.is_current, v2.supersedes_id) == (False, True, v1.id)
    assert v1.body == 'v1 CVE-2024-12345'  # never edited in place: offsets stay valid
    actions = list(db.scalars(select(AuditEvent.action)))
    assert actions.count('document.revision.supersede') == 1
    assert [r['id'] for r in services.revisions(db, v2)] == [v1.id, v2.id]


def test_reverting_to_earlier_content_reactivates_that_revision(db: Session) -> None:
    v1, _ = ingest(db, item(body='v1 CVE-2024-12345'), ref=KEV)
    v2, _ = ingest(db, item(body='v2 CVE-2024-12345'), ref=KEV)
    back, created = ingest(db, item(body='v1 CVE-2024-12345'), ref=KEV)
    assert not created
    assert back.id == v1.id
    assert (v1.is_current, v2.is_current) == (True, False)
    assert count(db, Document) == 2
    assert 'document.revision.reactivate' in db.scalars(select(AuditEvent.action)).all()


def test_different_items_from_one_source_are_independent(db: Session) -> None:
    a, _ = ingest(db, item(body='A'), ref=SourceRef('cisa-kev', 'CVE-1'))
    b, _ = ingest(db, item(body='B'), ref=SourceRef('cisa-kev', 'CVE-2'))
    assert a.is_current
    assert b.is_current


def test_keyed_ingest_matching_a_manual_document_returns_it_unchanged(db: Session) -> None:
    manual, _ = ingest(db, item())
    same, created = ingest(db, item(), ref=KEV)
    assert not created
    assert same.id == manual.id
    assert manual.source_key is None


def test_invalid_revision_does_not_demote_the_current_one(db: Session) -> None:
    v1, _ = ingest(db, item(body='CVE-2024-12345'), ref=KEV)
    with pytest.raises(ValueError, match='exceeds'):
        ingest(db, item(body='CVE-2024-12345 ' * 2001), ref=KEV)
    assert v1.is_current


# --------------------------------------------------------------------------- search (decision 5)


@pytest.fixture
def corpus(db: Session) -> Session:
    ingest(db, item(title='Literal 100% report', body='needle', source_name='Alpha Publisher'))
    ingest(db, item(title='Under_score', body='x', source_name='Beta', tlp='RED'))
    ingest(db, item(title='MiXeD CaSe Title', body='Body', source_name='Gamma'))
    ingest(db, item(title='Old revision', body='superseded text'), ref=KEV)
    ingest(db, item(title='New revision', body='current text'), ref=KEV)
    return db


@pytest.mark.parametrize(
    ('q', 'expected'),
    [
        ('needle', ['Literal 100% report']),
        ('NEEDLE', ['Literal 100% report']),  # case-insensitive on every backend
        ('mixed case', ['MiXeD CaSe Title']),
        ('alpha publisher', ['Literal 100% report']),  # source name is searched too
        ('100%', ['Literal 100% report']),
        ('%', ['Literal 100% report']),  # '%' is literal, not a wildcard
        ('_', ['Under_score']),  # '_' is literal, not a single-character wildcard
        ('  needle  ', ['Literal 100% report']),  # surrounding whitespace is ignored
        ('superseded', []),  # superseded revisions are hidden by default
    ],
)
def test_search_semantics(corpus: Session, q: str, expected: list[str]) -> None:
    assert titles(services.search_documents(corpus, DocumentQuery(q=q))) == expected


def test_search_filters_and_superseded(corpus: Session) -> None:
    assert titles(services.search_documents(corpus, DocumentQuery(tlp='RED'))) == ['Under_score']
    assert services.search_documents(corpus, DocumentQuery(status='reviewed')) == []
    everything = services.search_documents(corpus, DocumentQuery(include_superseded=True))
    assert 'Old revision' in titles(everything)
    assert 'Old revision' not in titles(services.search_documents(corpus, DocumentQuery()))


def test_search_pagination_is_bounded(corpus: Session) -> None:
    assert len(services.search_documents(corpus, DocumentQuery(limit=0))) == 1
    assert len(services.search_documents(corpus, DocumentQuery(limit=10_000))) == 4
    assert len(services.search_documents(corpus, DocumentQuery(offset=-3))) == 4
    assert len(services.search_documents(corpus, DocumentQuery(offset=3))) == 1


def test_search_query_is_length_bounded(corpus: Session) -> None:
    assert services.search_documents(corpus, DocumentQuery(q='needle' + 'x' * 500)) == []


# --------------------------------------------------------------------------- read models (decision 3)


def test_summaries_use_a_constant_number_of_queries(db: Session, count_queries: CountQueries) -> None:
    """Regression: entity counts were fetched with one query per document (N+1)."""
    for i in range(30):
        ingest(db, item(title=f'T{i}', body=f'CVE-2024-{10000 + i} at 192.0.2.{i}'))
    docs = services.search_documents(db, DocumentQuery(limit=200))
    bind = db.get_bind()
    assert isinstance(bind, Engine)
    with count_queries(bind) as statements:
        rows = services.summaries(db, docs)
    assert len(rows) == 30
    assert len(statements) == 1
    assert {r['entity_count'] for r in rows} == {2}


def test_summaries_of_nothing_runs_no_query(db: Session, count_queries: CountQueries) -> None:
    bind = db.get_bind()
    assert isinstance(bind, Engine)
    with count_queries(bind) as statements:
        assert services.summaries(db, []) == []
    assert statements == []


def test_document_without_observables(db: Session) -> None:
    doc, _ = ingest(db, item(body='Nothing to see here'))
    assert summary(db, doc)['entity_count'] == 0
    assert detail(db, doc)['observations'] == []


def test_summary_shape_and_truncation(db: Session) -> None:
    doc, _ = ingest(db, item(body='x' * 1000))
    result = summary(db, doc)
    assert len(result['summary']) == 220
    assert set(result) == {
        'id',
        'title',
        'source_name',
        'source_url',
        'tlp',
        'status',
        'created_at',
        'summary',
        'entity_count',
        'is_current',
        'truncated',
        'credibility',
    }


def test_detail_includes_offsets_kev_context_notes_and_revisions(db: Session) -> None:
    doc, _ = ingest(db, item(), ref=KEV)
    db.add(
        KEVRecord(
            cve='CVE-2024-12345',
            vendor='V',
            product='P',
            date_added='2025-01-01',
            due_date='2025-01-22',
            required_action='Patch',
        )
    )
    db.add_all(
        [
            Note(document_id=doc.id, body='first', created_at='2025-01-01T00:00:00+00:00'),
            Note(document_id=doc.id, body='second', created_at='2025-01-02T00:00:00+00:00'),
        ]
    )
    db.flush()
    result = detail(db, doc)
    cve, ip = result['observations']
    assert (cve['kind'], cve['start_offset'], cve['end_offset']) == ('cve', 0, 14)
    assert cve['kev']['required_action'] == 'Patch'
    assert ip['kev'] is None
    assert [n['body'] for n in result['notes']] == ['first', 'second']
    assert (result['source_key'], result['external_id'], result['supersedes_id']) == (
        'cisa-kev',
        'CVE-2024-12345',
        None,
    )
    assert [r['id'] for r in result['revisions']] == [doc.id]


def test_manual_documents_have_no_revision_history(db: Session) -> None:
    doc, _ = ingest(db, item())
    assert services.revisions(db, doc) == []


def test_stats_count_current_revisions_only(db: Session) -> None:
    ingest(db, item(body='v1 CVE-2024-12345'), ref=KEV)
    ingest(db, item(body='v2 CVE-2024-12345'), ref=KEV)
    ingest(db, item(title='manual', body='192.0.2.1'))
    assert services.stats(db) == {
        'documents': 2,
        'entities': 2,
        'unreviewed': 2,
        'observations_unreviewed': 2,
    }


def test_entities_listing_search_and_pivot(db: Session) -> None:
    a, _ = ingest(db, item(body='CVE-2024-12345 twice CVE-2024-12345'))
    b, _ = ingest(db, item(body='CVE-2024-12345', source_name='Other'))
    rows = services.list_entities(db, 'cve-2024')  # case-insensitive
    assert [(e.value, n) for e, n in rows] == [('CVE-2024-12345', 2)]
    assert services.list_entities(db, '%') == []
    entity_id = rows[0][0].id
    assert {d.id for d in services.entity_documents(db, entity_id)} == {a.id, b.id}
    assert services.get_entity(db, entity_id) is not None


# --------------------------------------------------------------------------- analyst actions


def test_status_changes_are_validated_and_audited(db: Session) -> None:
    doc, _ = ingest(db, item())
    obs = db.scalars(select(Observation)).first()
    assert obs is not None
    assert services.set_document_status(db, doc.id, 'reviewed') is doc
    assert services.set_observation_status(db, obs.id, 'accepted') is obs
    assert services.set_document_status(db, 'missing', 'reviewed') is None
    assert services.set_observation_status(db, 'missing', 'accepted') is None
    with pytest.raises(ValueError, match='Unknown'):
        services.set_document_status(db, doc.id, 'invented')
    with pytest.raises(ValueError, match='Unknown'):
        services.set_observation_status(db, obs.id, 'malicious')
    actions = db.scalars(select(AuditEvent.action)).all()
    assert {'document.review', 'observation.review'} <= set(actions)


def test_a_review_records_when_the_status_changed(db: Session) -> None:
    """TAXII polls with added_after: an indicator accepted after its report arrived must say when."""
    ingest(db, item())
    obs = db.scalars(select(Observation)).first()
    assert obs is not None
    times: list[str | None] = [obs.reviewed_at]
    services.set_observation_status(db, obs.id, 'accepted')
    times.append(obs.reviewed_at)
    services.set_observation_status(db, obs.id, 'accepted')  # no change, so no new time
    times.append(obs.reviewed_at)
    services.set_observation_status(db, obs.id, 'rejected')
    times.append(obs.reviewed_at)
    never, accepted, unchanged, rejected = times
    assert never is None
    assert accepted is not None
    assert unchanged == accepted
    assert rejected is not None
    assert rejected >= accepted


def test_notes(db: Session) -> None:
    doc, _ = ingest(db, item())
    note = services.add_note(db, doc.id, 'Checked.')
    assert note is not None
    assert services.add_note(db, 'missing', 'x') is None
    assert 'note.add' in db.scalars(select(AuditEvent.action)).all()


def test_watch_terms_lifecycle(db: Session) -> None:
    term = services.add_watch_term(db, '  GlobalProtect  ')
    assert term is not None
    assert term.term == 'GlobalProtect'
    assert services.add_watch_term(db, 'globalprotect') is None  # case-insensitive duplicate
    for bad in ('', '   ', 'x' * 121):
        with pytest.raises(ValueError, match='between 1 and 120'):
            services.add_watch_term(db, bad)
    assert [t.term for t in services.list_watch_terms(db)] == ['GlobalProtect']
    assert services.remove_watch_term(db, term.id)
    assert not services.remove_watch_term(db, term.id)
    actions = db.scalars(select(AuditEvent.action)).all()
    assert {'watch_term.create', 'watch_term.remove'} <= set(actions)


@pytest.mark.parametrize(
    ('terms', 'text', 'expected'),
    [
        (['VPN', 'Citrix'], 'New vpn flaw', ['VPN']),
        (['Palo Alto'], 'PALO ALTO networks', ['Palo Alto']),
        (['x'], '', []),
        ([], 'anything', []),
    ],
)
def test_watch_matches(terms: list[str], text: str, expected: list[str]) -> None:
    assert services.watch_matches(terms, text) == expected


def test_like_pattern_escapes_wildcards() -> None:
    assert services.like_pattern('50%_\\') == '%50\\%\\_\\\\%'


@pytest.mark.parametrize('mentions', [1, 10, 100])
def test_ingest_query_count_does_not_grow_with_mentions(
    db: Session, count_queries: CountQueries, mentions: int
) -> None:
    """Regression: two round trips per extracted entity made PostgreSQL ingest 14x slower than SQLite."""
    body = ' '.join(f'CVE-2024-{10000 + i}' for i in range(mentions))
    ingest(db, item(title='warm-up', body='CVE-2024-10000'))  # one entity already exists
    bind = db.get_bind()
    assert isinstance(bind, Engine)
    with count_queries(bind) as statements:
        ingest(db, item(body=body))
    assert len(statements) <= 7, statements
    assert count(db, Observation) == 1 + mentions


def test_same_value_under_a_different_kind_is_a_different_entity(db: Session) -> None:
    """Found by mutation testing: dropping the ``kind`` condition from the batched lookup survived."""
    db.add(Entity(kind='url', value='example.com'))
    db.flush()
    doc, _ = ingest(db, item(body='Seen example.com again'))
    (observation,) = db.scalars(select(Observation).where(Observation.document_id == doc.id))
    entity = db.get(Entity, observation.entity_id)
    assert entity is not None
    assert (entity.kind, entity.value) == ('domain', 'example.com')


def test_revisions_are_scoped_to_their_source(db: Session) -> None:
    """Found by mutation testing: two sources may use the same external id (e.g. a shared link)."""
    shared = 'https://example.org/advisory/1'
    a, _ = ingest(db, item(body='A'), ref=SourceRef('cisa-advisories', shared))
    b, _ = ingest(db, item(body='B'), ref=SourceRef('ncsc', shared))
    assert a.is_current
    assert b.is_current
    assert b.supersedes_id is None


@pytest.mark.parametrize(
    ('text', 'folded'),
    [
        ('ÜBERWACHUNG', 'uberwachung'),
        ('İSTANBUL', 'istanbul'),
        ('cafe\u0301', 'cafe'),  # NFD
        ('café', 'cafe'),  # NFC
        ('Straße', 'strasse'),
        ('ＦＵＬＬＷＩＤＴＨ', 'fullwidth'),
        ('exam\u200bple', 'example'),
        ('標的型攻撃', '標的型攻撃'),
    ],
)
def test_fold(text: str, folded: str) -> None:
    assert services.fold(text) == folded


def test_entity_pivots_are_paginated(db: Session) -> None:
    for i in range(30):
        ingest(db, item(title=f'T{i}', body='Shared 192.0.2.99'))
    entity = db.scalar(select(Entity).where(Entity.value == '192.0.2.99'))
    assert entity is not None
    first = services.entity_documents(db, entity.id)
    second = services.entity_documents(db, entity.id, offset=services.PIVOT_PAGE_SIZE)
    assert len(first) == services.PIVOT_PAGE_SIZE
    assert len(second) == 30 - services.PIVOT_PAGE_SIZE
    assert not {d.id for d in first} & {d.id for d in second}
    assert services.count_entity_documents(db, entity.id) == 30


def test_truncated_flag_is_stored(db: Session) -> None:
    doc, _ = ingest(db, item(), truncated=True)
    assert doc.truncated
    assert services.detail(db, doc)['truncated'] is True
