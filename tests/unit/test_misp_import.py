"""A local MISP event file imports as a bounded, unreviewed snapshot with exact typed observations."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from insight import services
from insight.flags import flags
from insight.misp_import import MAX_MISP_BYTES, import_misp_event, parse_misp_event
from insight.models import Document
from insight.schemas import TLP_LEVELS

UUID_1 = 'ff1a6763-2c05-4eef-8c39-95dc1b4d9823'
UUID_2 = '12345678-1234-4abc-8abc-543210abcdef'


def event(**changes: Any) -> dict[str, Any]:
    return {
        'uuid': UUID_1,
        'info': 'Shared indicators',
        'distribution': '3',
        'date': '2026-11-21',
        'Tag': [{'name': 'tlp:clear'}],
        'Attribute': [{'type': 'domain', 'value': 'relay.example'}],
        **changes,
    }


def wire(item: dict[str, Any]) -> bytes:
    return json.dumps({'Event': item}).encode()


def test_supported_types_are_exact_with_source_spans_and_privacy_warning(db: Session) -> None:
    rows = [
        ('ip-src', '192.0.2.9', 'ip'),
        ('ip-dst', '2001:db8::/32', 'cidr'),
        ('email-src', 'CVE-2024-12345@example.org', 'email'),
        ('url', 'https://demo.example/CVE-2024-12345', 'url'),
        ('domain', 'invoice.zip', 'domain'),
        ('vulnerability', 'CVE-2026-12345', 'cve'),
        ('sha1', 'be' * 20, 'sha1'),
        ('sha512', 'ab' * 64, 'sha512'),
    ]
    attrs = [{'type': ty, 'value': val, 'to_ids': True, 'distribution': '5'} for ty, val, _ in rows]
    doc, created = import_misp_event(db, wire(event(Attribute=attrs)), max_tlp='GREEN')
    assert created
    assert doc.source_key == 'misp'
    assert doc.external_id == UUID_1
    assert (doc.tlp, doc.extractor_version) == ('CLEAR', 'misp-event-v1')
    observations = services.detail(db, doc)['observations']
    assert {(o['kind'], o['value']) for o in observations} == {(kind, val) for _, val, kind in rows}
    for obs in observations:
        assert doc.body[obs['start_offset'] : obs['end_offset']] == obs['value']
        assert obs['value'] in obs['evidence']
        assert obs['review_status'] == 'unreviewed'
        if obs['kind'] == 'email':
            assert 'personal-data' in flags(obs['kind'], obs['value'])


def test_repeated_event_deduplicates_and_changed_event_supersedes(db: Session) -> None:
    attrs = [{'type': 'ip-src', 'value': '198.51.100.9'}, {'type': 'domain', 'value': 'relay.example'}]
    a, created = import_misp_event(db, wire(event(Attribute=attrs)), max_tlp='AMBER')
    assert created
    reordered, created = import_misp_event(db, wire(event(Attribute=attrs[::-1])), max_tlp='AMBER')
    assert (reordered.id, created) == (a.id, False)
    attrs[0]['deleted'] = '1'
    b, created = import_misp_event(db, wire(event(Attribute=attrs)), max_tlp='AMBER')
    assert created
    assert b.supersedes_id == a.id
    assert not a.is_current
    assert [o['value'] for o in services.detail(db, b)['observations']] == ['relay.example']
    c, created = import_misp_event(db, wire(event(uuid=UUID_2, Attribute=attrs)), max_tlp='AMBER')
    assert created
    assert c.id != b.id
    assert c.external_id == UUID_2
    assert not c.supersedes_id
    attrs[1]['deleted'] = 'true'
    d, created = import_misp_event(db, wire(event(Attribute=attrs)), max_tlp='AMBER')
    assert created
    assert d.supersedes_id == b.id
    assert not services.detail(db, d)['observations']


@pytest.mark.parametrize(
    ('dist', 'expected'), [('0', 'AMBER+STRICT'), ('1', 'GREEN'), ('2', 'GREEN'), ('3', 'CLEAR')]
)
def test_distribution_can_only_raise_the_event_label(dist: str, expected: str) -> None:
    _, report, _ = parse_misp_event(wire(event(distribution=dist)))
    assert report.tlp == expected
    _, report, _ = parse_misp_event(
        wire(event(Attribute=[{'type': 'domain', 'value': 'relay.example', 'distribution': dist}]))
    )
    assert report.tlp == expected


def test_explicit_red_and_site_limit_apply_to_nested_tags_and_title(db: Session) -> None:
    for item in (
        event(Attribute=[{'type': 'domain', 'value': 'relay.example', 'Tag': [{'name': 'TLP:RED'}]}]),
        event(info='Briefing TLP:RED'),
        event(Tag=[{'name': 'tlp : red'}]),
        event(Attribute=[{'type': 'domain', 'value': 'relay.example', 'comment': 'Internal note TLP:RED'}]),
    ):
        with pytest.raises(ValueError, match='allow-red'):
            import_misp_event(db, wire(item), max_tlp='RED')
        with pytest.raises(services.TlpNotPermitted):
            import_misp_event(db, wire(item), max_tlp='AMBER+STRICT', allow_red=True)
    assert db.scalar(select(func.count()).select_from(Document)) == 0
    allowed, _ = import_misp_event(db, wire(item), max_tlp='RED', allow_red=True)
    assert allowed.tlp == 'RED'


def test_tags_are_merged_and_untagged_community_events_default_to_amber() -> None:
    for label in TLP_LEVELS:
        _, report, _ = parse_misp_event(wire(event(Tag=[{'name': 'tlp:white'}, {'name': f'tlp:{label}'}])))
        assert report.tlp == label
    item = event(distribution='3', Tag=[])
    assert parse_misp_event(json.dumps(item).encode())[1].tlp == 'AMBER'
    del item['distribution']
    assert parse_misp_event(wire(item))[1].tlp == 'AMBER+STRICT'


@pytest.mark.parametrize(
    'changes',
    [
        {'uuid': 'not a UUID'},
        {'uuid': '0' * 32},
        {'uuid': 12345678901234567890123456789012},
        {'disable_correlation': True},
        {'info': ' '},
        {'date': '2026-13-01'},
        {'Attribute': {}},
        {'distribution': '5'},
        {'distribution': '4'},
        {'sharing_group_id': '7'},
        {'Tag': [{'name': 'tlp:future'}]},
        {'Tag': [{'name': 1}]},
        {'EventTag': [{}]},
        {'Object': [{}]},
        {'Attribute': [17]},
        {'Attribute': [{'type': 'attachment', 'value': 'file', 'data': 'AAAA'}]},
        {'Attribute': [{'type': 'domain', 'value': 'relay.example', 'distribution': '4'}]},
        {'Attribute': [{'type': 'domain', 'value': 'relay.example', 'disable_correlation': True}]},
        {'Attribute': [{'type': 'domain', 'value': 'relay.example', 'Tag': [42]}]},
        {'Attribute': [{'type': 'domain', 'value': 'relay.example', 'deleted': 'invalid'}]},
        {'Attribute': [{'type': 'sha256', 'value': 'bad-hash'}]},
    ],
)
def test_invalid_or_unrepresentable_events_leave_existing_revision_untouched(
    db: Session, changes: dict[str, Any]
) -> None:
    a, _ = import_misp_event(db, wire(event()), max_tlp='AMBER')
    with pytest.raises(ValueError, match=r'MISP|Insight cannot import'):
        import_misp_event(db, wire(event(**changes)), max_tlp='RED', allow_red=True)
    assert a.is_current
    assert db.scalar(select(func.count()).select_from(Document)) == 1


def test_bounds_and_wrong_remote_event_id() -> None:
    for payload in (
        b' ' * (MAX_MISP_BYTES + 1),
        wire(event(Attribute=[{}] * 2001)),
        b'{"Event":{},"Event":{}}',
        b'[]',
        b'not json',
    ):
        with pytest.raises(ValueError, match='MISP'):
            parse_misp_event(payload)
    with pytest.raises(ValueError, match='different event UUID'):
        parse_misp_event(wire(event()), expected_uuid=UUID_2)
    assert parse_misp_event(wire(event()), expected_uuid=UUID_1)[0] == UUID_1


def test_oversized_report_error_does_not_disclose_restricted_values() -> None:
    attributes = [{'type': 'url', 'value': f'https://relay.example/{i}/' + 'a' * 8000} for i in range(30)]
    with pytest.raises(ValueError, match='exceeds Insight report limits') as err:
        parse_misp_event(wire(event(Attribute=attributes)))
    assert 'relay.example' not in str(err.value)


def test_replaying_original_snapshot_reactivates_original_revision(db: Session) -> None:
    first, _ = import_misp_event(db, wire(event()), max_tlp='AMBER')
    second, _ = import_misp_event(db, wire(event(info='Changed title')), max_tlp='AMBER')
    current, created = import_misp_event(db, wire(event()), max_tlp='AMBER')
    assert current.id == first.id
    assert current.is_current
    assert not second.is_current
    assert not created
    assert db.scalar(select(func.count()).select_from(Document)) == 2


def test_an_identical_manual_document_cannot_be_reported_as_a_misp_event(db: Session) -> None:
    payload = wire(event())
    manual, _ = services.ingest(db, parse_misp_event(payload)[1])
    with pytest.raises(ValueError, match='different source'):
        import_misp_event(db, payload, max_tlp='AMBER')
    assert manual.external_id is None
    assert db.scalar(select(func.count()).select_from(Document)) == 1


def test_failure_after_demoting_current_rolls_back_the_whole_revision(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as first_db:
        original, _ = import_misp_event(first_db, wire(event()), max_tlp='AMBER')

    def fail(*_: Any, **__: Any) -> None:
        raise RuntimeError('simulated storage failure')

    monkeypatch.setattr(services.documents, '_create_document', fail)
    with pytest.raises(RuntimeError, match='simulated storage failure'), session_factory.begin() as failed_db:
        import_misp_event(failed_db, wire(event(info='New revision')), max_tlp='AMBER')
    with session_factory.begin() as fresh:
        current = fresh.scalars(select(Document)).one()
        assert current.id == original.id
        assert current.is_current
