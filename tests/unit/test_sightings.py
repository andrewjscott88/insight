"""Sightings (TIP 4.2, ADR 0035): known indicators a hunt tool saw in its own data, and their confidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Entity
from insight.schemas import DocumentInput, HuntPackageInput, HuntPackageItemInput, SightingInput

NOW = datetime.now(UTC)


def report(db: Session, body: str, tlp: str = 'GREEN') -> None:
    services.ingest(db, DocumentInput(title='Note', body=body, source_name='Blog', tlp=tlp))


def entity(db: Session, value: str) -> str:
    found: str = db.scalars(select(Entity.id).where(Entity.value == value)).one()
    return found


def sighting(**fields: object) -> SightingInput:
    return SightingInput.model_validate({'first_seen': NOW - timedelta(days=1), 'tlp': 'GREEN'} | fields)


def test_a_sighting_is_matched_by_value_and_is_the_strongest_signal(db: Session) -> None:
    report(db, 'C2 at 203.0.113.90 and evil.example.')
    ip = entity(db, '203.0.113.90')
    before = services.indicator_confidence(db, ip)
    row = services.record_sighting(db, sighting(value=' 203.0.113.90 ', where='Corp east', count=3))
    assert (row.entity_id, row.count, row.location, row.tlp) == (ip, 3, 'Corp east', 'GREEN')
    after = services.indicator_confidence(db, ip)
    assert after.score > before.score
    assert after.band == 'high'
    seen = next(s for s in after.sources if s.kind == 'sighting')
    assert (seen.source_name, seen.reliability, seen.reports) == ('Seen in Corp east', 'A', 1)
    recent = NOW - timedelta(hours=1)
    services.record_sighting(
        db, sighting(value='EVIL.example', kind='domain', observer='Shift', first_seen=recent)
    )
    assert [s.value for s in services.list_sightings(db)] == ['evil.example', '203.0.113.90']
    events = list(db.scalars(select(AuditEvent.action).where(AuditEvent.object_id == ip)))
    assert 'sighting.add' in events


def test_old_sightings_count_for_less(db: Session) -> None:
    report(db, 'C2 at 203.0.113.91.')
    ip = entity(db, '203.0.113.91')
    services.record_sighting(db, sighting(value='203.0.113.91', first_seen=NOW - timedelta(days=60)))
    weight = next(s for s in services.indicator_confidence(db, ip).sources if s.kind == 'sighting').weight
    assert weight == round(90 * 0.25)  # two half-lives of an IP address


def test_unknown_hidden_and_future_sightings_are_refused(db: Session) -> None:
    report(db, 'C2 at 203.0.113.92.', tlp='AMBER')
    with pytest.raises(LookupError):
        services.record_sighting(db, sighting(value='198.51.100.250'))
    with pytest.raises(LookupError):
        services.record_sighting(db, sighting(value='203.0.113.92'), max_tlp='GREEN')
    with pytest.raises(ValueError, match='Not a valid ip'):
        services.record_sighting(db, sighting(value='not-an-ip', kind='ip'))
    with pytest.raises(ValidationError):
        sighting(value='203.0.113.92', first_seen=NOW + timedelta(hours=1))
    with pytest.raises(ValidationError):
        sighting(value='203.0.113.92', last_seen=NOW - timedelta(days=3))


def test_labels_limit_who_sees_a_sighting(db: Session) -> None:
    report(db, 'C2 at 203.0.113.93.')
    report(db, 'C2 at 203.0.113.94.', tlp='AMBER')
    ip = entity(db, '203.0.113.93')
    package = services.create_hunt_package(
        db,
        HuntPackageInput(title='Hunt', hypothesis='H', tlp='AMBER',
                         items=[HuntPackageItemInput(kind='indicator', target_id=ip)]),
    )  # fmt: skip
    services.record_sighting(db, sighting(value='203.0.113.93', hunt_package_id=package.id))  # AMBER: package
    services.record_sighting(db, sighting(value='203.0.113.93', note='Seen TLP:RED'))
    services.record_sighting(db, sighting(value='203.0.113.94'))  # GREEN sighting of an AMBER-only indicator
    assert sorted(s.tlp for s in services.list_sightings(db)) == ['AMBER', 'GREEN', 'RED']
    assert services.list_sightings(db, max_tlp='GREEN') == []
    assert [s.tlp for s in services.list_sightings(db, max_tlp='AMBER', entity_id=ip)] == ['AMBER']
    assert not [
        s for s in services.indicator_confidence(db, ip, max_tlp='GREEN').sources if s.kind == 'sighting'
    ]
    hidden = services.list_sightings(db, max_tlp='AMBER', hunt_package_id=package.id)[0]
    with pytest.raises(LookupError):
        services.delete_sighting(db, hidden.id, max_tlp='GREEN')
    services.delete_sighting(db, hidden.id)
    assert len(services.list_sightings(db)) == 2
