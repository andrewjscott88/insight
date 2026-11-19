"""INSIGHT_MAX_TLP in the service layer: reports above the limit are refused before anything is stored."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document
from insight.schemas import DocumentInput

LIMIT = 'AMBER+STRICT'


def item(body: str = 'Seen at 192.0.2.8.', tlp: str = 'AMBER', title: str = 'Report') -> DocumentInput:
    return DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Analyst', 'tlp': tlp})


def stored(db: Session) -> tuple[int, int]:
    return db.scalar(select(func.count()).select_from(Document)) or 0, db.scalar(
        select(func.count()).select_from(AuditEvent)
    ) or 0


def test_a_report_labelled_red_is_refused_and_nothing_is_stored(db: Session) -> None:
    with pytest.raises(services.TlpNotPermitted) as exc:
        services.ingest(db, item(tlp='RED'), max_tlp=LIMIT)
    assert str(exc.value) == (
        'TLP:RED reports cannot be stored here. This instance stores reports up to TLP:AMBER+STRICT '
        '(INSIGHT_MAX_TLP).'
    )
    assert stored(db) == (0, 0)


@pytest.mark.parametrize(
    ('title', 'body'),
    [
        ('Report', 'TLP:RED - do not share.\nSeen at 192.0.2.8.'),
        ('TLP: red briefing', 'Seen at 192.0.2.8.'),  # in the title, any case and spacing
    ],
)
def test_a_red_marking_in_the_text_cannot_slip_past_the_limit(db: Session, title: str, body: str) -> None:
    """The limit applies to the label *after* raising, so submitting the text as AMBER does not help."""
    with pytest.raises(services.TlpNotPermitted) as exc:
        services.ingest(db, item(body, tlp='AMBER', title=title), max_tlp=LIMIT)
    message = str(exc.value)
    assert message.startswith('Refused: the text carries a TLP:RED marking, so the report counts as TLP:RED')
    assert '(submitted as TLP:AMBER)' in message
    assert 'If the text only mentions that label, reword it.' in message
    assert stored(db) == (0, 0)


def test_refusals_are_logged_without_content(db: Session, caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(services.TlpNotPermitted):
        services.ingest(db, item('TLP:RED secret-victim.example'), max_tlp=LIMIT)
    assert 'Refused a TLP:RED report (submitted as TLP:AMBER; limit TLP:AMBER+STRICT)' in caplog.text
    assert 'secret-victim' not in caplog.text


def test_an_existing_red_duplicate_is_not_returned_either(db: Session) -> None:
    """A RED report stored before the limit existed is not handed back as an 'exact duplicate'."""
    services.ingest(db, item(tlp='RED'))
    with pytest.raises(services.TlpNotPermitted):
        services.ingest(db, item(tlp='RED'), max_tlp=LIMIT)


@pytest.mark.parametrize('tlp', ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT'])
def test_labels_up_to_the_limit_are_stored(db: Session, tlp: str) -> None:
    doc, created = services.ingest(db, item(tlp=tlp), max_tlp=LIMIT)
    assert (created, doc.tlp) == (True, tlp)


def test_a_marking_up_to_the_limit_still_raises_the_label(db: Session) -> None:
    doc, _ = services.ingest(db, item('TLP:AMBER+STRICT\nSeen at 192.0.2.8.', tlp='GREEN'), max_tlp=LIMIT)
    assert doc.tlp == 'AMBER+STRICT'


@pytest.mark.parametrize('max_tlp', ['RED', None])
def test_red_is_stored_when_allowed_or_unlimited(db: Session, max_tlp: str | None) -> None:
    """``RED`` allows everything; ``None`` (connectors, demo: public or synthetic data) means no limit."""
    doc, _ = services.ingest(db, item('TLP:RED\nSeen at 192.0.2.8.'), max_tlp=max_tlp)
    assert doc.tlp == 'RED'


@pytest.mark.parametrize(
    ('max_tlp', 'levels'),
    [
        ('RED', ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED']),
        ('AMBER+STRICT', ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT']),
        ('GREEN', ['CLEAR', 'GREEN']),
        ('CLEAR', ['CLEAR']),
    ],
)
def test_permitted_levels(max_tlp: str, levels: list[str]) -> None:
    assert services.permitted_tlp_levels(max_tlp) == levels


def test_count_documents_above(db: Session) -> None:
    for tlp in ('GREEN', 'AMBER', 'AMBER+STRICT', 'RED'):
        services.ingest(db, item(f'Seen {tlp}', tlp=tlp))
    assert services.count_documents_above(db, 'RED') == 0
    assert services.count_documents_above(db, 'AMBER+STRICT') == 1
    assert services.count_documents_above(db, 'GREEN') == 3
    assert services.count_documents_above(db, 'CLEAR') == 4
