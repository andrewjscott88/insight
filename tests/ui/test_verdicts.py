"""Verdicts and warning flags in the workspace (review Design 1): the reader and the entity explorer."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.flags import FLAGS
from insight.models import AuditEvent, EntityAssessment
from insight.schemas import TLP_LEVELS, VERDICTS, DocumentInput
from insight.services import ingest
from insight.ui.glossary import GLOSSARY
from insight.ui.verdicts import FLAG_LABELS, VERDICT_LABELS, suggested_tlp

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str, tlp: str = 'AMBER') -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp=tlp))


def assessments(env: SimpleNamespace) -> list[tuple[str, str, str, str]]:
    with env.app.state.session_factory() as db:
        rows = db.scalars(select(EntityAssessment))
        return [(a.verdict, a.reason, a.tlp, a.actor) for a in rows]


async def open_report(user: User, title: str) -> None:
    await user.open('/')
    with user.scope(marker='document-list'):
        user.find(kind=ui.button, content=title).click()
    with user.scope(marker='document-detail'):
        await user.should_see(kind=ui.label, content=title)


async def test_the_reader_records_a_verdict(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Verdict report', 'The loader calls update-check.net every hour.')
    await open_report(user, 'Verdict report')
    await user.should_see('Verdict: Unknown')
    user.find(kind=ui.button, content='Set verdict').click()
    await user.should_see('Verdict on this indicator')
    user.find(kind=ui.radio).elements.pop().set_value('malicious')
    user.find(kind=ui.textarea, content='Reason').type('Command server in this report.')
    user.find('Save verdict').click()
    await user.should_see('Verdict saved.')
    await user.should_see('Verdict: Malicious · TLP:AMBER · set by operator')
    await user.should_see('Command server in this report.')
    assert assessments(ui_env) == [('malicious', 'Command server in this report.', 'AMBER', 'operator')]
    with ui_env.app.state.session_factory() as db:
        assert 'entity.assess' in db.scalars(select(AuditEvent.action)).all()


async def test_unknown_clears_the_verdict(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Verdict report', 'The loader calls update-check.net every hour.')
    await open_report(user, 'Verdict report')
    user.find(kind=ui.button, content='Set verdict').click()
    user.find('Save verdict').click()
    await user.should_see('Verdict: Malicious')
    user.find(kind=ui.button, content='Change verdict').click()
    user.find(kind=ui.radio).elements.pop().set_value('unknown')
    user.find('Save verdict').click()
    await user.should_see('Verdict cleared.')
    await user.should_see('Verdict: Unknown')
    assert assessments(ui_env) == []


async def test_an_end_date_in_the_past_is_refused(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Verdict report', 'The loader calls update-check.net every hour.')
    await open_report(user, 'Verdict report')
    user.find(kind=ui.button, content='Set verdict').click()
    user.find(kind=ui.input, content='Valid until').type('2020-01-01')
    user.find('Save verdict').click()
    await user.should_see('Pick today or a later date, or leave the end date empty.')
    assert assessments(ui_env) == []


async def test_warnings_show_and_keep_a_value_off_the_blocklist(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Example report', 'Beacon to 192.0.2.10 seen in the lab.')
    await open_report(user, 'Example report')
    await user.should_see('Example address')
    user.find(kind=ui.button, content='Set verdict').click()
    user.find('Save verdict').click()
    await user.should_see('Kept off the blocklist because of its warning.')


async def test_the_reason_label_defaults_to_the_reports_when_stricter(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Strict report', 'The loader calls update-check.net every hour.', tlp='AMBER+STRICT')
    await open_report(user, 'Strict report')
    user.find(kind=ui.button, content='Set verdict').click()
    user.find('Save verdict').click()
    await user.should_see('Verdict saved.')
    assert [tlp for _, _, tlp, _ in assessments(ui_env)] == ['AMBER+STRICT']


async def test_the_entity_explorer_shows_and_sets_verdicts(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Explorer report', 'The loader calls update-check.net every hour.')
    await user.open('/')
    user.find(kind=ui.expansion, content='update-check.net').elements.pop().open()
    await user.should_see('In reports added from')
    user.find(kind=ui.button, content='Set verdict').click()  # no report is open, so only this one
    user.find(kind=ui.radio).elements.pop().set_value('benign')
    user.find('Save verdict').click()
    await user.should_see('Verdict: Benign')
    assert [verdict for verdict, *_ in assessments(ui_env)] == ['benign']


@pytest.mark.parametrize(
    ('report', 'permitted', 'expected'),
    [
        (None, list(TLP_LEVELS), 'AMBER'),
        ('GREEN', list(TLP_LEVELS), 'AMBER'),
        ('RED', list(TLP_LEVELS), 'RED'),
        ('RED', ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT'], 'AMBER+STRICT'),
        ('CLEAR', ['CLEAR', 'GREEN'], 'GREEN'),
    ],
)
def test_suggested_label_is_safe_and_storable(
    report: str | None, permitted: list[str], expected: str
) -> None:
    assert suggested_tlp(report, permitted) == expected


def test_every_verdict_and_flag_has_a_plain_name_in_the_glossary() -> None:
    assert set(VERDICT_LABELS) == set(VERDICTS)
    assert set(FLAG_LABELS) == set(FLAGS)
    terms = {term for term, _ in GLOSSARY}
    assert set(FLAG_LABELS.values()) <= terms
    assert {'Blocklist', 'Warning'} <= terms
