"""TIP 4.2 in the workspace: an indicator's confidence and its sources, a report's credibility in the reader,
and grading sources in Settings."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, Document, SourceRating
from insight.schemas import DocumentInput
from insight.services import ingest

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str, source: str) -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name=source, tlp='GREEN'))


async def test_the_explorer_shows_confidence_and_its_sources(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Vendor note', 'Beacon to 203.0.113.95.', 'Vendor')
    await user.open('/')
    user.find(kind=ui.expansion, content='203.0.113.95').elements.pop().open()
    await user.should_see('Confidence 12 (low): 1 source you can see')
    user.find(kind=ui.expansion, marker='entity-confidence').elements.pop().open()
    await user.should_see('Vendor · reliability F · 1 report(s)')
    await user.should_see('Reports lose half their weight every 30 days.')


async def test_the_reader_saves_credibility(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Vendor note', 'Beacon to 203.0.113.96.', 'Vendor')
    await user.open('/')
    with user.scope(marker='document-list'):
        user.find(kind=ui.button, content='Vendor note').click()
    await user.should_see('How believable is this report?')
    user.find(kind=ui.select, marker='report-credibility').elements.pop().set_value(2)
    await user.should_see('Credibility saved. Confidence in its indicators follows.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(Document.credibility)).one() == 2
        assert 'document.credibility' in db.scalars(select(AuditEvent.action)).all()


async def test_settings_grades_a_source_and_shows_what_it_adds(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Vendor note', 'Beacon to 203.0.113.97.', 'Vendor')
    await user.open('/')
    await user.should_see('Source reliability')
    await user.should_see('1 report(s) · 1 indicator(s), 1 only here · none reviewed')
    with user.scope(marker='source-rating-Vendor'):
        user.find(kind=ui.select, content='Reliability').elements.pop().set_value('B')
    await user.should_see('Vendor: reliability B.')
    with ui_env.app.state.session_factory() as db:
        row = db.scalars(select(SourceRating)).one()
        assert (row.source_name, row.reliability, row.half_life_days) == ('Vendor', 'B', None)
