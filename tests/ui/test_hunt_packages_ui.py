"""TIP 4.3 in Threat Hunt: write, fill, publish and retire a hunt package; add a report from the reader."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, HuntPackage, HuntPackageItem
from insight.schemas import DocumentInput
from insight.services import ingest

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str) -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='Vendor', tlp='GREEN'))


async def test_a_package_is_written_filled_published_and_retired(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Beacon note', 'Beacon to 203.0.113.80 after encoded PowerShell.')
    await user.open('/')
    user.find(marker='hunt-new').click()
    await user.should_see('New hunt package')
    user.find(kind=ui.input, marker='hunt-title').type('Encoded PowerShell beacons')
    user.find(kind=ui.textarea, marker='hunt-hypothesis').type('A crew runs encoded PowerShell and beacons.')
    user.find(marker='hunt-save').click()
    await user.should_see('Package saved as a draft. Add techniques, indicators and rules, then publish it.')
    await user.should_see('Only you can see a draft. Publish it when it is ready for your hunt tools.')

    user.find(marker='hunt-publish').click()
    await user.should_see('Add at least one ATT&CK technique, indicator or rule before publishing.')
    user.find(kind=ui.input, content='Technique ID, such as T1059.001').type('T1059.001')
    user.find(marker='hunt-add-technique').click()
    await user.should_see('Technique · Command and Scripting Interpreter: PowerShell')
    user.find(kind=ui.input, content='Indicator, such as an address or a domain').type('203.0.113.80')
    user.find(marker='hunt-add-indicator').click()
    await user.should_see('Indicator · 203.0.113.80')
    user.find(marker='hunt-publish').click()
    await user.should_see('Published. Hunt tools get it from the feed.')
    await user.should_see(marker='hunt-retire')
    user.find(marker='hunt-retire').click()
    await user.should_see('Retired. Hunt tools are told it no longer applies.')

    with ui_env.app.state.session_factory() as db:
        row = db.scalars(select(HuntPackage)).one()
        assert (row.title, row.status, row.tlp) == ('Encoded PowerShell beacons', 'retired', 'AMBER')
        kinds = sorted(db.scalars(select(HuntPackageItem.kind)))
        actions = list(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like('hunt_package.%'))))
    assert kinds == ['indicator', 'technique']
    assert actions == [
        'hunt_package.create',
        'hunt_package.item.add',
        'hunt_package.item.add',
        'hunt_package.publish',
        'hunt_package.retire',
    ]


async def test_the_reader_adds_a_report_to_a_new_package(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Vendor advisory', 'Encoded PowerShell from 203.0.113.81.')
    await user.open('/')
    with user.scope(marker='document-list'):
        user.find(kind=ui.button, content='Vendor advisory').click()
    await user.should_see('How believable is this report?')
    user.find(marker='report-add-to-hunt').click()
    await user.should_see('Add to hunt package')
    user.find(kind=ui.input, marker='hunt-new-title').type('From the reader')
    user.find(kind=ui.textarea, content='What should the hunt look for, and why?').type('Look for it.')
    user.find(marker='hunt-add').click()
    await user.should_see('Added this report to the hunt package.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(HuntPackage.title)).one() == 'From the reader'
        assert db.scalars(select(HuntPackageItem.kind)).one() == 'document'
