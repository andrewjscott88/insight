"""TIP 4.4 in the workspace: write a product's bottom line, a key judgement with its evidence and a gap, ask
the gap as a request for information, and publish version 1."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, CaseJudgement, CaseVersion, Requirement
from insight.schemas import CaseInput, CaseItemInput, DocumentInput
from insight.services import add_case_item, create_case, ingest

pytestmark = pytest.mark.ui


async def test_a_product_is_written_and_published(user: User, ui_env: SimpleNamespace) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        doc, _ = ingest(
            db, DocumentInput(title='Vendor advisory', body='CVE-2024-3400 exploited.', source_name='V')
        )
        case = create_case(db, CaseInput(title='Edge appliance exploitation', tlp='GREEN'))
        item = add_case_item(db, case.id, CaseItemInput(kind='document', target_id=doc.id))
    await user.open('/')
    user.find(kind=ui.button, content='Edge appliance exploitation').click()
    await user.should_see('Not published yet. Publishing keeps this exact text as version 1.')
    user.find(marker='product-publish').click()
    await user.should_see('To publish, add a bottom line up front and at least one key judgement.')

    user.find(kind=ui.textarea, marker='product-bluf').type('Expect more edge appliance exploitation.')
    user.find(marker='product-bluf-save').click()
    await user.should_see('Saved.')
    await user.should_see(marker='product-judgement')
    user.find(kind=ui.textarea, marker='product-judgement').type('The crew will keep exploiting gateways.')
    user.find(kind=ui.select, marker='product-judgement-evidence').elements.pop().set_value([item.id])
    user.find(marker='product-judgement-add').click()
    await user.should_see('Key judgement added.')
    await user.should_see('1. Likely (55-80%), Moderate confidence')
    await user.should_see('Evidence: Report · Vendor advisory')

    await user.should_see(marker='product-gap-new')
    user.find(kind=ui.input, marker='product-gap-new').type('Which of our gateways are exposed?')
    user.find(marker='product-gap-add').click()
    await user.should_see('Gap added.')
    await user.should_see(marker='product-gap-ask')
    user.find(marker='product-gap-ask').click()
    await user.should_see('Asked. The request is in Requirements.')

    await user.should_see(marker='product-publish')
    user.find(marker='product-publish').click()
    await user.should_see('Published. That version is kept as it is now.')
    await user.should_see(marker='product-version')
    await user.should_see('PDF')
    pdfs = sorted(link.props['href'] for link in user.find(kind=ui.link, content='PDF').elements)
    assert [href.split('export?')[1] for href in pdfs] == ['format=pdf', 'format=pdf&version=1']

    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(CaseJudgement.statement)).one() == 'The crew will keep exploiting gateways.'
        assert db.scalars(select(CaseVersion.version)).one() == 1
        assert db.scalars(select(Requirement.kind)).one() == 'rfi'
        actions = list(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like('case.%'))))
    assert {'case.update', 'case.judgement.add', 'case.gap.add', 'case.gap.rfi', 'case.publish'} <= set(
        actions
    )
