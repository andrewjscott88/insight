"""The industry threats tab, threat guides, hunts, rules and report links in the workspace (TIP 2.10)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, DetectionRule, Hunt, HuntCheck, IndustryClaim, ThreatActor
from insight.schemas import DocumentInput
from insight.services import ingest

from .test_verdicts import open_report

pytestmark = pytest.mark.ui
SIGMA = (
    'title: Encoded PowerShell\nlogsource:\n  product: windows\n'
    'detection:\n  sel:\n    x: 1\n  condition: sel\n'
)


def add_report(env: SimpleNamespace, title: str, body: str) -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp='GREEN'))


def actions(env: SimpleNamespace, prefix: str) -> list[str]:
    with env.app.state.session_factory() as db:
        return sorted(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like(f'{prefix}%'))))


async def open_guide(user: User, ref: str, name: str) -> None:
    user.find(kind=ui.expansion, content='Find any group by name').elements.pop().open()
    user.find(kind=ui.input, content='Group name or ID').type(ref)
    user.find(kind=ui.button, content=f'{ref} · {name}').click()
    await user.should_see('Hunt plan')


async def test_the_tab_lists_the_top_groups_with_their_evidence(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Ministry phishing', 'Cozy Bear sent lures to a ministry.')
    await user.open('/')
    await user.should_see('Industry threats')
    await user.should_see('These are the top 10.')
    await user.should_see('APT29 (G0016) · named in 1 of your reports')
    user.find(kind=ui.select, content='Industry').elements.pop().set_value('healthcare')
    await user.should_see('Hospitals, health services')


async def test_a_guide_opens_with_its_hunt_plan_and_records_a_hunt(
    user: User, ui_env: SimpleNamespace
) -> None:
    await user.open('/')
    await open_guide(user, 'G0016', 'APT29')
    await user.should_see('Threat guide: APT29')
    await user.should_see('Who it targets')
    await user.should_see('Download the guide (Markdown)')
    await user.should_see('Download the sweep list with reports that only name it (CSV)')
    await user.should_see('Reports that only name the group are left out')
    dialogs = user.find(kind=ui.dialog).elements
    guides = [d for d in dialogs if d.props.get('aria-label') == 'Threat guide: APT29']
    assert len(guides) == 1  # review L1: the label is a prop value, not formatted into a props string
    await user.should_see('Indicators to search for (0)')
    user.find(kind=ui.button, content='Start a hunt').click()
    await user.should_see('Name of the hunt')
    user.find(marker='start-hunt').click()
    await user.should_see('Hunt started. Record each check as you go.')
    with ui_env.app.state.session_factory() as db:
        hunt = db.scalars(select(Hunt)).one()
        assert (hunt.group_ref, hunt.title, hunt.tlp) == ('G0016', 'APT29 hunt', 'AMBER')
    await user.should_see('Hunt records (1)')
    user.find(kind=ui.expansion, content='APT29 hunt').elements.pop().open()
    user.find(marker='save-check-T1059.001').click()
    await user.should_see('Saved the check of T1059.001.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(HuntCheck.technique_id)).one() == 'T1059.001'
    assert actions(ui_env, 'hunt.') == ['hunt.check', 'hunt.start']


async def test_an_analyst_adds_an_industry_with_a_citation(user: User, ui_env: SimpleNamespace) -> None:
    await user.open('/')
    await open_guide(user, 'G0016', 'APT29')
    user.find(kind=ui.button, content='Add or remove an industry').click()
    user.find(kind=ui.select, marker='claim-industry').elements.pop().set_value('energy')
    user.find(kind=ui.button, content='Save').click()
    await user.should_see('Give the link or the report that says this group targets the industry.')
    user.find(kind=ui.input, content='Web page that says so').type('https://example.org/energy')
    user.find(kind=ui.textarea, content='Why').type('Vendor report on power companies')
    user.find(kind=ui.button, content='Save').click()
    await user.should_see('Saved. The industry lists use it now.')
    with ui_env.app.state.session_factory() as db:
        claim = db.scalars(select(IndustryClaim)).one()
        assert (claim.industry, claim.decision, claim.actor) == ('energy', 'added', 'operator')


async def test_an_analyst_tracks_an_actor_and_links_a_report(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Case 42', 'Copper Fox ran T1486.')
    await user.open('/')
    user.find(kind=ui.button, content='Track your own actor').click()
    user.find(kind=ui.input, content='Name').type('Copper Fox')
    user.find(kind=ui.button, content='Save').click()
    await user.should_see('Threat guide: Copper Fox')
    with ui_env.app.state.session_factory() as db:
        actor = db.scalars(select(ThreatActor)).one()
    await open_report(user, 'Case 42')
    await user.should_see('Threat groups (0)')
    user.find(kind=ui.input, content='Link to a group').type('Copper')
    user.find(kind=ui.button, content='Copper Fox').click()
    await user.should_see('Report linked.')
    await user.should_see('Threat groups (1)')
    assert actions(ui_env, 'actor.') == ['actor.create', 'actor.link']
    assert actor.name == 'Copper Fox'


async def test_a_rule_is_saved_and_shown_as_text(user: User, ui_env: SimpleNamespace) -> None:
    await user.open('/')
    await open_guide(user, 'G0016', 'APT29')
    user.find(kind=ui.button, content='Add a rule').click()
    user.find(kind=ui.input, content='Name').type('Encoded PowerShell')
    user.find(kind=ui.textarea, content='Rule text').type(SIGMA)
    user.find(kind=ui.input, content='Technique ID').type('T1059.001')
    user.find(kind=ui.button, content='Save').click()
    await user.should_see('Rule saved and linked.')
    await user.should_see('Detection rules (1)')
    assert actions(ui_env, 'rule.') == ['rule.add', 'rule.link', 'rule.link']


async def test_report_reader_attaches_and_displays_a_rule(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Test bulletin', 'Analyst summary.')
    add_report(ui_env, 'Second bulletin', 'Additional findings.')
    await user.open('/')
    await open_report(user, 'Test bulletin')
    user.find(kind=ui.expansion, content='Detection rules (0)').elements.pop().open()
    user.find(kind=ui.button, content='Add a rule to this report').click()
    user.find(kind=ui.input, content='Name').type('Audit fixture')
    user.find(kind=ui.textarea, content='Rule text').type(SIGMA)
    user.find(kind=ui.input, content='Malware family').type('Example Family')
    user.find(marker='save-detection-rule').click()
    await user.should_see('Detection rules (1)')
    user.find(kind=ui.expansion, content='Detection rules (1)').elements.pop().open()
    user.find(kind=ui.expansion, content='Audit fixture').elements.pop().open()
    await user.should_see('Download rule and manifest')
    await user.should_see('malware example family')
    assert actions(ui_env, 'rule.') == ['rule.add', 'rule.link', 'rule.link']
    with ui_env.app.state.session_factory() as db:
        rule_id = db.scalars(select(DetectionRule.id)).one()
    await open_report(user, 'Second bulletin')
    user.find(kind=ui.expansion, content='Detection rules (0)').elements.pop().open()
    user.find(marker='choose-saved-rule').click()
    user.find(marker='saved-rule').elements.pop().set_value(rule_id)
    user.find(marker='attach-saved-rule').click()
    await user.should_see('Rule linked to this report.')
    await user.should_see('Detection rules (1)')
