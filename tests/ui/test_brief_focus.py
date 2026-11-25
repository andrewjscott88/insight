"""A searched focus replaces the general brief and follows the selected reporting period."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from .test_landscape import add_report

pytestmark = pytest.mark.ui


async def test_search_focus_period_and_return_to_all_intelligence(
    user: User, ui_env: SimpleNamespace
) -> None:
    """Regression: a focused brief must not keep showing unrelated general intelligence."""
    add_report(ui_env, 'Current ransomware report', 'A ransomware incident described in a public report.')
    add_report(ui_env, 'Earlier ransomware report', 'A report on ransomware.', days_ago=20)
    add_report(ui_env, 'Unrelated phishing report', 'A phishing incident described in a public report.')
    await user.open('/')
    await user.should_not_see('What matters and what to check next')
    await user.should_see(marker='brief-focus-kind')
    kind = user.find(marker='brief-focus-kind').elements.pop()
    assert isinstance(kind, ui.select)
    assert kind.value == 'all'
    await user.should_see(marker='brief-focus-query')
    query = user.find(marker='brief-focus-query').elements.pop()
    assert isinstance(query, ui.input)
    query.set_value('ransomware')
    await user.should_see(marker='brief-focus-search')
    user.find(marker='brief-focus-search').click()
    await user.should_see(marker='brief-focus-match')
    match = user.find(marker='brief-focus-match').elements.pop()
    assert isinstance(match, ui.select)
    assert isinstance(match.options, dict)
    match.set_value(next(key for key, label in match.options.items() if label == 'Threat type · Ransomware'))
    await user.should_see(marker='brief-focus-show')
    user.find(marker='brief-focus-show').click()
    await user.should_see(marker='focused-brief')
    with user.scope(marker='focused-brief'):
        await user.should_see('Ransomware')
        await user.should_see('Current ransomware report')
        await user.should_see('Earlier ransomware report')
        await user.should_not_see('Unrelated phishing report')
    with user.scope(marker='intel-brief'):
        period = user.find(kind=ui.toggle).elements.pop()
        assert isinstance(period, ui.toggle)
        assert period.value == 30
        period.set_value(7)
    await user.should_see(marker='focused-brief-period', content='Last 7 days')
    with user.scope(marker='focused-brief'):
        await user.should_not_see('Earlier ransomware report')
        await user.should_not_see('Unrelated phishing report')
    await user.should_see(marker='brief-focus-reset')
    user.find(marker='brief-focus-reset').click()
    await user.should_see(marker='brief-summary')
    await user.should_not_see(marker='focused-brief')


async def test_actor_brief_has_background_without_recent_reports(user: User) -> None:
    """Regression: selecting an actor with no recent reports must still show useful actor intelligence."""
    await user.should_see(marker='brief-focus-query')
    query = user.find(marker='brief-focus-query').elements.pop()
    assert isinstance(query, ui.input)
    query.set_value('Volt Typhoon')
    await user.should_see(marker='brief-focus-search')
    user.find(marker='brief-focus-search').click()
    await user.should_see(marker='brief-focus-match')
    match = user.find(marker='brief-focus-match').elements.pop()
    assert isinstance(match, ui.select)
    assert isinstance(match.options, dict)
    match.set_value(
        next(key for key, label in match.options.items() if label.startswith('Threat actor · Volt'))
    )
    await user.should_see(marker='brief-focus-show')
    user.find(marker='brief-focus-show').click()
    await user.should_see(marker='focused-brief-profile')
    with user.scope(marker='focused-brief'):
        await user.should_see('critical infrastructure')
        await user.should_see('How they operate')
        await user.should_see('Use real accounts')
        await user.should_see('What to watch for')
        await user.should_see('Mimikatz')
        await user.should_see('No explicitly linked')
        await user.should_see(marker='focused-brief-sources')


async def test_sector_can_be_browsed_without_a_query_and_defaults_to_thirty_days(user: User) -> None:
    """Regression: sector choices were absent, and a new brief opened with a seven-day window."""
    await user.should_see(marker='brief-focus-kind')
    kind = user.find(marker='brief-focus-kind').elements.pop()
    assert isinstance(kind, ui.select)
    assert isinstance(kind.options, dict)
    assert kind.options['industry'] == 'Sector / Industry'
    kind.set_value('industry')
    await user.should_see(marker='brief-focus-match')
    match = user.find(marker='brief-focus-match').elements.pop()
    assert isinstance(match, ui.select)
    assert isinstance(match.options, dict)
    match.set_value(
        next(key for key, label in match.options.items() if label == 'Healthcare and pharmaceuticals')
    )
    await user.should_see(marker='brief-focus-show')
    user.find(marker='brief-focus-show').click()
    await user.should_see(marker='focused-brief-period', content='Report window: last 30 days')
    with user.scope(marker='focused-brief'):
        await user.should_see('Healthcare and pharmaceuticals')
        await user.should_see('Hospitals, health services, medical research and drug makers.')
        await user.should_see('Groups known to target this sector')
        await user.should_see('Reports mentioning this sector')
        await user.should_see('Reports linked to sector-targeting groups')
