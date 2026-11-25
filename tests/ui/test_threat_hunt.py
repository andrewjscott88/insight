"""A focus must be chosen and reviewed before a hunt guide can be downloaded."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.hunt_guide import GuideSection, HuntGuide
from insight.models import AuditEvent, HuntPackage
from insight.ui.threat_hunt import KINDS

from .test_landscape import add_report
from .test_workspace import record_navigation

pytestmark = pytest.mark.ui


async def choose(user: User, marker: str, value: str | None) -> None:
    await user.should_see(marker=marker)
    select = user.find(marker=marker).elements.pop()
    assert isinstance(select, ui.select)
    select.set_value(value)


async def test_industry_focus_browses_builds_downloads_and_saves_a_sector_hunt(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a sector selection must build and save its guide, not an unrelated actor or blank plan."""
    add_report(ui_env, 'Hospital security advisory', 'Hospitals should review remote access logs. T1078')
    add_report(ui_env, 'Unrelated bulletin', 'Routine office updates.')
    await user.should_see(marker='hunt-guide-kind')
    kind = user.find(marker='hunt-guide-kind').elements.pop()
    assert isinstance(kind, ui.select)
    assert isinstance(kind.options, dict)
    assert kind.options['industry'] == 'Sector / Industry'
    kind.set_value('industry')
    await user.should_see(marker='hunt-guide-subject')
    subject = user.find(marker='hunt-guide-subject').elements.pop()
    assert isinstance(subject, ui.select)
    assert isinstance(subject.options, dict)
    assert len(subject.options) == 15
    assert subject.options['healthcare'] == 'Healthcare and pharmaceuticals'
    assert subject.label == 'Sector / Industry'
    await user.should_see(marker='hunt-guide-query')
    user.find(marker='hunt-guide-query').type('hospitals')
    await user.should_see(marker='hunt-guide-search')
    user.find(marker='hunt-guide-search').click()
    assert subject.options == {'healthcare': 'Healthcare and pharmaceuticals'}
    await choose(user, 'hunt-guide-subject', 'healthcare')
    await user.should_see(marker='hunt-guide-build')
    user.find(marker='hunt-guide-build').click()
    await user.should_see('Your guide is ready.')
    await user.should_see('Threat hunt guide: Healthcare and pharmaceuticals')
    with user.scope(marker='hunt-guide-preview'):
        await user.should_see('Threat hunt guide: Healthcare and pharmaceuticals')
        await user.should_see('Groups known to target this sector')
        await user.should_see('Reports mentioning this sector')
        await user.should_see('Hospital security advisory')
        await user.should_not_see('Unrelated bulletin')
    downloads = record_navigation(user, monkeypatch)
    await user.should_see(marker='hunt-guide-markdown')
    user.find(marker='hunt-guide-markdown').click()
    await user.should_see(marker='hunt-guide-pdf')
    user.find(marker='hunt-guide-pdf').click()
    assert downloads == [
        ('/api/hunt-guides/industry/healthcare?format=md', True),
        ('/api/hunt-guides/industry/healthcare?format=pdf', True),
    ]
    await user.should_see(marker='hunt-guide-save-package')
    user.find(marker='hunt-guide-save-package').click()
    await user.should_see('Saved as a draft hunt package.')
    with ui_env.app.state.session_factory() as db:
        package = db.scalars(select(HuntPackage)).one()
        assert package.status == 'draft'
        assert package.title == 'Threat hunt guide: Healthcare and pharmaceuticals'
        assert package.group_ref is None
        assert package.tlp == 'GREEN'
        assert 'Groups known to target this sector' in package.hypothesis
        assert 'Start the hunt' in package.hypothesis
        assert any(
            item.kind == 'document'
            for item in services.get_hunt_package(db, package.id, max_tlp='AMBER+STRICT').items
        )


async def test_selected_guide_saves_a_draft_and_reopens_it_without_a_duplicate(
    user: User, ui_env: SimpleNamespace
) -> None:
    """Regression: saving the selected guide must carry its plan into a package, not open a blank form."""
    await user.should_see(marker='hunt-guide-save-package')
    save = user.find(marker='hunt-guide-save-package').elements.pop()
    assert isinstance(save, ui.button)
    assert not save.enabled
    await choose(user, 'hunt-guide-subject', 'ransomware')
    await user.should_see(marker='hunt-guide-build')
    user.find(marker='hunt-guide-build').click()
    await user.should_see('Your guide is ready.')
    assert save.enabled
    user.find(marker='hunt-guide-save-package').click()
    await user.should_see('Saved as a draft hunt package.')
    await user.should_see('Open saved package')
    with ui_env.app.state.session_factory() as db:
        package = db.scalars(select(HuntPackage)).one()
        package_id = package.id
        assert package.status == 'draft'
        assert 'Ransomware' in package.title
        assert 'Start the hunt' in package.hypothesis
        assert any(
            item.kind == 'technique'
            for item in services.get_hunt_package(db, package_id, max_tlp='AMBER+STRICT').items
        )
    await user.should_see('Done')
    user.find('Done').click()
    user.find(marker='hunt-guide-save-package').click()
    await user.should_see('Done')
    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(HuntPackage.id)).all() == [package_id]
    user.find('Done').click()
    await choose(user, 'hunt-guide-subject', 'phishing')
    assert not save.enabled
    assert save.text == 'Save as hunt package'


async def test_build_preview_download_and_invalidate_when_the_focus_changes(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a new selection must never download the previous focus's guide."""
    await user.should_see('Choose a focus, then build your guide to see it here.')
    await user.should_see(marker='hunt-guide-build')
    await user.should_see(marker='hunt-guide-markdown')
    await user.should_see(marker='hunt-guide-pdf')
    build = user.find(marker='hunt-guide-build').elements.pop()
    markdown = user.find(marker='hunt-guide-markdown').elements.pop()
    pdf = user.find(marker='hunt-guide-pdf').elements.pop()
    assert isinstance(build, ui.button)
    assert isinstance(markdown, ui.button)
    assert isinstance(pdf, ui.button)
    assert not build.enabled
    assert not markdown.enabled
    assert not pdf.enabled

    await choose(user, 'hunt-guide-subject', 'ransomware')
    assert build.enabled
    assert not markdown.enabled
    user.find(marker='hunt-guide-build').click()
    await user.should_see('Your guide is ready.')
    await user.should_see('Threat hunt guide: Ransomware')
    with user.scope(marker='hunt-guide-preview'):
        await user.should_see('Ransomware')
        await user.should_see('Reports used')
    assert markdown.enabled
    assert pdf.enabled
    with ui_env.app.state.session_factory() as db:
        audit = db.scalars(select(AuditEvent).where(AuditEvent.action == 'hunt.guide')).one()
        assert (audit.object_id, audit.detail, audit.actor) == (
            'ransomware',
            'theme; preview; TLP:CLEAR',
            'operator',
        )
    downloads = record_navigation(user, monkeypatch)
    user.find(marker='hunt-guide-markdown').click()
    user.find(marker='hunt-guide-pdf').click()
    assert downloads == [
        ('/api/hunt-guides/theme/ransomware?format=md', True),
        ('/api/hunt-guides/theme/ransomware?format=pdf', True),
    ]

    await choose(user, 'hunt-guide-subject', 'phishing')
    await user.should_see('Choose a focus, then build your guide to see it here.')
    with user.scope(marker='hunt-guide-preview'):
        await user.should_not_see('Ransomware')
    assert not markdown.enabled
    assert not pdf.enabled
    await choose(user, 'hunt-guide-subject', None)
    assert not build.enabled


@pytest.mark.parametrize('kind', tuple(KINDS))
async def test_each_starting_point_searches_the_service_and_builds_only_on_request(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """Search reaches saved items beyond the initial list, and every read carries the instance limit."""
    calls: list[tuple[str, str, str | None]] = []
    builds: list[tuple[str, str, str | None]] = []
    reference = 'choice/with space'

    def choices(
        db: Session, *, max_tlp: str | None = None, kind: str | None = None, q: str = ''
    ) -> dict[str, list[tuple[str, str]]]:
        assert kind is not None
        calls.append((kind, q, max_tlp))
        return {kind: [(reference, 'Matching saved intelligence')] if q == 'needle' else []}

    def guide(db: Session, kind: str, ref: str, *, max_tlp: str | None = None) -> HuntGuide:
        builds.append((kind, ref, max_tlp))
        return HuntGuide(
            kind,
            ref,
            'A focused hunt guide',
            'A plan from saved intelligence.',
            'CLEAR',
            '2026-11-23T12:00:00+00:00',
            (GuideSection('Checks to try', ('Review <script> as text, not code.',)),),
        )

    monkeypatch.setattr(services, 'hunt_guide_choices', choices)
    monkeypatch.setattr(services, 'hunt_guide', guide)
    await choose(user, 'hunt-guide-kind', kind)
    await user.should_see(marker='hunt-guide-query')
    await user.should_see(marker='hunt-guide-search')
    user.find(marker='hunt-guide-query').type('needle')
    user.find(marker='hunt-guide-search').click()
    await user.should_see('Choose from these matches.')
    await user.should_see(marker='hunt-guide-subject')
    subject = user.find(marker='hunt-guide-subject').elements.pop()
    assert isinstance(subject, ui.select)
    assert subject.options == {reference: 'Matching saved intelligence'}
    assert calls[-1] == (kind, 'needle', ui_env.app.state.settings.max_tlp)
    assert builds == []
    await choose(user, 'hunt-guide-subject', reference)
    assert builds == []
    await user.should_see(marker='hunt-guide-build')
    user.find(marker='hunt-guide-build').click()
    await user.should_see('A focused hunt guide')
    await user.should_see('Review <script> as text, not code.')
    assert builds == [(kind, reference, ui_env.app.state.settings.max_tlp)]
    downloads = record_navigation(user, monkeypatch)
    await user.should_see(marker='hunt-guide-markdown')
    user.find(marker='hunt-guide-markdown').click()
    assert downloads == [(f'/api/hunt-guides/{kind}/choice%2Fwith%20space?format=md', True)]


async def test_removed_or_hidden_focus_clears_preview_and_cannot_download(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a focus removed between choosing and building must not leave an old guide usable."""
    await choose(user, 'hunt-guide-subject', 'ransomware')
    await user.should_see(marker='hunt-guide-build')
    user.find(marker='hunt-guide-build').click()
    await user.should_see('Your guide is ready.')

    def hidden(db: Session, kind: str, ref: str, *, max_tlp: str | None = None) -> HuntGuide:
        raise LookupError('A hidden focus')

    monkeypatch.setattr(services, 'hunt_guide', hidden)
    user.find(marker='hunt-guide-build').click()
    await user.should_see('This focus is no longer available. Choose another one.')
    await user.should_see(marker='hunt-guide-markdown')
    button = user.find(marker='hunt-guide-markdown').elements.pop()
    assert isinstance(button, ui.button)
    assert not button.enabled
    with user.scope(marker='hunt-guide-preview'):
        await user.should_not_see('Ransomware')


async def test_a_revoked_session_cannot_build_or_download_a_guide(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    await choose(user, 'hunt-guide-subject', 'ransomware')
    await user.should_see(marker='hunt-guide-build')
    user.find(marker='hunt-guide-build').click()
    await user.should_see('Your guide is ready.')
    downloads = record_navigation(user, monkeypatch)
    with ui_env.app.state.session_factory.begin() as db:
        services.end_all_operator_sessions(db)
    await user.should_see(marker='hunt-guide-pdf')
    user.find(marker='hunt-guide-pdf').click()
    user.find(marker='hunt-guide-build').click()
    assert downloads
    assert {target for target, _ in downloads} == {'/login'}
