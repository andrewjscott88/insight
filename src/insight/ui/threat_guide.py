"""A group's threat guide in the workspace (TIP 2.10, ADR 0024): who it targets, how it works, your reports.

The same guide as ``GET /api/actors/{id}/guide``, built by :mod:`insight.threat_guide`. The hunt plan, rules
and hunt records are in ``hunts.py`` and ``rules.py``; the analyst's own changes in ``actors.py``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from nicegui import ui

from .. import services
from ..threat_guide import ThreatGuide, compose, industry_claims, industry_name
from ..threat_library import library
from .actors import open_industry_dialog
from .hunts import render_hunt_plan
from .messages import tell
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .workspace import Workspace


def load_guide(ws: Workspace, ref: str) -> ThreatGuide | None:
    with ws.read() as db:
        try:
            data = services.guide_data(db, ref, now=datetime.now(UTC))
        except LookupError:
            return None
    return compose(data, library())


def open_guide_dialog(ws: Workspace, ref: str, on_changed: Callable[[], Any]) -> None:
    guide = load_guide(ws, ref)
    if guide is None:
        tell('This group no longer exists.', 'warning')
        return
    title = f'Threat guide: {guide.name}'
    with (
        ui.dialog().props('maximized') as dialog,
        ui.card().classes('panel dialog-card w-full p-4 sm:p-6 gap-3'),
    ):
        with ui.row().classes('w-full items-center justify-between'):
            heading(title, 2)
            ui.button('Close', on_click=dialog.close).props('flat no-caps')
        # A prop value, never formatted into a props string: a quote in an actor's name cannot escape it.
        dialog.props['aria-label'] = title

        @ui.refreshable
        def body() -> None:
            current = load_guide(ws, ref)
            if current is None:
                ui.label('This group no longer exists.').classes('muted')
                return
            _render(ws, current, changed)

        def changed() -> None:
            body.refresh()
            on_changed()

        body()
    dialog.open()


def _render(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    subject = guide.data.subject
    tlp_badge(guide.tlp)
    ui.label(
        f'Built from data up to TLP:{guide.tlp}. Share it no wider. '
        'Insight wrote it from its sources, not by AI.'
    ).classes('muted prose')
    if subject.kind == 'analyst':
        ui.label('An actor you track.').classes('muted text-sm')
    if subject.aliases:
        ui.label('Also called: ' + ', '.join(subject.aliases)).classes('text-sm break-value')
    if subject.description:
        ui.label(subject.description).classes('prose')
    group = subject.catalog
    if group is not None:
        new_tab_link(f'{group.id} on the ATT&CK site', group.url)
    base = f'/api/actors/{subject.ref}'
    with ui.row().classes('gap-x-6 gap-y-1'):
        new_tab_link('Download the guide (Markdown)', f'{base}/guide?format=md')
        new_tab_link('Download the guide (JSON)', f'{base}/guide')
        new_tab_link('Download a layer for ATT&CK Navigator', f'{base}/navigator')
        new_tab_link('Download the sweep list (CSV)', f'{base}/sweep?format=csv')
        new_tab_link(
            'Download the sweep list with reports that only name it (CSV)',
            f'{base}/sweep?format=csv&linked_only=false',
        )
    _targets(ws, guide, refresh)
    _techniques(guide)
    _reports(ws, guide)
    render_hunt_plan(ws, guide, refresh)
    ui.label(guide.library.notice).classes('muted text-sm')


def _targets(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    claims = industry_claims(guide)
    heading('Who it targets', 3, 'subsection-title mt-3')
    if not claims:
        ui.label('No source names an industry for this group.').classes('muted')
    for claim in claims:
        with ui.column().classes('panel w-full p-3 gap-1'):
            names = ', '.join(industry_name(k) for k in claim['industries'])
            ui.label(f'{names} · {claim["source"]}').classes('font-medium')
            ui.label(claim['evidence']).classes('evidence text-sm w-full')
            if claim['url']:
                new_tab_link('Read the source', claim['url'])
            for citation in claim.get('citations', []):
                new_tab_link(citation['name'], citation['url'])
    for industry, reason, _ in guide.data.removed:
        ui.label(f'You removed {industry_name(industry)}: {reason}').classes('muted text-sm')
    group = guide.data.subject.catalog
    if group is not None and group.regions:
        ui.label('Countries named as victims: ' + ', '.join(group.regions)).classes('text-sm prose')
    if group is not None and group.last_activity is not None:
        latest = group.last_activity
        ui.label(f'Latest public activity: {latest.name}, last seen {latest.last_seen}.').classes('text-sm')
    ui.button(
        'Add or remove an industry',
        on_click=lambda: open_industry_dialog(ws, guide.data.subject.ref, refresh),
    ).props('outline no-caps')


def _techniques(guide: ThreatGuide) -> None:
    heading(f'How it works: {len(guide.techniques)} techniques', 3, 'subsection-title mt-3')
    by_tactic: dict[str, list[str]] = {}
    for row in guide.techniques:
        source = 'ATT&CK' if row.in_attack else 'your reports'
        for tactic in row.tactics[:1]:
            by_tactic.setdefault(tactic, []).append(f'{row.id} {row.name} ({source})')
    for tactic, rows in by_tactic.items():
        with ui.expansion(f'{tactic} ({len(rows)})').classes('w-full'):
            for text in rows:
                ui.label(text).classes('text-sm break-value')
    lib, group = guide.library, guide.data.subject.catalog
    software = [lib.software[s] for s in (group.software if group else ()) if s in lib.software]
    if software:
        with ui.expansion(f'Tools and malware ({len(software)})').classes('w-full'):
            for item in software:
                new_tab_link(f'{item.name} ({item.type})', item.url)
    if guide.mitigations:
        with ui.expansion(f'Ways to defend ({len(guide.mitigations)})').classes('w-full'):
            for mid, name, techniques in guide.mitigations[:15]:
                ui.label(f'{mid} {name}: helps against {len(techniques)} of its techniques').classes(
                    'text-sm'
                )


def _reports(ws: Workspace, guide: ThreatGuide) -> None:
    data = guide.data
    heading(f'Your reports ({len(data.reports)})', 3, 'subsection-title mt-3')
    ui.label(
        'Reports you linked to this group, and reports that use one of its names. A name in a report is '
        'not proof the group did it.'
    ).classes('muted prose')
    for report in data.reports:
        how = 'linked by you' if report.via == 'linked' else 'names it'

        def open_report(document_id: str = report.document_id) -> None:
            ws.show_inbox()
            ws.open_document(document_id)

        ui.button(
            f'{report.title} · TLP:{report.tlp} · {report.created_at[:10]} · {how}', on_click=open_report
        ).props('flat no-caps align=left').classes('w-full break-value')
