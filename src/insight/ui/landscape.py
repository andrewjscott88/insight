"""The threat landscape panel: an executive summary of what is trending, why it matters, and the evidence.

It opens the workspace. Everything in it comes from ``insight.landscape`` (counts from the reports, fixed
explanations from ``insight.themes``) and ``insight.brief`` (findings with a next step and the limits of the
data; docs/EXECUTIVE_BRIEF.md); every report and indicator in it opens its evidence
(ADR 0020).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, Literal

from nicegui import ui

from .. import services
from ..brief import DEMO, BriefHighlight, BriefItem, BriefSection, count_of, window_start
from ..brief_digest import executive_takeaways
from ..briefing import LABELS
from ..landscape import PERIOD_CHOICES, Landscape, ThreatTrend, compose, period_start, usual_text
from .brief_focus import build_brief_focus, render_focused_brief
from .sources import build_sync_all_button
from .theme import tlp_badge, tlp_guidance
from .typography import download_link, heading
from .workspace import Workspace

#: Threats shown as cards; the rest are listed below them.
CARDS: Final = 4
#: The two vulnerability sections retained in the brief, with context for their evidence.
SECTION_NOTES: Final[dict[str, str]] = {
    'Exploited now': (
        'CISA has seen these flaws used in attacks. This does not show attacks today or whether your '
        'systems are at risk.'
    ),
    'Most severe': (
        'A high score means a flaw could cause serious harm. It does not show that attackers are using it.'
    ),
}


def _reveal_evidence(destination: Literal['report', 'tabs']) -> None:
    """Evidence links cross a long page on every screen: wait for the target to render, then scroll to it."""
    selector = '.document-reader' if destination == 'report' else '.evidence-tabs'
    ui.run_javascript(
        'setTimeout(() => {'
        "const behavior = matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';"
        f"document.querySelector('{selector}')?.scrollIntoView({{behavior, block: 'start'}});"
        '}, 150);'
    )


def build_landscape(ws: Workspace) -> None:
    selected_focus: tuple[str, str] | None = None

    def open_item(item: BriefItem) -> None:
        if not ws.authorized():
            return
        if item.document_id:
            ws.show_inbox()  # Before opening, so the reader is on screen when a phone scrolls to it.
            ws.open_document(item.document_id)
            _reveal_evidence('report')
        elif item.entity:
            ws.show_entity(item.entity)
            _reveal_evidence('tabs')
        elif item.search:
            ws.show_inbox()
            ws.search_reports(item.search)
            _reveal_evidence('tabs')

    def evidence(item: BriefItem, prefix: str = '') -> None:
        ui.button(prefix + item.text, on_click=lambda i=item: open_item(i)).props(
            'flat dense no-caps align=left'
        ).classes('brief-evidence w-full break-value text-left')

    def highlight_card(index: int, highlight: BriefHighlight) -> None:
        with ui.column().classes('brief-priority min-w-0 gap-3 p-4 sm:p-5').mark(f'brief-priority-{index}'):
            heading(highlight.title, 3)
            ui.label(highlight.text).classes('prose')
            with ui.column().classes('brief-action gap-1 w-full'):
                ui.label('Next step').classes('font-semibold')
                ui.label(highlight.action).classes('prose')
            for item in highlight.evidence:
                evidence(item, 'View evidence: ')

    def threat_card(threat: ThreatTrend, days: int) -> None:
        with ui.column().classes('panel w-full p-3 sm:p-4 gap-1 min-w-0'):
            with ui.row().classes('w-full items-center justify-between gap-2'):
                heading(threat.name, 3)
                ui.badge(LABELS[threat.change.label]).props('outline')
            usual = usual_text(threat.change, days)
            ui.label(
                f'{count_of(threat.change.current, "report")} from {count_of(threat.sources, "source")}'
                + (f', {usual}' if usual else '')
            ).classes('muted text-sm prose')
            ui.label(threat.what).classes('prose')
            ui.label('Why it matters: ' + threat.impact).classes('prose')
            ui.label('What to check: ' + threat.check).classes('prose')
            for item in threat.reports:
                evidence(item)
            with ui.expansion('How Insight spots this').classes('w-full muted text-sm'):
                ui.label('Words in the report: ' + ', '.join(threat.words)).classes('prose break-value')
                if threat.techniques:
                    ui.label('ATT&CK techniques: ' + ', '.join(threat.techniques)).classes('prose')

    def section(index: int, part: BriefSection) -> None:
        with (
            ui.column()
            .classes('brief-section brief-section-primary min-w-0 gap-2 p-4 sm:p-5')
            .mark(f'brief-section-{index}')
        ):
            heading(part.title, 3)
            if note := SECTION_NOTES.get(part.title):
                ui.label(note).classes('muted text-sm prose')
            if not part.items:
                ui.label(part.empty).classes('muted text-sm prose')
            for item in part.items:
                evidence(item)

    def render(result: Landscape, takeaways: tuple[str, ...], partial: bool) -> None:
        days = result.days
        with ui.row().classes('w-full items-center gap-x-4 gap-y-1'):
            tlp_badge(result.tlp)
            ui.label(tlp_guidance(result.tlp)).classes('muted text-sm prose')
            if result.tlp != 'CLEAR':
                ui.label('This brief has limits on who may read it. Keep its sharing label.').classes(
                    'text-warn text-sm prose'
                )
            download_link(ws, 'Download as a briefing to share', f'/api/landscape/briefing?days={days}')
        with (
            ui.element('div').classes('brief-overview w-full'),
            ui.column().classes('summary-box w-full min-w-0 gap-2 p-4 sm:p-5').mark('brief-summary'),
        ):
            heading('Executive summary', 2)
            with ui.element('ul').classes('w-full m-0 pl-5 list-disc'):
                for sentence in takeaways:
                    with ui.element('li').classes('mb-2'):
                        ui.label(sentence).classes('brief-prose prose')
            note = 'Based on collected reports; this does not confirm an attack on your systems.'
            if partial:
                note += ' Coverage is limited; counts may be incomplete.'
            ui.label(note).classes('muted text-sm prose')
        if result.brief.highlights:
            heading('What needs attention', 2)
            with ui.element('div').classes('brief-priorities w-full').mark('brief-priorities'):
                for index, highlight in enumerate(result.brief.highlights):
                    highlight_card(index, highlight)
        heading('Trending threats', 2)
        if not result.threats:
            ui.label('No report in this period names a common kind of threat yet.').classes(
                'muted text-sm prose'
            )
        with ui.element('div').classes('grid grid-cols-1 md:grid-cols-2 gap-3 w-full'):
            for threat in result.threats[:CARDS]:
                threat_card(threat, days)
        if more := result.threats[CARDS:]:
            with (
                ui.expansion(f'Other kinds of threat in this period ({len(more)})').classes('w-full'),
                ui.element('div').classes('grid grid-cols-1 md:grid-cols-2 gap-3 w-full'),
            ):
                for threat in more:
                    threat_card(threat, days)
        if result.quieter:
            ui.label(
                'Quieter than usual: '
                + '; '.join(f'{t.name} ({usual_text(t.change, days)})' for t in result.quieter)
            ).classes('muted text-sm prose')
        ui.link_target('brief-evidence')
        heading('Vulnerabilities to watch', 2)
        with ui.element('div').classes('brief-sections w-full'):
            for index, part in enumerate(result.brief.sections):
                if part.title in SECTION_NOTES:
                    section(index, part)

    @ui.refreshable
    def landscape() -> None:
        if not ws.authorized():
            return
        days = ws.state.landscape_days
        if selected_focus is not None:
            try:
                with ws.read() as db:
                    focused = services.focused_brief(
                        db, *selected_focus, days=days, max_tlp=ws.app.state.settings.max_tlp
                    )
            except (LookupError, ValueError):
                ui.label(
                    'This focus is no longer available. Search again or choose All intelligence.'
                ).classes('muted prose')
                return
            render_focused_brief(ws, focused)
            return
        now = datetime.now(UTC)
        since = window_start(now, days)
        with ws.read() as db:
            data = services.landscape_data(
                db, start=period_start(now, days), ignore=DEMO, max_tlp=ws.reader_limit
            )
            brief = services.brief_data(db, since=since, max_tlp=ws.reader_limit)
        result = compose(data, brief, since=since, days=days)
        render(result, executive_takeaways(brief, result), data.truncated or brief.truncated)

    def choose(days: int) -> None:
        ws.state.landscape_days = days
        landscape.refresh()

    def change_focus(focus: tuple[str, str] | None) -> None:
        nonlocal selected_focus
        selected_focus = focus
        landscape.refresh()

    ws.on_refresh(landscape.refresh)
    with ui.column().classes('intel-brief w-full gap-4 sm:gap-5').mark('intel-brief'):
        with ui.row().classes('brief-heading w-full items-end justify-between gap-3'):
            heading('Intel brief', 1)
            with ui.row().classes('items-center gap-3 w-full sm:w-auto'):
                ui.toggle(
                    {days: f'Last {days} days' for days in PERIOD_CHOICES},
                    value=ws.state.landscape_days,
                    on_change=lambda e: choose(e.value),
                ).props('no-caps unelevated aria-label="Period"')
                build_sync_all_button(ws)
        build_brief_focus(ws, change_focus)
        landscape()
