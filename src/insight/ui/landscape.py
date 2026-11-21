"""The threat landscape panel: an executive summary of what is trending, why it matters, and the evidence.

It opens the workspace. Everything in it comes from ``insight.landscape`` (counts from the reports, fixed
explanations from ``insight.themes``); every report and indicator in it opens its evidence (ADR 0020).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from nicegui import ui

from .. import services
from ..brief import DEMO, BriefItem, BriefSection, count_of, window_start
from ..briefing import LABELS
from ..landscape import PERIOD_CHOICES, Landscape, TacticTrend, ThreatTrend, compose, period_start, usual_text
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .workspace import Workspace

#: Threats shown as cards; the rest are listed below them.
CARDS: Final = 4
#: Tactics listed before "Show all".
TACTICS: Final = 5


def build_landscape(ws: Workspace) -> None:
    def open_item(item: BriefItem) -> None:
        if not ws.authorized():
            return
        if item.document_id:
            ws.show_inbox()  # Before opening, so the reader is on screen when a phone scrolls to it.
            ws.open_document(item.document_id)
        elif item.entity:
            ws.show_entity(item.entity)
        elif item.search:
            ws.show_inbox()
            ws.search_reports(item.search)

    def evidence(item: BriefItem) -> None:
        ui.button(item.text, on_click=lambda i=item: open_item(i)).props(
            'flat dense no-caps align=left'
        ).classes('w-full break-value text-left')

    def threat_card(threat: ThreatTrend, days: int) -> None:
        with ui.column().classes('panel w-full p-3 sm:p-4 gap-1 min-w-0'):
            with ui.row().classes('w-full items-center justify-between gap-2'):
                heading(threat.name, 4)
                ui.badge(LABELS[threat.change.label]).props('outline')
            usual = usual_text(threat.change, days)
            ui.label(
                f'{count_of(threat.change.current, "report")} from {count_of(threat.sources, "source")}'
                + (f', {usual}' if usual else '')
            ).classes('muted text-sm')
            ui.label(threat.what).classes('prose')
            ui.label('Why it matters: ' + threat.impact).classes('prose')
            ui.label('What to check: ' + threat.check).classes('prose')
            for item in threat.reports:
                evidence(item)
            with ui.expansion('How Insight spots this').classes('w-full muted text-sm'):
                ui.label('Words in the report: ' + ', '.join(threat.words)).classes('prose break-value')
                if threat.techniques:
                    ui.label('ATT&CK techniques: ' + ', '.join(threat.techniques)).classes('prose')

    def tactic_row(tactic: TacticTrend, days: int) -> None:
        usual = usual_text(tactic.change, days)
        with ui.column().classes('w-full gap-0'):
            ui.label(
                f'{tactic.plain.capitalize()} ({tactic.name}) · {count_of(tactic.change.current, "report")}'
                + (f', {usual}' if usual else '')
                + f' · {LABELS[tactic.change.label]}'
            ).classes('prose')
            ui.label(' · '.join(f'{t} {name} ({n})' for t, name, n in tactic.techniques)).classes(
                'muted text-sm break-value'
            )

    def section(part: BriefSection) -> None:
        with ui.column().classes('gap-1 min-w-0'):
            heading(part.title, 3)
            if not part.items:
                ui.label(part.empty).classes('muted text-sm prose')
            for item in part.items:
                evidence(item)

    def render(result: Landscape) -> None:
        days = result.days
        with ui.row().classes('w-full items-center gap-x-4 gap-y-1'):
            tlp_badge(result.tlp)
            ui.label(f'Built from reports up to TLP:{result.tlp}. Share it no wider than that.').classes(
                'muted text-sm prose'
            )
            new_tab_link('Download as a briefing to share', f'/api/landscape/briefing?days={days}')
        with ui.column().classes('summary-box w-full gap-1 p-3 sm:p-4').mark('brief-summary'):
            heading('Executive summary', 3)
            for sentence in result.summary:
                ui.label(sentence).classes('prose')
            for caveat in result.caveats:
                ui.label(caveat).classes('muted text-sm prose')
        heading('Trending threats', 3)
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
        heading('What attackers are doing', 3)
        if not result.tactics:
            ui.label('No report in this period has ATT&CK techniques yet.').classes('muted text-sm prose')
        for tactic in result.tactics[:TACTICS]:
            tactic_row(tactic, days)
        if rest := result.tactics[TACTICS:]:
            with ui.expansion(f'Show all tactics ({len(result.tactics)})').classes('w-full'):
                for tactic in rest:
                    tactic_row(tactic, days)
        with ui.element('div').classes('grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4 w-full'):
            for part in result.brief.sections:
                section(part)

    @ui.refreshable
    def landscape() -> None:
        if not ws.authorized():
            return
        days = ws.state.landscape_days
        now = datetime.now(UTC)
        since = window_start(now, days)
        with ws.read() as db:
            data = services.landscape_data(db, start=period_start(now, days), ignore=DEMO)
            brief = services.brief_data(db, since=since)
        render(compose(data, brief, since=since, days=days))

    def choose(days: int) -> None:
        ws.state.landscape_days = days
        landscape.refresh()

    ws.on_refresh(landscape.refresh)
    with ui.column().classes('panel w-full p-4 sm:p-5 gap-3').mark('intel-brief'):
        with ui.row().classes('w-full items-center justify-between gap-2'):
            heading('Threat landscape', 2)
            ui.toggle(
                {days: f'Last {days} days' for days in PERIOD_CHOICES},
                value=ws.state.landscape_days,
                on_change=lambda e: choose(e.value),
            ).props('no-caps unelevated aria-label="Period"')
        ui.label(
            'What is trending in your reports and why it matters. Built from your reports, not written by '
            'AI. Choose a report to see where a line comes from.'
        ).classes('muted text-sm prose')
        landscape()
