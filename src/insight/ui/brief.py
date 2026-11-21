"""The landing brief: a plain-language overview, priorities and the reports behind them."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from nicegui import ui

from .. import services
from ..brief import DEFAULT_DAYS, BriefItem, compose, window_start
from .sources import build_sync_all_button
from .typography import heading
from .workspace import Workspace


def _count(value: int, noun: str) -> str:
    return f'{value} {noun}{"s" if value != 1 else ""}'


def _reveal_evidence(destination: Literal['report', 'tabs']) -> None:
    """Brief links cross a long page on every screen; wait for the target panel to render before scrolling."""
    selector = '.document-reader' if destination == 'report' else '.evidence-tabs'
    ui.run_javascript(
        'setTimeout(() => {'
        "const behavior = matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';"
        f"document.querySelector('{selector}')?.scrollIntoView({{behavior, block: 'start'}});"
        '}, 150);'
    )


def build_brief(ws: Workspace) -> None:
    def open_reports() -> None:
        if ws.authorized():
            ws.show_inbox()

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

    @ui.refreshable
    def brief() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            data = services.brief_data(db, since=window_start(datetime.now(UTC), DEFAULT_DAYS))
        result = compose(data, DEFAULT_DAYS)
        with ui.element('div').classes('brief-overview w-full'):
            with ui.column().classes('summary-box min-w-0 gap-4 p-4 sm:p-6').mark('brief-summary'):
                heading('Executive summary', 2)
                for sentence in result.summary:
                    ui.label(sentence).classes('brief-prose prose')
            with ui.column().classes('brief-context min-w-0 gap-4 p-4 sm:p-6').mark('brief-context'):
                ui.label('Last 24 hours').classes('eyebrow')
                ui.label(str(result.recent_reports)).classes('brief-recent-count')
                ui.label('Reports in this brief received in the last 24 hours.').classes('muted prose')
                with ui.column().classes('brief-scope w-full gap-2'):
                    ui.label(
                        f'{_count(result.report_count, "report")} · {_count(result.source_count, "source")}'
                    ).classes('font-medium')
                    ui.label(f'Across the last {result.days} days').classes('muted')
                    as_of = datetime.fromisoformat(result.as_of).astimezone(UTC)
                    ui.label(f'As of {as_of:%d %b %Y, %H:%M} UTC').classes('muted')
                with (
                    ui.expansion('About this brief', icon='info_outline').classes('brief-coverage w-full'),
                    ui.column().classes('gap-3 pt-2'),
                ):
                    for note in result.coverage:
                        ui.label(note).classes('muted prose')
        if result.highlights:
            with ui.column().classes('w-full gap-3').mark('brief-priorities'):
                heading('What needs attention', 2)
                with ui.element('div').classes('brief-priorities w-full'):
                    for index, highlight in enumerate(result.highlights):
                        with (
                            ui.column()
                            .classes('brief-priority min-w-0 gap-3 p-4 sm:p-5')
                            .mark(f'brief-priority-{index}')
                        ):
                            heading(highlight.title, 3)
                            ui.label(highlight.text).classes('prose')
                            with ui.column().classes('brief-action gap-1 w-full'):
                                ui.label('Next step').classes('font-semibold')
                                ui.label(highlight.action).classes('prose')
                            for evidence_index, item in enumerate(highlight.evidence):
                                ui.button(
                                    f'View evidence: {item.text}', on_click=lambda i=item: open_item(i)
                                ).mark(f'brief-highlight-evidence-{index}-{evidence_index}').props(
                                    'flat dense no-caps align=left'
                                ).classes('brief-evidence w-full break-value text-left')
        with ui.column().classes('w-full gap-3').props('id=brief-evidence'):
            heading('Evidence at a glance', 2)
            ui.label('Choose a report, indicator or topic to read more.').classes('muted prose')
            with ui.element('div').classes('brief-sections w-full'):
                for index, section in enumerate(result.sections):
                    emphasis = ' brief-section-primary' if index < 2 else ''
                    with (
                        ui.column()
                        .classes(f'brief-section min-w-0 gap-2 p-4 sm:p-5{emphasis}')
                        .mark(f'brief-section-{index}')
                    ):
                        heading(section.title, 3)
                        if section.title == 'Exploited now':
                            ui.label(
                                'CISA has seen these flaws used in attacks. This does not show attacks '
                                'today or whether your systems are at risk.'
                            ).classes('muted prose')
                        elif section.title == 'Most severe':
                            ui.label(
                                'A high score means a flaw could cause serious harm. '
                                'It does not show that attackers are using it.'
                            ).classes('muted prose')
                        if not section.items:
                            ui.label(section.empty).classes('muted prose')
                        for item in section.items:
                            ui.button(item.text, on_click=lambda i=item: open_item(i)).props(
                                'flat dense no-caps align=left'
                            ).classes('brief-evidence w-full break-value text-left')

    ws.on_refresh(brief.refresh)
    with ui.column().classes('intel-brief w-full gap-5 sm:gap-6').mark('intel-brief'):
        with ui.row().classes('brief-heading w-full items-end justify-between gap-3'):
            with ui.column().classes('gap-2'):
                ui.label(f'Your {DEFAULT_DAYS}-day view').classes('eyebrow')
                heading('Intel brief', 1)
                ui.label('What changed, why it matters, and what to check next.').classes('muted prose')
            with ui.row().classes('items-center gap-4 w-full sm:w-auto'):
                ui.link('View CVEs', '#brief-evidence').classes('target-link font-semibold')
                ui.link('Read reports', '#report-tools').classes('target-link font-semibold').on(
                    'click', open_reports
                )
                build_sync_all_button(ws)
        brief()
