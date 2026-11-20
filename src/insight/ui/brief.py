"""Intel brief panel: what the last week of intelligence adds up to, each line linked to its evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from nicegui import ui

from .. import services
from ..brief import DEFAULT_DAYS, BriefItem, compose, window_start
from .typography import heading
from .workspace import Workspace


def build_brief(ws: Workspace) -> None:
    def open_item(item: BriefItem) -> None:
        if not ws.authorized():
            return
        if item.document_id:
            ws.show_inbox()  # Before opening, so the reader is on screen when a phone scrolls to it.
            ws.open_document(item.document_id)
        elif item.entity:
            ws.show_entity(item.entity)

    @ui.refreshable
    def brief() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            data = services.brief_data(db, since=window_start(datetime.now(UTC), DEFAULT_DAYS))
        result = compose(data, DEFAULT_DAYS)
        ui.label(result.headline).classes('prose').mark('brief-headline')
        with ui.element('div').classes('grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4 w-full'):
            for section in result.sections:
                with ui.column().classes('gap-1 min-w-0'):
                    heading(section.title, 3)
                    if not section.items:
                        ui.label(section.empty).classes('muted text-sm prose')
                    for item in section.items:
                        if item.document_id or item.entity:
                            ui.button(item.text, on_click=lambda i=item: open_item(i)).props(
                                'flat dense no-caps align=left'
                            ).classes('w-full break-value text-left')
                        else:
                            ui.label(item.text).classes('text-sm break-value')

    ws.on_refresh(brief.refresh)
    with ui.column().classes('panel w-full p-4 sm:p-5 gap-3').mark('intel-brief'):
        with ui.row().classes('w-full items-baseline justify-between gap-2'):
            heading('Intel brief', 2)
            ui.label(f'Last {DEFAULT_DAYS} days').classes('muted text-sm')
        ui.label(
            'Built from your reports, not written by AI. Choose a line to see where it comes from.'
        ).classes('muted text-sm prose')
        brief()
