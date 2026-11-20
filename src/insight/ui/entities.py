"""Entity explorer: pivot from an indicator to every source that mentions it.

Pivot lists are loaded lazily (when an entity is expanded) and page by page. Rendering every document for
every entity up front made the page grow with how often indicators recur, which is exactly what happens in
CTI: 100 reports sharing 43 indicators produced ~5,200 UI elements and a 1.7 MB page.
"""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import services
from .typography import heading
from .workspace import Workspace


def build_entities(ws: Workspace) -> None:
    def render_page(container: ui.column, entity_id: str, offset: int) -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            docs = services.entity_documents(db, entity_id, offset=offset, limit=services.PIVOT_PAGE_SIZE)
            total = services.count_entity_documents(db, entity_id)
            rows = [(d.id, d.title, d.tlp, d.is_current) for d in docs]
        with container:
            for doc_id, title, tlp, is_current in rows:
                superseded = '' if is_current else ' · superseded'

                def open_source(document_id: str = doc_id) -> None:
                    ws.show_inbox()  # Before opening, so the reader is on screen when a phone scrolls to it.
                    ws.open_document(document_id)

                ui.button(f'{title} · TLP:{tlp}{superseded}', on_click=open_source).props(
                    'flat no-caps align=left'
                ).classes('w-full')
            shown = offset + len(rows)
            if shown < total:
                more = ui.button(f'Show more ({total - shown} remaining)').props('flat dense no-caps')

                def load_more(button: ui.button = more, next_offset: int = shown) -> None:
                    button.delete()
                    render_page(container, entity_id, next_offset)

                more.on_click(load_more)

    @ui.refreshable
    def entity_list() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            rows = [
                (e.id, e.kind, e.value, count) for e, count in services.list_entities(db, ws.state.entity_q)
            ]
        for entity_id, kind, value, count in rows:
            expansion = ui.expansion(f'{kind.upper()} · {value} · {count} source(s)').classes(
                'panel w-full break-value'
            )
            with expansion:
                ui.label(
                    'A match shows that reports mention the same value. It does not prove harm.'
                ).classes('muted text-xs')
                container = ui.column().classes('w-full gap-1')

            def on_open(event: Any, box: ui.column = container, target: str = entity_id) -> None:
                if event.value and not box.default_slot.children:
                    render_page(box, target, 0)

            expansion.on_value_change(on_open)
        if not rows:
            ui.label('No entities yet. Add a report to start linking evidence.').classes('muted p-5')

    def search(value: str | None) -> None:
        ws.state.entity_q = value or ''
        entity_list.refresh()

    ws.on_refresh(entity_list.refresh)
    heading('Entity explorer', 2)
    ui.label('Trace every indicator back to the reports that mention it.').classes('muted prose')
    search_box = ui.input('Search entity values', on_change=lambda e: search(e.value)).props(
        'outlined dense debounce=300 clearable'
    )
    search_box.classes('w-full max-w-xl')

    def find(value: str) -> None:
        search_box.set_value(value)  # Changing the value runs the search, as typing does.

    ws.find_entity = find
    with ui.column().classes('w-full gap-3'):
        entity_list()
