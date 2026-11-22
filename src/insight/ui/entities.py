"""Entity explorer: pivot from an indicator to every source that mentions it.

Pivot lists are loaded lazily (when an entity is expanded) and page by page. Rendering every document for
every entity up front made the page grow with how often indicators recur, which is exactly what happens in
CTI: 100 reports sharing 43 indicators produced ~5,200 UI elements and a 1.7 MB page.
"""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import greynoise, services
from .graph import open_graph
from .greynoise import open_greynoise
from .typography import heading
from .verdicts import Indicator, flag_badges, load_verdicts, render_verdict
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

    def render_about(box: ui.column, target: Indicator) -> None:
        """Warnings, when the value was seen and the verdict, for one entity (loaded when it is opened)."""
        if not ws.authorized():
            return
        with ws.read() as db:
            verdict = load_verdicts(db, [target.entity_id]).get(target.entity_id)
            first, last = services.entity_seen(db, target.entity_id)
            show_greynoise = (
                target.kind == 'ip'
                and greynoise.configured()
                and services.eligible_greynoise_ip(db, target.value)
            )
        box.clear()
        with box:
            flag_badges(target.kind, target.value)
            ui.button('Show links', on_click=lambda: open_graph(ws, f'indicator:{target.entity_id}')).props(
                'outline no-caps'
            ).mark(f'entity-links-{target.value}')
            if show_greynoise:
                ui.button(
                    'GreyNoise Community context', on_click=lambda: open_greynoise(ws, target.value)
                ).props('outline no-caps')
            if first and last:
                ui.label(f'In reports added from {first[:10]} to {last[:10]}').classes('muted text-sm')
            render_verdict(ws, target, verdict, on_saved=lambda: render_about(box, target))

    @ui.refreshable
    def entity_list() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            rows = [
                (e.id, e.kind, e.value, count) for e, count in services.list_entities(db, ws.state.entity_q)
            ]
        for entity_id, kind, value, count in rows:
            indicator = Indicator(entity_id, kind, value)
            expansion = ui.expansion(f'{kind.upper()} · {value} · {count} source(s)').classes(
                'panel w-full break-value'
            )
            with expansion:
                ui.label(
                    'A match shows that reports mention the same value. It does not prove harm.'
                ).classes('muted text-xs')
                about = ui.column().classes('w-full gap-1')
                container = ui.column().classes('w-full gap-1')

            def on_open(
                event: Any,
                box: ui.column = container,
                info: ui.column = about,
                target: Indicator = indicator,
            ) -> None:
                if event.value and not box.default_slot.children:
                    render_about(info, target)
                    render_page(box, target.entity_id, 0)

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
