"""Headline counters."""

from __future__ import annotations

from nicegui import ui

from .. import services
from .workspace import Workspace


def build_stats(ws: Workspace) -> None:
    @ui.refreshable
    def stats() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            counts = services.stats(db)
        # Each tile opens the list it counts.
        tiles = (
            (counts['documents'], 'Reports', 'triage', None),
            (counts['entities'], 'Indicators', 'investigate', 'indicators'),
            (counts['observations_unreviewed'], 'Waiting for review', 'triage', None),
        )
        # As many across as fit without breaking a word (three on most screens, fewer with "Larger text" on
        # a phone). The width is in rem, so it grows with the text. Regression: labels broke mid-word.
        with ui.element('div').classes('stat-tiles w-full gap-2 sm:gap-4'):
            for value, title, section, tab in tiles:
                tile = (
                    ui.button(on_click=lambda s=section, t=tab: ws.show_section(s, t))
                    .props(f'flat no-caps align=left aria-label="{value} {title.lower()}: open the list"')
                    .classes('panel stat-tile p-3 sm:p-5 min-w-0')
                    .mark(f'stat-{section}-{tab or "list"}')
                )
                with tile, ui.column().classes('gap-1 items-start'):
                    ui.label(str(value)).classes('text-2xl sm:text-3xl font-medium')
                    ui.label(title).classes('muted text-xs')

    ws.on_refresh(stats.refresh)
    stats()
