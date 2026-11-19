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
        tiles = (
            (counts['documents'], 'Source documents'),
            (counts['entities'], 'Unique extracted entities'),
            (counts['observations_unreviewed'], 'Observations awaiting review'),
        )
        # As many across as fit without breaking a word (three on most screens, fewer with "Larger text" on
        # a phone). The width is in rem, so it grows with the text. Regression: labels broke mid-word.
        with ui.element('div').classes('stat-tiles w-full gap-2 sm:gap-4'):
            for value, title in tiles:
                with ui.column().classes('panel p-3 sm:p-5 min-w-0 gap-1'):
                    ui.label(str(value)).classes('text-2xl sm:text-3xl font-medium')
                    ui.label(title).classes('muted text-xs')

    ws.on_refresh(stats.refresh)
    stats()
