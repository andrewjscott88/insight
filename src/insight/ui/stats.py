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
        with ui.row().classes('w-full gap-4 flex-wrap'):
            for value, title in tiles:
                with ui.column().classes('panel p-5 flex-1 min-w-[180px] gap-1'):
                    ui.label(str(value)).classes('text-3xl font-medium')
                    ui.label(title).classes('muted text-xs')

    ws.on_refresh(stats.refresh)
    stats()
