"""Curated source registry: explicit, opt-in sync with visible history."""

from __future__ import annotations

from nicegui import ui

from .. import services
from ..connectors import SOURCES, sync_source
from .messages import tell
from .typography import heading, new_tab_link
from .workspace import Workspace


def build_sources(ws: Workspace) -> None:
    @ui.refreshable
    def source_history() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            runs = [
                (r.source_key, r.status, r.created_at, r.message) for r in services.recent_source_runs(db)
            ]
        if not runs:
            ui.label('No source syncs yet. Insight only goes online when you press Sync now.').classes(
                'muted prose'
            )
        for source_key, status, created_at, message in runs:
            with ui.column().classes('panel p-3 w-full gap-1'):
                ui.label(f'{source_key} · {status} · {created_at[:16]}').classes('text-sm')
                ui.label(message).classes('muted text-sm break-value prose')

    async def run(key: str, button: ui.button) -> None:
        if not ws.authorized():
            return
        lock = ws.app.state.sync_lock
        if lock.locked():
            tell('Another source sync is running. Try again when it finishes.', 'warning')
            return
        button.disable()
        try:
            async with lock:
                message = await sync_source(ws.sessions, key)
            if ws.authorized():
                tell(message, 'success')
                ws.refresh_all()
        except Exception as exc:  # Surface any failure to the analyst, never crash the page.
            if ws.authorized():
                tell(f'Sync failed: {exc}', 'error')
                source_history.refresh()
        finally:
            button.enable()

    ws.on_refresh(source_history.refresh)
    heading('Public sources', 2)
    ui.label(
        'Nothing syncs by itself. When you press Sync now, Insight fetches public reports from that '
        'publisher and keeps them here. It never sends your own reports anywhere.'
    ).classes('muted prose')
    for source in SOURCES.values():
        with ui.column().classes('panel w-full p-4 my-3'):
            heading(source.name, 3)
            ui.label(source.note).classes('muted text-sm prose')
            new_tab_link(f'View the {source.name} feed', source.url)
            sync_button = ui.button('Sync now')
            sync_button.on_click(lambda key=source.key, button=sync_button: run(key, button))
    heading('Recent sync activity', 3, 'subsection-title mt-4')
    with ui.column().classes('w-full gap-3'):
        source_history()
