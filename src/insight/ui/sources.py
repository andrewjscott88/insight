"""Curated source registry: explicit, opt-in sync with visible history."""

from __future__ import annotations

from nicegui import ui

from .. import services
from ..connectors import SOURCES, sync_source
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
            ui.label('No source syncs yet. Network access is manual and opt-in.').classes('muted text-sm')
        for source_key, status, created_at, message in runs:
            with ui.column().classes('panel p-3 w-full gap-1'):
                ui.label(f'{source_key} · {status} · {created_at[:16]}').classes('text-xs')
                ui.label(message).classes('muted text-xs break-value')

    async def run(key: str, button: ui.button) -> None:
        if not ws.authorized():
            return
        lock = ws.app.state.sync_lock
        if lock.locked():
            ui.notify('Another source sync is running. Try again when it finishes.', type='warning')
            return
        button.disable()
        try:
            async with lock:
                message = await sync_source(ws.sessions, key)
            if ws.authorized():
                ui.notify(message)
                ws.refresh_all()
        except Exception as exc:  # Surface any failure to the analyst, never crash the page.
            if ws.authorized():
                ui.notify(f'Sync failed: {exc}', type='negative', timeout=10000)
                source_history.refresh()
        finally:
            button.enable()

    ws.on_refresh(source_history.refresh)
    ui.label('Curated public sources').classes('text-xl')
    ui.label(
        'Nothing syncs automatically. Each sync contacts the named publisher and stores '
        'public feed data locally. It does not upload your intelligence.'
    ).classes('muted text-sm')
    for source in SOURCES.values():
        with ui.column().classes('panel w-full p-4 my-3'):
            ui.label(source.name).classes('font-medium')
            ui.label(source.note).classes('muted text-xs')
            ui.link('View feed ↗', source.url, new_tab=True).classes('text-xs')
            sync_button = ui.button('Sync now')
            sync_button.on_click(lambda key=source.key, button=sync_button: run(key, button))
    ui.label('RECENT SYNC ACTIVITY').classes('eyebrow mt-4')
    with ui.column().classes('w-full gap-3'):
        source_history()
