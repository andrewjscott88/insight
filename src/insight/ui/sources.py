"""Curated source registry: explicit, opt-in sync with visible history."""

from __future__ import annotations

from typing import Final

from nicegui import ui

from .. import services
from ..connectors import SOURCES, Source, sync_all, sync_source
from .messages import tell
from .schedules import ScheduleControls, build_all_sources_schedule, build_schedule_control
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
            nothing = (
                'No source syncs yet. Insight only goes online when you press Sync now or turn on a schedule.'
            )
            ui.label(nothing).classes('muted prose')
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
        'Nothing syncs by itself unless you turn on a schedule. When you press Sync now, Insight fetches '
        'public reports from that publisher and keeps them here. Sync all sources, at the top of the page, '
        'does this for each one in turn. A schedule does it for you, and skips a feed that has not changed. '
        'Insight never sends your own reports anywhere.'
    ).classes('muted prose')
    controls = ScheduleControls()
    build_all_sources_schedule(ws, controls)
    for source in SOURCES.values():
        with ui.column().classes('panel w-full p-4 my-3'):
            heading(source.name, 3)
            ui.label(source.note).classes('muted text-sm prose')
            new_tab_link(f'View the {source.name} feed', source.url)
            with ui.row().classes('items-center gap-3 flex-wrap'):
                sync_button = ui.button('Sync now')
                sync_button.on_click(lambda key=source.key, button=sync_button: run(key, button))
                build_schedule_control(ws, source, controls)
    heading('Recent sync activity', 3, 'subsection-title mt-4')
    with ui.column().classes('w-full gap-3'):
        source_history()


SYNC_ALL: Final = 'Sync all sources'


def build_sync_all_button(ws: Workspace) -> ui.button:
    """One button that syncs every source in turn, shows how far it has got, and sums up the results."""

    async def run_all(button: ui.button) -> None:
        if not ws.authorized():
            return
        lock = ws.app.state.sync_lock
        if lock.locked():
            tell('Another source sync is running. Try again when it finishes.', 'warning')
            return

        def started(position: int, total: int, source: Source) -> None:
            button.set_text(f'Syncing {position} of {total}: {source.name}')

        button.disable()
        try:
            async with lock:
                results = await sync_all(ws.sessions, on_start=started)
            if not ws.authorized():
                return
            failed = [r.name for r in results if not r.ok]
            if failed:
                tell(
                    f'{len(results) - len(failed)} of {len(results)} sources synced. Failed: '
                    f'{", ".join(failed)}. The Sources tab shows why.',
                    'warning',
                )
            else:
                tell(
                    f'All {len(results)} sources synced. The Sources tab shows what each one added.',
                    'success',
                )
            ws.refresh_all()
        finally:
            button.set_text(SYNC_ALL)
            button.enable()

    button = ui.button(SYNC_ALL, icon='sync').props('outline').classes('flex-1 sm:flex-none')
    button.on_click(lambda: run_all(button))
    return button
