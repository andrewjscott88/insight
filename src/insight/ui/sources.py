"""Curated source registry: explicit, opt-in sync with visible history."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from nicegui import ui

from .. import services
from ..connectors import sync_all, sync_source
from ..permissions import Permission
from ..source_registry import CATEGORIES, SOURCES, Source, in_use
from .censys import build_censys_settings
from .lookups import build_lookup_switches
from .messages import tell
from .offered import setting_switch
from .operator_sources import build_operator_sources
from .pivots import build_pivot_switches
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
                (r.source_key, r.status, r.created_at, r.message)
                for r in services.recent_source_runs(db, max_tlp=ws.app.state.settings.max_tlp)
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
        if not ws.allowed(Permission.SYNC_SOURCES):
            return
        actor = ws.actor(Permission.SYNC_SOURCES)
        lock = ws.app.state.sync_lock
        if lock.locked():
            tell('Another source sync is running. Try again when it finishes.', 'warning')
            return
        button.disable()
        try:
            async with lock:
                message = await sync_source(
                    ws.sessions, key, max_tlp=ws.app.state.settings.max_tlp, actor=actor
                )
            if ws.authorized():
                tell(message, 'success')
                ws.refresh_all()
        except Exception as exc:  # Surface any failure to the analyst, never crash the page.
            if ws.authorized():
                if key in SOURCES:
                    tell(f'Sync failed: {exc}', 'error')
                    source_history.refresh()
                else:
                    tell('Sync failed. Check recent sync activity.', 'error')
                    ws.refresh_all()
        finally:
            # Custom cards redraw from the saved switch, which may have changed during a fetch.
            if key in SOURCES and not button.is_deleted:
                button.enable()

    def switch(source: Source, on: bool, sync_button: ui.button | None, schedule: ui.select | None) -> None:
        if not ws.allowed(Permission.SOURCES):
            return
        with ws.write(Permission.SOURCES) as db:
            services.set_source_switch(db, source.key, on, at=datetime.now(UTC))
        for control in (sync_button, schedule):
            if control is not None:
                control.set_enabled(on)
        if on:
            tell(f'{source.name} is on. Press Sync now to fetch its reports.', 'success')
        else:
            if schedule is not None:
                schedule.set_value(0)  # Switching off turned the schedule off too.
            tell(f'{source.name} is off. Insight will not contact it.', 'success')

    def source_panel(source: Source, on: bool, controls: ScheduleControls) -> None:
        """Each control only for a role that may use it (ADR 0046); the others see the setting in words."""
        with ui.column().classes('panel w-full p-4 my-3'):
            heading(source.name, 4)
            ui.label(source.note).classes('muted text-sm prose')
            new_tab_link(f'View the {source.name} feed', source.url)
            # The switch comes first on the page; its callback runs later, when both controls exist.
            setting_switch(
                ws,
                Permission.SOURCES,
                'Use this source',
                on,
                lambda value: switch(source, value, sync_button, schedule),
                state=('In use', 'Not in use'),
            )
            with ui.row().classes('items-center gap-3 flex-wrap'):
                sync_button = ui.button('Sync now') if ws.can(Permission.SYNC_SOURCES) else None
                if sync_button is not None:
                    sync_button.on_click(lambda key=source.key, button=sync_button: run(key, button))
                    sync_button.set_enabled(on)
                schedule = build_schedule_control(ws, source.key, source.name, controls)
                if schedule is not None:
                    schedule.set_enabled(on)

    ws.on_refresh(source_history.refresh)
    heading('Public sources', 2)
    ui.label(
        'Nothing syncs by itself unless you turn on a schedule. When you press Sync now, Insight fetches '
        'public reports from that publisher and keeps them here. Sync all sources, at the top of the page, '
        'does this for each source you use, in turn. A schedule does it for you, and skips a feed that has '
        'not changed. Insight never sends your own reports anywhere.'
    ).classes('muted prose')
    ui.label(
        'Threat research and news sources are off until you switch them on. Insight keeps only the title, '
        'a short summary and the link from them, and leaves their words out of exports.'
    ).classes('muted prose')
    controls = ScheduleControls()
    build_all_sources_schedule(ws, controls)
    build_operator_sources(ws, controls, run)
    with ws.read() as db:
        switches = services.source_switches(db)
    for category, title in CATEGORIES.items():
        heading(title, 3, 'subsection-title mt-4')
        for source in (s for s in SOURCES.values() if s.category == category):
            source_panel(source, in_use(source, switches), controls)
    build_lookup_switches(ws)
    build_pivot_switches(ws)
    build_censys_settings(ws)
    heading('Recent sync activity', 3, 'subsection-title mt-4')
    with ui.column().classes('w-full gap-3'):
        source_history()


SYNC_ALL: Final = 'Sync all sources'


def build_sync_all_button(ws: Workspace) -> ui.button:
    """One button that syncs every source in turn, shows how far it has got, and sums up the results."""

    async def run_all(button: ui.button) -> None:
        if not ws.allowed(Permission.SYNC_SOURCES):
            return
        actor = ws.actor(Permission.SYNC_SOURCES)
        lock = ws.app.state.sync_lock
        if lock.locked():
            tell('Another source sync is running. Try again when it finishes.', 'warning')
            return

        def started(position: int, total: int, source: Source) -> None:
            button.set_text(f'Syncing {position} of {total}: {source.name}')

        button.disable()
        try:
            async with lock:
                results = await sync_all(
                    ws.sessions, on_start=started, max_tlp=ws.app.state.settings.max_tlp, actor=actor
                )
            if not ws.authorized():
                return
            failed = [r.name for r in results if not r.ok]
            if failed:
                tell(
                    f'{len(results) - len(failed)} of {len(results)} sources synced. Failed: '
                    f'{", ".join(failed)}. The list below shows why.',
                    'warning',
                )
            else:
                tell(
                    f'All {len(results)} sources synced. The list below shows what each one added.',
                    'success',
                )
            ws.refresh_all()
        finally:
            button.set_text(SYNC_ALL)
            button.enable()

    button = ui.button(SYNC_ALL, icon='sync').props('outline').classes('flex-1 sm:flex-none')
    button.on_click(lambda: run_all(button))
    return button
