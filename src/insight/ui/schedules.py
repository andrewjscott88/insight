"""Schedule controls in the Sources tab: how often each source syncs by itself (off unless you choose)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from nicegui import ui

from .. import services
from ..connectors import SOURCES, Source
from .messages import tell
from .workspace import Workspace

#: Choices shown for :data:`insight.services.SCHEDULE_INTERVALS` (minutes).
CHOICES: Final = {0: 'Off', 60: 'Every hour', 360: 'Every 6 hours', 1440: 'Every day'}


def _interval(ws: Workspace, key: str) -> tuple[int, str | None]:
    with ws.read() as db:
        schedule = services.list_schedules(db).get(key)
    if schedule is None or not schedule.enabled:
        return 0, None
    return schedule.interval_minutes, schedule.next_run_at


def _save(ws: Workspace, keys: list[str], minutes: int) -> None:
    with ws.write() as db:
        for key in keys:
            services.set_schedule(db, key, minutes, at=datetime.now(UTC))


def _confirm(ws: Workspace, what: str, minutes: int) -> None:
    if not minutes:
        tell(f'{what} now only when you press Sync now.', 'success')
    elif ws.app.state.settings.run_jobs:
        tell(
            f'{what} by itself {CHOICES[minutes].lower()}. The first sync starts within a minute.', 'success'
        )
    else:
        tell(
            'The schedule is saved, but this server does not run scheduled syncs (INSIGHT_RUN_JOBS is off).',
            'warning',
        )


def build_all_sources_schedule(ws: Workspace, selects: dict[str, ui.select]) -> None:
    """One control that sets every source's schedule at once."""

    def changed(minutes: int | None) -> None:
        if minutes is None or not ws.authorized():
            return
        _save(ws, list(SOURCES), minutes)
        for select in selects.values():
            select.set_value(minutes)  # Each source's own control runs nothing new for an unchanged value.
        _confirm(ws, 'All sources sync', minutes)

    with ui.row().classes('items-center gap-3 flex-wrap'):
        ui.select(
            CHOICES, label='Sync all sources by themselves', on_change=lambda e: changed(e.value)
        ).props('outlined dense').classes('min-w-[16rem]')


def build_schedule_control(ws: Workspace, source: Source) -> ui.select:
    """A source's schedule choice, and when it next syncs by itself."""
    minutes, _ = _interval(ws, source.key)

    @ui.refreshable
    def next_sync() -> None:
        current, upcoming = _interval(ws, source.key)
        text = (
            f'Next sync: {upcoming[:16].replace("T", " ")} UTC'
            if current and upcoming
            else 'Syncs only when you ask.'
        )
        ui.label(text).classes('muted text-sm')

    def changed(value: int | None) -> None:
        if value is None or not ws.authorized() or value == _interval(ws, source.key)[0]:
            next_sync.refresh()
            return
        _save(ws, [source.key], value)
        _confirm(ws, source.name + ' syncs', value)
        next_sync.refresh()

    select = ui.select(CHOICES, value=minutes, label='Sync by itself', on_change=lambda e: changed(e.value))
    select.props('outlined dense').classes('min-w-[12rem]')
    next_sync()
    ws.on_refresh(next_sync.refresh)
    return select
