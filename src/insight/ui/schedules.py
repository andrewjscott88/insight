"""Schedule controls in the Sources tab: how often each source syncs by itself (off unless you choose), and at
what time of day (UTC) the schedules start."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

from nicegui import ui

from .. import services
from ..connectors import SOURCES, Source
from .messages import tell
from .workspace import Workspace

#: Choices shown for :data:`insight.services.SCHEDULE_INTERVALS` (minutes).
CHOICES: Final = {0: 'Off', 60: 'Every hour', 360: 'Every 6 hours', 1440: 'Every day'}
SOON: Final = 'soon'
START_TIMES: Final = {SOON: 'As soon as possible'} | {f'{h:02d}:00': f'{h:02d}:00 UTC' for h in range(24)}


@dataclass
class ScheduleControls:
    """What the Sources tab's schedule controls share: the chosen start time and how to redraw them."""

    start: str = SOON
    selects: dict[str, ui.select] = field(default_factory=dict)
    redraw: list[Callable[[], object]] = field(default_factory=list)


def _interval(ws: Workspace, key: str) -> tuple[int, str | None]:
    with ws.read() as db:
        schedule = services.list_schedules(db).get(key)
    if schedule is None or not schedule.enabled:
        return 0, None
    return schedule.interval_minutes, schedule.next_run_at


def _save(ws: Workspace, keys: list[str], minutes: int, start: str) -> None:
    now = datetime.now(UTC)
    starts_at = services.time_of_day(start, now) if start != SOON else None
    with ws.write() as db:
        for key in keys:
            services.set_schedule(db, key, minutes, at=now, starts_at=starts_at)


def _confirm(ws: Workspace, what: str, minutes: int, start: str) -> None:
    if not minutes:
        tell(f'{what} now only when you press Sync now.', 'success')
    elif not ws.app.state.settings.run_jobs:
        tell(
            'The schedule is saved, but this server does not run scheduled syncs (INSIGHT_RUN_JOBS is off).',
            'warning',
        )
    elif start == SOON:
        tell(
            f'{what} by itself {CHOICES[minutes].lower()}. The first sync starts within a minute.', 'success'
        )
    else:
        tell(f'{what} by itself {CHOICES[minutes].lower()}, starting at {start} UTC.', 'success')


def build_all_sources_schedule(ws: Workspace, controls: ScheduleControls) -> None:
    """The start time, and one control that sets every source's schedule at once."""

    def redraw() -> None:
        for refresh in controls.redraw:
            refresh()

    def start_changed(start: str | None) -> None:
        if start is None or not ws.authorized():
            return
        controls.start = start
        on = [key for key in SOURCES if _interval(ws, key)[0]]
        if start != SOON and on:
            with ws.write() as db:
                for key in on:
                    services.set_schedule(
                        db, key, _interval(ws, key)[0], at=datetime.now(UTC),
                        starts_at=services.time_of_day(start, datetime.now(UTC)),
                    )  # fmt: skip
            tell(f'Schedules that are on now run from {start} UTC.', 'success')
            redraw()

    def changed(minutes: int | None) -> None:
        if minutes is None or not ws.authorized():
            return
        _save(ws, list(SOURCES), minutes, controls.start)
        for select in controls.selects.values():
            select.set_value(minutes)  # Each source's own control runs nothing new for an unchanged value.
        _confirm(ws, 'All sources sync', minutes, controls.start)
        redraw()

    with ui.row().classes('items-center gap-3 flex-wrap'):
        ui.select(
            START_TIMES, value=SOON, label='Start at', on_change=lambda e: start_changed(e.value)
        ).props('outlined dense').classes('min-w-[12rem]')
        ui.select(
            CHOICES, label='Sync all sources by themselves', on_change=lambda e: changed(e.value)
        ).props('outlined dense').classes('min-w-[16rem]')
    ui.label(
        'Times are in UTC. A schedule repeats from its start time, so a daily sync keeps its hour.'
    ).classes('muted text-sm prose')


def build_schedule_control(ws: Workspace, source: Source, controls: ScheduleControls) -> ui.select:
    """A source's schedule choice, and when it next syncs by itself."""
    minutes, _ = _interval(ws, source.key)

    @ui.refreshable
    def next_sync() -> None:
        current, upcoming = _interval(ws, source.key)
        when = f'Next sync: {upcoming[:16].replace("T", " ")} UTC' if current and upcoming else ''
        ui.label(when or 'Syncs only when you ask.').classes('muted text-sm')

    def changed(value: int | None) -> None:
        if value is None or not ws.authorized() or value == _interval(ws, source.key)[0]:
            next_sync.refresh()
            return
        _save(ws, [source.key], value, controls.start)
        _confirm(ws, source.name + ' syncs', value, controls.start)
        next_sync.refresh()

    select = ui.select(CHOICES, value=minutes, label='Sync by itself', on_change=lambda e: changed(e.value))
    select.props('outlined dense').classes('min-w-[12rem]')
    next_sync()
    controls.selects[source.key] = select
    controls.redraw.append(lambda: next_sync.refresh())
    return select
