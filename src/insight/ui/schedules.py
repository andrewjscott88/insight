"""Schedule controls in the Sources tab: how often each source syncs by itself (off unless you choose), and at
what time of day (UTC) the schedules start."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

from nicegui import ui

from .. import services
from ..source_registry import SOURCES, in_use, is_operator_source
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
    redraw: dict[str, Callable[[], object]] = field(default_factory=dict)


def _interval(ws: Workspace, key: str) -> tuple[int, str | None]:
    with ws.read() as db:
        schedule = services.list_schedules(db).get(key)
    if schedule is None or not schedule.enabled:
        return 0, None
    return schedule.interval_minutes, schedule.next_run_at


def _in_use(ws: Workspace) -> list[str]:
    """Keys of the sources Insight may contact: a schedule for every source covers only these."""
    with ws.read() as db:
        switches = services.source_switches(db)
        operator = services.list_operator_sources(db, max_tlp=ws.app.state.settings.max_tlp)
    return [key for key, source in SOURCES.items() if in_use(source, switches)] + [
        source.key for source in operator if source.enabled
    ]


def _save(ws: Workspace, keys: list[str], minutes: int | None, start: str) -> list[str]:
    """For a new start time, keep the current interval. Recheck each custom feed in the write transaction."""
    now = datetime.now(UTC)
    starts_at = services.time_of_day(start, now) if start != SOON else None
    saved = []
    with ws.write() as db:
        schedules = services.list_schedules(db) if minutes is None else {}
        for key in keys:
            interval = minutes
            if interval is None:
                schedule = schedules.get(key)
                if schedule is None or not schedule.enabled:
                    continue
                interval = schedule.interval_minutes
            limit = ws.app.state.settings.max_tlp
            try:
                if not interval and is_operator_source(key):
                    # A disabled schedule still needs a visible source; enabling is checked in set_schedule.
                    services.get_operator_source(db, key, max_tlp=limit, lock=True)
                services.set_schedule(db, key, interval, at=now, starts_at=starts_at, max_tlp=limit)
            except (LookupError, ValueError):
                # A feed or its credentials can change after the page is shown.
                continue
            saved.append(key)
    return saved


def _confirm(ws: Workspace, what: str, minutes: int, start: str, *, plural: bool = False) -> None:
    itself = 'by themselves' if plural else 'by itself'
    if not minutes:
        tell(f'{what} now only when you press Sync now.', 'success')
    elif not ws.app.state.settings.run_jobs:
        tell(
            'The schedule is saved, but this server does not run scheduled syncs (INSIGHT_RUN_JOBS is off).',
            'warning',
        )
    elif start == SOON:
        tell(f'{what} {itself} {CHOICES[minutes].lower()}. The first sync starts within a minute.', 'success')
    else:
        tell(f'{what} {itself} {CHOICES[minutes].lower()}, starting at {start} UTC.', 'success')


def build_all_sources_schedule(ws: Workspace, controls: ScheduleControls) -> None:
    """The start time, and one control that sets every source's schedule at once."""

    def redraw() -> None:
        for refresh in controls.redraw.values():
            refresh()

    def start_changed(start: str | None) -> None:
        if start is None or not ws.authorized():
            return
        controls.start = start
        if start != SOON and _save(ws, _in_use(ws), None, start):
            tell(f'Schedules that are on now run from {start} UTC.', 'success')
            redraw()

    def changed(minutes: int | None) -> None:
        if minutes is None or not ws.authorized():
            return
        keys = _in_use(ws)
        saved = _save(ws, keys, minutes, controls.start)
        for key in saved:
            # Each source's own control runs nothing new for an unchanged value.
            if select := controls.selects.get(key):
                select.set_value(minutes)
        if len(saved) == len(keys):
            _confirm(ws, 'All sources you use sync', minutes, controls.start, plural=True)
        else:
            tell('Saved schedules for feeds that are ready. Check settings for the other feeds.', 'warning')
        redraw()

    with ui.row().classes('items-center gap-3 flex-wrap'):
        ui.select(
            START_TIMES, value=SOON, label='Start at', on_change=lambda e: start_changed(e.value)
        ).props('outlined dense').classes('min-w-[12rem]')
        ui.select(
            CHOICES, label='Sync all sources you use by themselves', on_change=lambda e: changed(e.value)
        ).props('outlined dense').classes('min-w-[16rem]')
    ui.label(
        'Times are in UTC. A schedule repeats from its start time, so a daily sync keeps its hour.'
    ).classes('muted text-sm prose')


def build_schedule_control(
    ws: Workspace, key: str, name: str, controls: ScheduleControls, *, configured: bool = True
) -> ui.select:
    """A source's schedule choice, and when it next syncs by itself."""
    minutes, _ = _interval(ws, key)

    @ui.refreshable
    def next_sync() -> None:
        current, upcoming = _interval(ws, key)
        when = f'Next sync: {upcoming[:16].replace("T", " ")} UTC' if current and upcoming else ''
        ui.label(when or 'Syncs only when you ask.').classes('muted text-sm')

    def changed(value: int | None) -> None:
        if value is None or not ws.authorized() or value == _interval(ws, key)[0]:
            next_sync.refresh()
            return
        if not _save(ws, [key], value, controls.start):
            ws.refresh_all()
            tell('This source has changed. Check it before you set a schedule.', 'warning')
            return
        if not configured and value == 0:
            select.disable()
        _confirm(ws, name + ' syncs', value, controls.start)
        next_sync.refresh()

    choices = CHOICES if configured else {k: v for k, v in CHOICES.items() if k in (0, minutes)}
    select = ui.select(choices, value=minutes, label='Sync by itself', on_change=lambda e: changed(e.value))
    select.props('outlined dense').classes('min-w-[12rem]')
    next_sync()
    controls.selects[key] = select
    controls.redraw[key] = next_sync.refresh
    return select
