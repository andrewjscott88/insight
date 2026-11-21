"""The hunt plan in a threat guide (TIP 2.10, ADR 0025): hypotheses, the sweep list, rules and hunt records.

Hypotheses come from ATT&CK's detection strategies and data components; they are starting points, not
detections. A hunt record keeps, for each hypothesis, what was searched, over which dates and what was found.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import TLP_LEVELS, HuntCheckInput, HuntInput, HuntUpdate
from ..threat_guide import ThreatGuide
from .messages import problem_area, tell
from .rules import render_rules
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .workspace import Workspace

SHOWN_HYPOTHESES: Final = 15
SHOWN_SWEEP: Final = 20
RESULT_NAMES: Final = {
    'not-checked': 'Not checked yet',
    'nothing-found': 'Nothing found',
    'suspicious': 'Something to look at',
    'confirmed': 'Found it',
}


def render_hunt_plan(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    heading('Hunt plan', 3, 'subsection-title mt-3')
    ui.label(
        'Ideas to start a hunt. Each one says what the group may do and which logs to search. '
        'They come from ATT&CK. They are not alerts: check each one in your own data.'
    ).classes('muted prose')
    for item in guide.hypotheses[:SHOWN_HYPOTHESES]:
        with ui.expansion(f'{item.technique_id} {item.technique_name}').classes('w-full break-value'):
            ui.label(item.statement).classes('prose')
            if item.why_first:
                ui.label(f'Why it is near the top: {item.why_first}.').classes('muted text-sm')
            if item.from_parent:
                ui.label('These detection ideas are for the main technique.').classes('muted text-sm')
            for strategy in item.detections[:3]:
                new_tab_link(f'Detection idea: {strategy.name}', strategy.url)
    if len(guide.hypotheses) > SHOWN_HYPOTHESES:
        ui.label(f'{len(guide.hypotheses) - SHOWN_HYPOTHESES} more are in the downloaded guide.').classes(
            'muted'
        )
    _sweep(guide)
    render_rules(ws, guide, refresh)
    _hunts(ws, guide, refresh)


def _sweep(guide: ThreatGuide) -> None:
    sweep = guide.data.sweep
    heading(f'Indicators to search for ({len(sweep)})', 4)
    ui.label(
        'Accepted indicators from the reports you linked to this group. Search your logs for them. They show '
        'where to look, not who did it. Reports that only name the group are left out; the second sweep list '
        'download includes them.'
        if guide.data.sweep_linked_only
        else 'Accepted indicators from the reports above, including reports that only name the group. Search '
        'your logs for them. They show where to look, not who did it.'
    ).classes('muted prose')
    for entry in sweep[:SHOWN_SWEEP]:
        ui.label(f'{entry.kind} · {entry.value} · seen {entry.last_seen[:10]}').classes(
            'font-mono text-sm break-value'
        )
    if len(sweep) > SHOWN_SWEEP:
        ui.label(f'{len(sweep) - SHOWN_SWEEP} more are in the sweep list download.').classes('muted text-sm')


def _hunts(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    heading(f'Hunt records ({len(guide.data.hunts)})', 4)
    ui.label('Keep track of what you searched, so the next hunt can start where this one ended.').classes(
        'muted prose'
    )
    ui.button('Start a hunt', icon='add', on_click=lambda: _start_dialog(ws, guide, refresh)).props(
        'outline no-caps'
    )
    techniques = [h.technique_id for h in guide.hypotheses[:SHOWN_HYPOTHESES]]
    for view in guide.data.hunts:
        hunt = view.hunt
        with ui.expansion(f'{hunt.title} · {hunt.status} · started {hunt.created_at[:10]}').classes('w-full'):
            tlp_badge(hunt.tlp)
            for tid in dict.fromkeys([*view.checks, *techniques]):
                _check_row(ws, hunt.id, tid, view.checks.get(tid), hunt.status == 'open', refresh)
            _close_row(ws, hunt.id, hunt.status, hunt.summary, refresh)


def _check_row(
    ws: Workspace,
    hunt_id: str,
    technique_id: str,
    saved: tuple[str, str, str, str, str] | None,
    editable: bool,
    refresh: Callable[[], Any],
) -> None:
    result, checked, start, end, notes = saved or ('not-checked', '', '', '', '')
    with ui.column().classes('panel w-full p-3 gap-2'):
        ui.label(technique_id).classes('font-medium')
        choice = ui.select(RESULT_NAMES, value=result, label='Result').props('outlined dense').classes('w-60')
        data = (
            ui.input('Data you searched', value=checked)
            .props('outlined dense maxlength=2000')
            .classes('w-full')
        )
        with ui.row().classes('gap-3'):
            first = ui.input('From, such as 2026-10-01', value=start).props('outlined dense maxlength=10')
            last = ui.input('To, such as 2026-10-31', value=end).props('outlined dense maxlength=10')
        note = ui.textarea('Notes', value=notes).props('outlined dense maxlength=10000').classes('w-full')
        problem = problem_area()

        def save() -> None:
            if not ws.authorized():
                return
            try:
                payload = HuntCheckInput(
                    result=choice.value,
                    data_checked=data.value or '',
                    period_start=date.fromisoformat(first.value) if first.value else None,
                    period_end=date.fromisoformat(last.value) if last.value else None,
                    notes=note.value or '',
                )
                with ws.write() as db:
                    services.record_check(db, hunt_id, technique_id, payload)
            except (ValidationError, ValueError) as exc:
                problem.set_text(_plain_problem(exc))
                return
            except LookupError:
                tell('This hunt no longer exists.', 'warning')
                return
            refresh()
            tell(f'Saved the check of {technique_id}.', 'success')

        if editable:
            ui.button('Save this check', on_click=save).props('outline dense no-caps').mark(
                f'save-check-{technique_id}'
            )


def _plain_problem(exc: Exception) -> str:
    if isinstance(exc, ValidationError) or 'isoformat' in str(exc) or 'Invalid' in str(exc):
        return 'Check the dates. Write them as year, month, day, such as 2026-10-31.'
    return str(exc)


def _close_row(ws: Workspace, hunt_id: str, status: str, summary: str, refresh: Callable[[], Any]) -> None:
    text = (
        ui.textarea('What the hunt found', value=summary).props('outlined maxlength=10000').classes('w-full')
    )

    def save(new_status: str) -> None:
        if not ws.authorized():
            return
        try:
            with ws.write() as db:
                services.update_hunt(
                    db,
                    hunt_id,
                    HuntUpdate.model_validate({'status': new_status, 'summary': text.value or ''}),
                )
        except LookupError:
            tell('This hunt no longer exists.', 'warning')
            return
        refresh()
        tell('Hunt saved.', 'success')

    if status == 'open':
        ui.button('Close the hunt', on_click=lambda: save('closed')).props('outline no-caps')
    else:
        ui.button('Open the hunt again', on_click=lambda: save('open')).props('flat no-caps')


def _start_dialog(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with (
        ui.dialog().props('aria-label="Start a hunt"') as dialog,
        ui.card().classes('panel dialog-card p-6 gap-3'),
    ):
        heading('Start a hunt', 2)
        title = ui.input('Name of the hunt', value=f'{guide.name} hunt').props(
            'outlined maxlength=200 autofocus'
        )
        label = ui.select(
            [t for t in TLP_LEVELS if services.tlp_permitted(t, limit)], value=min_label(limit), label='TLP'
        )
        label.props('outlined')
        problem = problem_area()

        def start() -> None:
            if not ws.authorized():
                return
            try:
                payload = HuntInput(title=title.value or '', tlp=label.value)
                with ws.write() as db:
                    services.start_hunt(db, guide.data.subject.ref, payload, max_tlp=limit)
            except ValidationError:
                problem.set_text('Give the hunt a name.')
                return
            except (LookupError, services.TlpNotPermitted) as exc:
                problem.set_text(str(exc))
                return
            dialog.close()
            refresh()
            tell('Hunt started. Record each check as you go.', 'success')

        with ui.row():
            ui.button('Start', on_click=start).mark('start-hunt')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def min_label(limit: str) -> str:
    """The label a new record starts with: AMBER, or the instance limit when that is stricter."""
    return services.stricter_limit('AMBER', limit) or 'AMBER'
