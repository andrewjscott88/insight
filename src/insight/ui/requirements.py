"""The Requirements section (TIP 4.1, ADR 0032): the questions your intelligence work answers.

Priority intelligence requirements (PIRs) with the narrower requirements under them, and requests for
information (RFIs) from people or other tools. Each shows how many recent reports address it, so a requirement
that has gone quiet stands out.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..permissions import Permission
from ..schemas import RequirementInput, RequirementStatusFilter
from .actors import _labels
from .messages import problem_area, tell
from .requirement_detail import open_requirement_dialog
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

KINDS: Final = {
    'pir': 'Priority requirement (PIR)',
    'ir': 'Narrower requirement (under a PIR)',
    'rfi': 'Request for information (RFI)',
}
SHORT: Final = {'pir': 'PIR', 'ir': 'IR', 'rfi': 'RFI'}
PRIORITIES: Final = {'high': 'High', 'medium': 'Medium', 'low': 'Low'}
STATUSES: Final[dict[RequirementStatusFilter, str]] = {
    'open': 'Open',
    'answered': 'Answered requests',
    'retired': 'Retired',
    'all': 'All',
}


def coverage_text(summary: services.RequirementSummary) -> str:
    if summary.kind == 'rfi' and summary.status == 'answered':
        return 'Answered'
    if not summary.criteria_count:
        return 'No criteria yet: add what makes a report relevant'
    if summary.quiet:
        return f'Quiet: no report in {services.QUIET_DAYS} days'
    reports = 'report' if summary.recent_matches == 1 else 'reports'
    return f'{summary.recent_matches} {reports} in {services.QUIET_DAYS} days'


def _new_requirement(ws: Workspace, saved: Callable[[str], object]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ws.read() as db:
        pirs = {p.id: p.question for p in services.list_requirements(db, max_tlp=limit, kind='pir')}
    labels, start = _labels(ws)
    with ui.dialog().props('aria-label="New requirement"') as dialog, ui.card().classes('dialog-card w-full'):
        heading('New requirement', 2)
        kind = ui.select(KINDS, value='pir', label='Kind').props('outlined').mark('req-kind')
        parent = ui.select(pirs, label='Under which PIR?').props('outlined').mark('req-parent')
        parent.bind_visibility_from(kind, 'value', value='ir')
        question = ui.input('The question').props('outlined maxlength=300').mark('req-question')
        context = ui.textarea('Why it matters, or the decision it supports (optional)').props(
            'outlined maxlength=10000'
        )
        stakeholder = ui.input('Who needs the answer (optional)').props('outlined maxlength=120')
        priority = ui.select(PRIORITIES, value='medium', label='Priority').props('outlined')
        label = ui.select(labels, value=start, label='Sharing label').props('outlined')
        error = problem_area()

        def save() -> None:
            if not ws.allowed(Permission.REQUIREMENTS):
                return
            try:
                item = RequirementInput.model_validate(
                    {
                        'kind': kind.value,
                        'question': question.value or '',
                        'context': context.value or '',
                        'stakeholder': stakeholder.value or '',
                        'priority': priority.value,
                        'tlp': label.value,
                        'parent_id': parent.value if kind.value == 'ir' else None,
                    }
                )
                with ws.write(Permission.REQUIREMENTS) as db:
                    requirement_id = services.create_requirement(db, item, max_tlp=limit).id
            except (ValidationError, ValueError, LookupError):
                error.set_text(
                    'Write the question (at least five letters). A narrower requirement needs its PIR.'
                )
                return
            dialog.close()
            saved(requirement_id)
            tell('Requirement added. Now add what makes a report relevant to it.', 'success')

        with ui.row():
            ui.button('Add requirement', on_click=save).mark('req-save')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def _row(summary: services.RequirementSummary, show: Callable[[str], None], *, nested: bool = False) -> None:
    with (
        ui.column()
        .classes(f'panel w-full p-3 gap-1 min-w-0 {"ml-6" if nested else ""}')
        .mark(f'req-{summary.id}')
    ):
        with ui.row().classes('w-full items-center gap-2'):
            ui.badge(SHORT[summary.kind]).props('outline')
            ui.button(summary.question, on_click=lambda: show(summary.id)).props(
                'flat dense no-caps align=left'
            ).classes('font-semibold break-value text-left')
            tlp_badge(summary.tlp)
            if summary.priority == 'high':
                ui.badge('High priority').classes('bg-negative')
        details = [coverage_text(summary)]
        if summary.stakeholder:
            details.append(f'for {summary.stakeholder}')
        if summary.due_at:
            details.append(f'due {summary.due_at[:10]}')
        ui.label(' · '.join(details)).classes('muted text-sm' + (' text-warning' if summary.quiet else ''))


def build_requirements(ws: Workspace, *, embedded: bool = False) -> None:
    status: dict[str, RequirementStatusFilter] = {'value': 'open'}
    # Dialogs live here, not inside the list: refreshing the list would delete an open dialog with it.
    holder = ui.element('div')

    def show(requirement_id: str) -> None:
        holder.clear()
        with holder:
            open_requirement_dialog(ws, requirement_id, changed=ws.refresh_all)

    ws.show_requirement = show

    def created(requirement_id: str) -> None:
        listing.refresh()
        show(requirement_id)

    def choose(value: RequirementStatusFilter) -> None:
        status['value'] = value
        listing.refresh()

    @ui.refreshable
    def listing() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            found = services.list_requirements(
                db, max_tlp=ws.app.state.settings.max_tlp, status=status['value']
            )
        if not found:
            ui.label('No requirements here yet.').classes('muted p-2')
            return
        children: dict[str, list[services.RequirementSummary]] = {}
        for summary in found:
            if summary.parent_id:
                children.setdefault(summary.parent_id, []).append(summary)
        shown = {s.id for s in found}
        for title, kinds in (
            ('Priority requirements', ('pir', 'ir')),
            ('Requests for information', ('rfi',)),
        ):
            group = [s for s in found if s.kind in kinds and (not s.parent_id or s.parent_id not in shown)]
            if not group:
                continue
            heading(title, 3 if embedded else 2, 'subsection-title')
            for summary in group:
                _row(summary, show)
                for child in children.get(summary.id, []):
                    _row(child, show, nested=True)

    heading('Intelligence questions' if embedded else 'Requirements', 2 if embedded else 1)
    ui.label(
        'The questions your intelligence work answers. A report addresses a requirement when it meets one of '
        'its criteria: a term, a CVE, an ATT&CK technique, a threat group or a campaign.'
    ).classes('muted prose')
    with ui.row().classes('items-center gap-4'):
        if ws.can(Permission.REQUIREMENTS):
            ui.button('＋ New requirement', on_click=lambda: _new_requirement(ws, created)).mark('req-new')
        ui.select(STATUSES, value='open', label='Show', on_change=lambda e: choose(e.value)).props(
            'outlined dense'
        ).classes('min-w-40').mark('req-status')
    ws.on_refresh(listing.refresh)
    with ui.column().classes('w-full gap-2 mt-2'):
        listing()
