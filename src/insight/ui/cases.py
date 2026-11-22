"""The Cases tab (TIP 3.8, ADR 0029): open an investigation, collect what belongs to it, close it with a note.

"Add to case" in the reader and the entity explorer opens :func:`open_add_to_case`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import CaseInput, CaseItemInput, CaseItemKind, CaseStatusFilter
from .actors import _labels
from .case_detail import open_case_dialog
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

STATUSES: Final[dict[CaseStatusFilter, str]] = {
    'open': 'Open cases',
    'closed': 'Closed cases',
    'all': 'All cases',
}
NEW: Final = '__new__'


def _create(ws: Workspace, title: str, summary: str, label: str) -> str:
    item = CaseInput.model_validate({'title': title, 'summary': summary, 'tlp': label})
    with ws.write() as db:
        return services.create_case(db, item, max_tlp=ws.app.state.settings.max_tlp).id


def _new_case(ws: Workspace, saved: Callable[[str], object]) -> None:
    if not ws.authorized():
        return
    labels, start = _labels(ws)
    with ui.dialog().props('aria-label="Open a case"') as dialog, ui.card().classes('dialog-card w-full'):
        heading('Open a case', 2)
        title = ui.input('What are you looking into?').props('outlined maxlength=200').mark('case-title')
        summary = ui.textarea('Summary (optional)').props('outlined maxlength=10000')
        label = ui.select(labels, value=start, label='Sharing label').props('outlined')
        error = problem_area()

        def save() -> None:
            if not ws.authorized():
                return
            try:
                case_id = _create(ws, title.value or '', summary.value or '', label.value)
            except (ValidationError, ValueError):
                error.set_text('Give the case a title, and a sharing label this server allows.')
                return
            dialog.close()
            saved(case_id)
            tell('Case opened. Add reports and indicators from the reader or the entity explorer.', 'success')

        with ui.row():
            ui.button('Open case', on_click=save).mark('case-save')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def build_cases(ws: Workspace) -> None:
    status: dict[str, CaseStatusFilter] = {'value': 'open'}
    # Dialogs live here, not inside the list: refreshing the list would delete an open dialog with it.
    holder = ui.element('div')

    def show(case_id: str) -> None:
        holder.clear()
        with holder:
            open_case_dialog(ws, case_id, changed=ws.refresh_all)

    def created(case_id: str) -> None:
        listing.refresh()
        show(case_id)

    def choose(value: CaseStatusFilter) -> None:
        status['value'] = value
        listing.refresh()

    @ui.refreshable
    def listing() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            found = services.list_cases(
                db, max_tlp=ws.app.state.settings.max_tlp, status=status['value'], limit=200
            )
        if not found:
            ui.label('No cases here yet.').classes('muted p-2')
            return
        for case in found:
            with ui.column().classes('panel w-full p-3 gap-1 min-w-0').mark(f'case-{case.id}'):
                with ui.row().classes('w-full items-center gap-2'):
                    ui.button(case.title, on_click=lambda c=case.id: show(c)).props(
                        'flat dense no-caps align=left'
                    ).classes('font-semibold break-value text-left')
                    tlp_badge(case.tlp)
                    if case.status == 'closed':
                        ui.badge('Closed').props('outline')
                items = 'item' if case.items == 1 else 'items'
                ui.label(f'{case.items} {items} · changed {case.updated_at[:10]}').classes('muted text-sm')

    heading('Cases', 1)
    ui.label(
        'A case groups the reports, indicators, actors and campaigns of one investigation, with your notes. '
        'Its label is the strictest of what it holds. Close it with a note when you are done.'
    ).classes('muted prose')
    with ui.row().classes('items-center gap-4'):
        ui.button('＋ Open a case', on_click=lambda: _new_case(ws, created)).mark('case-new')
        ui.select(STATUSES, value='open', label='Show', on_change=lambda e: choose(e.value)).props(
            'outlined dense'
        ).classes('min-w-40').mark('case-status')
    ws.on_refresh(listing.refresh)
    with ui.column().classes('w-full gap-2 mt-2'):
        listing()


def open_add_to_case(ws: Workspace, kind: CaseItemKind, target_id: str, name: str) -> None:
    """Add a report or indicator to an open case, or to a new one."""
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ws.read() as db:
        found = services.list_cases(db, max_tlp=limit, status='open', limit=200)
    choices = {c.id: f'{c.title} · TLP:{c.tlp}' for c in found} | {NEW: 'A new case…'}
    labels, start = _labels(ws)
    with ui.dialog().props('aria-label="Add to case"') as dialog, ui.card().classes('dialog-card w-full'):
        heading('Add to case', 2)
        ui.label(name).classes('break-value')
        target = (
            ui.select(choices, value=next(iter(choices)), label='Case').props('outlined').mark('case-pick')
        )
        title = ui.input('New case title').props('outlined maxlength=200').mark('case-new-title')
        label = ui.select(labels, value=start, label='New case sharing label').props('outlined')
        title.bind_visibility_from(target, 'value', value=NEW)
        label.bind_visibility_from(target, 'value', value=NEW)
        error = problem_area()

        def add() -> None:
            if not ws.authorized():
                return
            try:
                case_id = (
                    _create(ws, title.value or '', '', label.value) if target.value == NEW else target.value
                )
                with ws.write() as db:
                    item = CaseItemInput(kind=kind, target_id=target_id)
                    services.add_case_item(db, case_id, item, max_tlp=limit)
            except (ValidationError, ValueError, LookupError) as exc:
                error.set_text(
                    str(exc) if isinstance(exc, services.CaseClosed) else 'Choose a case or give a title.'
                )
                return
            dialog.close()
            ws.refresh_all()
            tell(f'Added this {kind_label(kind)} to the case.', 'success')

        with ui.row():
            ui.button('Add', on_click=add).mark('case-add')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def kind_label(kind: str) -> str:
    return {'document': 'report', 'indicator': 'indicator', 'actor': 'actor', 'campaign': 'campaign'}.get(
        kind, kind
    )
