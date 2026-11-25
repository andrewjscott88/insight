"""Saved hunt packages (TIP 4.3, ADR 0034): a hypothesis with the ATT&CK techniques, indicators, rules and
reports a hunt tool needs. Published packages go out in the Hunt packages TAXII collection.

"Add to hunt package" in the reader and the indicator explorer opens :func:`open_add_to_package`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..permissions import Permission
from ..schemas import HuntPackageInput, HuntPackageItemInput, HuntPackageItemKind, HuntPackageStatusFilter
from .actors import _labels
from .hunt_package_detail import STATUS_TEXT, open_hunt_package_dialog
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

STATUSES: Final[dict[HuntPackageStatusFilter, str]] = {
    'all': 'All packages',
    'draft': 'Drafts',
    'published': 'Published',
    'retired': 'Retired',
}
NEW: Final = '__new__'


def _create(ws: Workspace, title: str, hypothesis: str, group: str, label: str) -> str:
    payload = HuntPackageInput.model_validate(
        {'title': title, 'hypothesis': hypothesis, 'group': group.strip() or None, 'tlp': label}
    )
    with ws.write(Permission.HUNTING) as db:
        return services.create_hunt_package(db, payload, max_tlp=ws.app.state.settings.max_tlp).id


def _problem(exc: Exception) -> str:
    if isinstance(exc, LookupError):
        return 'There is no such threat group. Use a group ID such as G0016, or leave it empty.'
    return 'Give the package a title, a hypothesis and a sharing label this server allows.'


def _new_package(ws: Workspace, saved: Callable[[str], object]) -> None:
    if not ws.authorized():
        return
    labels, start = _labels(ws)
    with (
        ui.dialog().props('aria-label="New hunt package"') as dialog,
        ui.card().classes('dialog-card w-full'),
    ):
        heading('New hunt package', 2)
        title = ui.input('Title').props('outlined maxlength=200').mark('hunt-title')
        hypothesis = (
            ui.textarea('What should the hunt look for, and why?')
            .props('outlined maxlength=10000')
            .mark('hunt-hypothesis')
        )
        group = ui.input('Threat group (optional), such as G0016').props('outlined maxlength=36')
        label = ui.select(labels, value=start, label='Sharing label').props('outlined')
        error = problem_area()

        def save() -> None:
            if not ws.allowed(Permission.HUNTING):
                return
            try:
                package_id = _create(
                    ws, title.value or '', hypothesis.value or '', group.value or '', label.value
                )
            except (ValidationError, ValueError, LookupError) as exc:
                error.set_text(_problem(exc))
                return
            dialog.close()
            saved(package_id)
            tell(
                'Package saved as a draft. Add techniques, indicators and rules, then publish it.', 'success'
            )

        with ui.row():
            ui.button('Save draft', on_click=save).mark('hunt-save')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def build_hunt_packages(ws: Workspace, *, embedded: bool = False) -> Callable[[str], None]:
    status: dict[str, HuntPackageStatusFilter] = {'value': 'all'}
    # Dialogs live here, not inside the list: refreshing the list would delete an open dialog with it.
    holder = ui.element('div')

    def show(package_id: str) -> None:
        holder.clear()
        with holder:
            open_hunt_package_dialog(ws, package_id, changed=ws.refresh_all)

    def created(package_id: str) -> None:
        status['value'] = 'all'
        status_picker.set_value('all')
        listing.refresh()
        show(package_id)

    def choose(value: HuntPackageStatusFilter) -> None:
        status['value'] = value
        listing.refresh()

    @ui.refreshable
    def listing() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            found = services.list_hunt_packages(
                db, max_tlp=ws.app.state.settings.max_tlp, status=status['value']
            )
        if not found:
            ui.label('No hunt packages here yet.').classes('muted p-2')
            return
        for package in found:
            with ui.column().classes('panel w-full p-3 gap-1 min-w-0').mark(f'hunt-package-{package.id}'):
                with ui.row().classes('w-full items-center gap-2'):
                    ui.button(package.title, on_click=lambda p=package.id: show(p)).props(
                        'flat dense no-caps align=left'
                    ).classes('font-semibold break-value text-left')
                    tlp_badge(package.tlp)
                    ui.badge(STATUS_TEXT[package.status]).props('outline')
                ui.label(
                    f'{package.techniques} technique(s) · {package.indicators} indicator(s) · '
                    f'{package.rules} rule(s) · {package.documents} report(s) · '
                    f'changed {package.updated_at[:10]}'
                ).classes('muted text-sm')

    if not embedded:
        heading('Hunt packages', 2, 'subsection-title mt-6')
    ui.label(
        'Packages you save from the guide builder appear here. Open one to review its plan and evidence. '
        'Publish it when you want connected hunt tools to receive it. Or start a blank package.'
    ).classes('muted prose')
    with ui.row().classes('items-center gap-4'):
        if ws.can(Permission.HUNTING):
            ui.button('Start a blank package', icon='add', on_click=lambda: _new_package(ws, created)).props(
                'outline'
            ).mark('hunt-new')
        status_picker = (
            ui.select(STATUSES, value='all', label='Show', on_change=lambda e: choose(e.value))
            .props('outlined dense')
            .classes('min-w-40')
            .mark('hunt-status')
        )
    ws.on_refresh(listing.refresh)
    with ui.column().classes('w-full gap-2 mt-2'):
        listing()
    return created


def open_add_to_package(ws: Workspace, kind: HuntPackageItemKind, target_id: str, name: str) -> None:
    """Add a report or indicator to a draft or published package, or to a new one."""
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ws.read() as db:
        found = [p for p in services.list_hunt_packages(db, max_tlp=limit) if p.status != 'retired']
    choices = {p.id: f'{p.title} · TLP:{p.tlp}' for p in found} | {NEW: 'A new package…'}
    labels, start = _labels(ws)
    with (
        ui.dialog().props('aria-label="Add to hunt package"') as dialog,
        ui.card().classes('dialog-card w-full'),
    ):
        heading('Add to hunt package', 2)
        ui.label(name).classes('break-value')
        target = (
            ui.select(choices, value=next(iter(choices)), label='Package').props('outlined').mark('hunt-pick')
        )
        title = ui.input('New package title').props('outlined maxlength=200').mark('hunt-new-title')
        hypothesis = ui.textarea('What should the hunt look for, and why?').props('outlined maxlength=10000')
        label = ui.select(labels, value=start, label='New package sharing label').props('outlined')
        for field in (title, hypothesis, label):
            field.bind_visibility_from(target, 'value', value=NEW)
        error = problem_area()

        def add() -> None:
            if not ws.allowed(Permission.HUNTING):
                return
            try:
                package_id = (
                    _create(ws, title.value or '', hypothesis.value or '', '', label.value)
                    if target.value == NEW
                    else target.value
                )
                with ws.write(Permission.HUNTING) as db:
                    item = HuntPackageItemInput(kind=kind, target_id=target_id)
                    services.add_hunt_package_item(db, package_id, item, max_tlp=limit)
            except services.HuntPackageConflict as exc:
                error.set_text(str(exc))
                return
            except (ValidationError, ValueError, LookupError):
                error.set_text('Choose a package, or give a new one a title and a hypothesis.')
                return
            dialog.close()
            ws.refresh_all()
            word = 'report' if kind == 'document' else 'indicator'
            tell(f'Added this {word} to the hunt package.', 'success')

        with ui.row():
            ui.button('Add', on_click=add).mark('hunt-add')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()
