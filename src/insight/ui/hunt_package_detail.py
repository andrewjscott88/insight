"""One hunt package (TIP 4.3, ADR 0034): its hypothesis and items, adding techniques, indicators and rules,
publishing and retiring it, and the STIX download."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..permissions import Permission
from ..schemas import HuntPackageItemInput, HuntPackageItemKind, HuntPackageUpdate
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .workspace import Workspace

KINDS: Final = {'technique': 'Technique', 'indicator': 'Indicator', 'rule': 'Rule', 'document': 'Report'}
STATUS_TEXT: Final = {'draft': 'Draft', 'published': 'Published', 'retired': 'Retired'}
STATUS_HELP: Final = {
    'draft': 'Only you can see a draft. Publish it when it is ready for your hunt tools.',
    'published': 'Hunt tools get this package, and every change you make to it, from the feed.',
    'retired': 'Hunt tools are told this package no longer applies. Publish it again to change it.',
}


def _indicator_id(ws: Workspace, value: str) -> str:
    """The ID of the indicator with exactly this value (``LookupError`` if no report you can see has it)."""
    wanted = value.strip().casefold()
    with ws.read() as db:
        for entity, _ in services.list_entities(db, value.strip(), 20, max_tlp=ws.app.state.settings.max_tlp):
            if entity.value.casefold() == wanted:
                return str(entity.id)
    raise LookupError('No such indicator')


def open_hunt_package_dialog(ws: Workspace, package_id: str, *, changed: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ui.dialog().props('aria-label="Hunt package"') as dialog, ui.card().classes('dialog-card w-full'):

        def write(action: Callable[[Any], object], done: str) -> None:
            if not ws.allowed(Permission.HUNTING):
                return
            try:
                with ws.write(Permission.HUNTING) as db:
                    action(db)
            except services.HuntPackageConflict as exc:
                error.set_text(str(exc))
                return
            except LookupError:
                error.set_text('That was not found. Check the ID or the value.')
                return
            except (ValidationError, ValueError):
                error.set_text('That could not be saved. Check the text and its sharing label.')
                return
            error.set_text('')
            body.refresh()
            changed()
            tell(done, 'success')

        def add(kind: HuntPackageItemKind, target: Callable[[], str]) -> None:
            def action(db: Any) -> object:
                item = HuntPackageItemInput(kind=kind, target_id=target())
                return services.add_hunt_package_item(db, package_id, item, max_tlp=limit)

            write(action, f'{KINDS[kind]} added. The package label is at least as strict as it.')

        def save(title: str, hypothesis: str) -> None:
            payload = HuntPackageUpdate(title=title, hypothesis=hypothesis)
            write(lambda db: services.update_hunt_package(db, package_id, payload, max_tlp=limit), 'Saved.')

        @ui.refreshable
        def body() -> None:
            try:
                with ws.read() as db:
                    view = services.get_hunt_package(db, package_id, max_tlp=limit)
                    rules = services.list_rules(db, max_tlp=limit)
            except LookupError:
                ui.label('This hunt package no longer exists.').classes('muted')
                return
            editable = view.status != 'retired'
            heading(view.title, 2)
            with ui.row().classes('items-center gap-2'):
                tlp_badge(view.tlp)
                ui.badge(STATUS_TEXT[view.status]).props('outline').mark('hunt-package-status')
                if view.group_name:
                    ui.label(f'Threat group: {view.group_name}').classes('muted')
            ui.label(STATUS_HELP[view.status]).classes('muted prose')
            if editable:
                title = ui.input('Title', value=view.title).props('outlined maxlength=200')
                hypothesis = ui.textarea('Hypothesis', value=view.hypothesis).props(
                    'outlined maxlength=10000'
                )
                ui.button(
                    'Save changes', on_click=lambda: save(title.value or '', hypothesis.value or '')
                ).props('outline').mark('hunt-edit-save')
            else:
                ui.label(view.hypothesis).classes('prose break-value')

            heading('In this package', 3)
            if not view.items:
                ui.label('Nothing yet. Add what the hunt needs below.').classes('muted')
            for item in view.items:
                with ui.row().classes('items-center gap-2 w-full').mark(f'hunt-item-{item.target_id}'):
                    ui.label(f'{KINDS[item.kind]} · {item.name or item.target_id}').classes('break-value')
                    tlp_badge(item.tlp)
                    if editable:
                        ui.button(
                            'Remove',
                            on_click=lambda i=item: write(
                                lambda db: services.remove_hunt_package_item(
                                    db, package_id, i.id, max_tlp=limit
                                ),
                                'Removed. The package keeps its label.',
                            ),
                        ).props('flat dense no-caps')
            if editable:
                heading('Add to this package', 3)
                with ui.row().classes('items-center gap-2 w-full'):
                    technique = ui.input('Technique ID, such as T1059.001').props(
                        'outlined dense maxlength=16'
                    )
                    ui.button(
                        'Add technique', on_click=lambda: add('technique', lambda: technique.value or '')
                    ).props('outline no-caps').mark('hunt-add-technique')
                with ui.row().classes('items-center gap-2 w-full'):
                    value = ui.input('Indicator, such as an address or a domain').props('outlined dense')
                    ui.button(
                        'Add indicator',
                        on_click=lambda: add('indicator', lambda: _indicator_id(ws, value.value or '')),
                    ).props('outline no-caps').mark('hunt-add-indicator')
                if rules:
                    with ui.row().classes('items-center gap-2 w-full'):
                        options = {r.rule.id: f'{r.rule.name} · {r.rule.kind}' for r in rules}
                        rule = (
                            ui.select(options, label='Saved rule').props('outlined dense').classes('min-w-60')
                        )
                        ui.button('Add rule', on_click=lambda: add('rule', lambda: rule.value or '')).props(
                            'outline no-caps'
                        ).mark('hunt-add-rule')
                ui.label('Add reports from the reader with "Add to hunt package".').classes('muted prose')

            heading('Share', 3)
            with ui.row().classes('items-center gap-4'):
                if view.status != 'published':
                    ui.button(
                        'Publish',
                        on_click=lambda: write(
                            lambda db: services.publish_hunt_package(db, package_id, max_tlp=limit),
                            'Published. Hunt tools get it from the feed.',
                        ),
                    ).mark('hunt-publish')
                else:
                    ui.button(
                        'Retire',
                        on_click=lambda: write(
                            lambda db: services.retire_hunt_package(db, package_id, max_tlp=limit),
                            'Retired. Hunt tools are told it no longer applies.',
                        ),
                    ).props('outline').mark('hunt-retire')
                new_tab_link('Download as STIX', f'/api/hunt-packages/{package_id}/stix')

        def delete() -> None:
            if not ws.allowed(Permission.HUNTING):
                return
            try:
                with ws.write(Permission.HUNTING) as db:
                    services.delete_hunt_package(db, package_id, max_tlp=limit)
            except services.HuntPackageConflict as exc:
                confirm.close()
                error.set_text(str(exc))
                return
            except LookupError:
                pass
            confirm.close()
            dialog.close()
            changed()
            tell('Package deleted. What it held stays in Insight.', 'success')

        with (
            ui.dialog().props('aria-label="Delete hunt package"') as confirm,
            ui.card().classes('dialog-card'),
        ):
            ui.label('Delete this hunt package? What it holds stays in Insight.').classes('prose')
            with ui.row():
                ui.button('Delete package', on_click=delete).props('color=negative').mark(
                    'hunt-delete-confirm'
                )
                ui.button('Keep it', on_click=confirm.close).props('flat')

        body()
        error = problem_area()
        with ui.row():
            ui.button('Done', on_click=dialog.close)
            ui.button('Delete package…', on_click=confirm.open).props('flat no-caps').mark('hunt-delete')
    dialog.open()
