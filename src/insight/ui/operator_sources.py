"""RSS and Atom feeds the operator adds in Settings."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from nicegui import ui

from .. import services
from ..schemas import TLP_LEVELS, OperatorSourceInput
from .messages import problem_area, tell
from .schedules import ScheduleControls, build_schedule_control
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

_CHANGED = 'This source has changed. Close this dialog and check the current settings.'


def _editor(ws: Workspace, source: services.OperatorSourceView | None, refresh: Callable[[], object]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    choices = [label for label in TLP_LEVELS if services.tlp_permitted(label, limit)]
    default = source.tlp if source else services.stricter_limit('AMBER', limit)
    title = 'Edit feed' if source else 'Add a feed'
    with (
        ui.dialog()
        .props(f'aria-label="{title}"')
        .mark('edit-operator-feed' if source else 'add-operator-feed') as dialog,
        ui.card().classes('panel dialog-card w-[38rem] max-w-full p-5 gap-3'),
    ):
        heading(title, 2)
        name = (
            ui.input('Feed name', value=source.name if source else '')
            .props('outlined maxlength=160')
            .classes('w-full')
        )
        address = (
            ui.input('Feed web address', value=source.url if source else '')
            .props('outlined maxlength=2048')
            .classes('w-full')
        )
        ui.label('Use an https:// address. Leave out passwords and tokens.').classes('muted prose')
        tlp = ui.select(choices, value=default, label='Sharing label (TLP)').props('outlined')
        ui.label(
            'Exports include titles, dates and links. Select the box only if the publisher allows more.'
        ).classes('muted prose')
        full_text = ui.checkbox(
            'The publisher allows sharing its report text.', value=bool(source and source.reuse == 'public')
        )
        if source:
            ui.label('Changing the web address turns the feed off and stops its schedule.').classes(
                'muted prose'
            )
        problem = problem_area()

        def save() -> None:
            if not ws.authorized():
                return
            try:
                item = OperatorSourceInput.model_validate(
                    {
                        'kind': 'rss',
                        'name': name.value,
                        'url': address.value,
                        'tlp': tlp.value,
                        'reuse': 'public' if full_text.value else 'metadata',
                    }
                )
                with ws.write() as db:
                    if source is None:
                        services.create_operator_source(db, item, max_tlp=limit)
                    else:
                        current = services.get_operator_source(db, source.key, max_tlp=limit, lock=True)
                        if current.revision != source.revision:
                            raise LookupError
                        services.update_operator_source(db, source.key, item, max_tlp=limit)
            except LookupError:
                refresh()
                problem.set_text(_CHANGED)
                return
            except services.TlpNotPermitted:
                problem.set_text('Choose a sharing label this server allows.')
                return
            except ValueError:
                problem.set_text(
                    'Check the feed name and address. Use https:// and leave out any text after a ? or #.'
                )
                return
            dialog.close()
            refresh()
            tell('Feed saved.', 'success')

        with ui.row():
            ui.button('Save feed', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def _confirm_delete(
    ws: Workspace, source: services.OperatorSourceView, refresh: Callable[[], object]
) -> None:
    if not ws.authorized():
        return
    with ui.dialog().props('aria-label="Delete feed"') as dialog, ui.card().classes('dialog-card gap-3'):
        heading('Delete feed', 2)
        ui.label(source.name).classes('break-value')
        ui.label(
            'Its reports stay in Insight. Future exports can share only their titles, dates and links.'
        ).classes('muted prose')
        problem = problem_area()

        def remove() -> None:
            if not ws.authorized():
                return
            limit = ws.app.state.settings.max_tlp
            try:
                with ws.write() as db:
                    current = services.get_operator_source(db, source.key, max_tlp=limit, lock=True)
                    if current.revision != source.revision:
                        raise LookupError
                    services.delete_operator_source(db, source.key, max_tlp=limit)
            except LookupError:
                refresh()
                problem.set_text(_CHANGED)
                return
            dialog.close()
            refresh()
            tell('Feed deleted.', 'success')

        with ui.row():
            ui.button('Delete feed', on_click=remove).mark('confirm-delete-feed')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def build_operator_sources(
    ws: Workspace, controls: ScheduleControls, run: Callable[[str, ui.button], Awaitable[None]]
) -> None:
    heading('Your sources', 3, 'subsection-title mt-4')
    ui.label(
        'Add an RSS or Atom feed. It starts off. Turning it on lets Insight contact that address '
        'when you sync it, sync all sources, or give it a schedule.'
    ).classes('muted prose')
    keys: set[str] = set()

    def panel(source: services.OperatorSourceView) -> None:
        def switch(on: bool) -> None:
            nonlocal source
            if not ws.authorized():
                return
            limit = ws.app.state.settings.max_tlp
            try:
                with ws.write() as db:
                    current = services.get_operator_source(db, source.key, max_tlp=limit, lock=True)
                    if current.revision != source.revision:
                        raise LookupError
                    source = services.set_operator_source_enabled(db, source.key, on, max_tlp=limit)
            except LookupError:
                feeds.refresh()
                tell('This feed has changed. Check its settings and try again.', 'warning')
                return
            sync.set_enabled(on)
            schedule.set_enabled(on)
            if not on:
                schedule.set_value(0)
                controls.redraw[source.key]()
            tell('Feed is on.' if on else 'Feed is off. Its schedule is off too.', 'success')

        with ui.column().classes('panel w-full p-4 operator-source-card').mark(f'feed-{source.key}'):
            heading(source.name, 4)
            ui.label(source.url).classes('break-value text-sm')
            tlp_badge(source.tlp)
            ui.label(
                'The publisher allows sharing its report text.'
                if source.reuse == 'public'
                else 'Share titles, dates and links only.'
            ).classes('text-sm')
            ui.switch('Use this feed', value=source.enabled, on_change=lambda e: switch(bool(e.value)))
            with ui.row().classes('items-center gap-3 flex-wrap'):
                sync = ui.button('Sync now')
                sync.on_click(lambda: run(source.key, sync))
                sync.set_enabled(source.enabled)
                schedule = build_schedule_control(ws, source.key, source.name, controls)
                schedule.set_enabled(source.enabled)
            with ui.row():
                ui.button('Edit feed', on_click=lambda: _editor(ws, source, feeds.refresh)).props(
                    'flat no-caps'
                )
                ui.button('Delete feed', on_click=lambda: _confirm_delete(ws, source, feeds.refresh)).props(
                    'flat no-caps'
                )

    @ui.refreshable
    def feeds() -> None:
        if not ws.authorized():
            return
        for key in keys:
            controls.selects.pop(key, None)
            controls.redraw.pop(key, None)
        keys.clear()
        with ws.read() as db:
            found = services.list_operator_sources(db, max_tlp=ws.app.state.settings.max_tlp)
        for source in found:
            keys.add(source.key)
            panel(source)
        if not found:
            ui.label('You have no feeds yet.').classes('muted text-sm')

    ui.button('Add a feed', icon='add', on_click=lambda: _editor(ws, None, feeds.refresh)).props(
        'outline no-caps'
    )
    feeds()
    ws.on_refresh(feeds.refresh)
