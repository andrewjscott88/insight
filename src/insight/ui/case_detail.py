"""One case (TIP 3.8, ADR 0029): what it holds, notes, timeline, and closing or reopening it."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import CaseCloseInput, CaseNoteInput
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

KINDS: Final = {'document': 'Report', 'indicator': 'Indicator', 'actor': 'Actor', 'campaign': 'Campaign'}
EVENTS: Final = {
    'case.open': 'Opened',
    'case.update': 'Changed the title, summary or label',
    'case.item.add': 'Added',
    'case.item.remove': 'Removed',
    'case.note': 'Added a note',
    'case.close': 'Closed',
    'case.reopen': 'Reopened',
}


def _event_text(action: str, detail: str) -> str:
    words = EVENTS.get(action, action)
    if action in ('case.item.add', 'case.item.remove'):
        try:
            kind = json.loads(detail).get('kind', '')
        except (ValueError, AttributeError):
            kind = ''
        words = f'{words} a {KINDS.get(kind, "item").lower()}'
    return words


def open_case_dialog(ws: Workspace, case_id: str, *, changed: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ui.dialog().props('aria-label="Case"') as dialog, ui.card().classes('dialog-card w-full'):

        def write(action: Callable[[Any], object], done: str) -> None:
            if not ws.authorized():
                return
            try:
                with ws.write() as db:
                    action(db)
            except services.CaseClosed as exc:
                error.set_text(str(exc))
                return
            except (ValidationError, ValueError, LookupError):
                error.set_text('That could not be saved. Check the text and its sharing label.')
                return
            body.refresh()
            changed()
            tell(done, 'success')

        def go(kind: str, target_id: str, name: str) -> None:
            dialog.close()
            if kind == 'document':
                ws.show_inbox()
                ws.open_document(target_id)
            elif kind == 'indicator':
                ws.show_entity(name)
            elif kind == 'actor':
                ws.open_guide(target_id)

        @ui.refreshable
        def body() -> None:
            try:
                with ws.read() as db:
                    view = services.get_case(db, case_id, max_tlp=limit)
                    events = services.case_timeline(db, case_id, max_tlp=limit)
            except LookupError:
                ui.label('This case no longer exists.').classes('muted')
                return
            is_open = view.status == 'open'
            heading(view.title, 2)
            with ui.row().classes('items-center gap-2'):
                tlp_badge(view.tlp)
                ui.label('Open' if is_open else f'Closed {(view.closed_at or "")[:10]}').classes('muted')
            if view.summary:
                ui.label(view.summary).classes('prose break-value')

            heading('In this case', 3)
            things = [i for i in view.items if i.kind != 'note']
            if not things:
                ui.label('Nothing yet. Use "Add to case" on a report or an indicator.').classes('muted')
            for item in things:
                with ui.row().classes('items-center gap-2 w-full').mark(f'case-item-{item.target_id}'):
                    ui.label(f'{KINDS[item.kind]} · {item.name or item.target_id}').classes('break-value')
                    tlp_badge(item.tlp)
                    if item.kind != 'campaign':
                        ui.button('Open', on_click=lambda i=item: go(i.kind, i.target_id, i.name)).props(
                            'flat dense no-caps'
                        )
                    if is_open:
                        ui.button(
                            'Remove',
                            on_click=lambda i=item: write(
                                lambda db: services.remove_case_item(db, case_id, i.id, max_tlp=limit),
                                'Removed from the case. The case keeps its label.',
                            ),
                        ).props('flat dense no-caps')

            heading('Notes', 3)
            for note in (i for i in view.items if i.kind == 'note'):
                with ui.column().classes('gap-0'):
                    ui.label(note.note).classes('prose break-value')
                    ui.label(
                        f'{note.added_at[:16].replace("T", " ")} · {note.added_by} · TLP:{note.tlp}'
                    ).classes('muted text-sm')
            if is_open:
                text = ui.textarea('New note').props('outlined maxlength=10000').mark('case-note')
                ui.button(
                    'Add note',
                    on_click=lambda: write(
                        lambda db: services.add_case_note(
                            db, case_id, CaseNoteInput(text=text.value or ''), max_tlp=limit
                        ),
                        'Note added.',
                    ),
                ).props('outline').mark('case-note-save')

            heading('Timeline', 3)
            with ui.column().classes('gap-0').mark('case-timeline'):
                for event in events:
                    when = event.at[:16].replace('T', ' ')
                    ui.label(f'{when} · {_event_text(event.action, event.detail)} · {event.actor}').classes(
                        'text-sm'
                    )

            heading('Close or reopen', 3)
            if is_open:
                outcome = (
                    ui.textarea('What did you find or decide?')
                    .props('outlined maxlength=10000')
                    .mark('case-close-note')
                )
                ui.button(
                    'Close case',
                    on_click=lambda: write(
                        lambda db: services.close_case(
                            db, case_id, CaseCloseInput(note=outcome.value or ''), max_tlp=limit
                        ),
                        'Case closed.',
                    ),
                ).mark('case-close')
            else:
                ui.label(view.close_note).classes('prose break-value')
                ui.button(
                    'Reopen case',
                    on_click=lambda: write(
                        lambda db: services.reopen_case(db, case_id, max_tlp=limit), 'Case reopened.'
                    ),
                ).props('outline').mark('case-reopen')

        def delete() -> None:
            if not ws.authorized():
                return
            try:
                with ws.write() as db:
                    services.delete_case(db, case_id, max_tlp=limit)
            except LookupError:
                pass
            confirm.close()
            dialog.close()
            changed()
            tell('Case deleted. Its reports, indicators, actors and campaigns stay.', 'success')

        with ui.dialog().props('aria-label="Delete case"') as confirm, ui.card().classes('dialog-card'):
            ui.label('Delete this case and its notes? Its reports and indicators stay.').classes('prose')
            with ui.row():
                ui.button('Delete case', on_click=delete).props('color=negative').mark('case-delete-confirm')
                ui.button('Keep it', on_click=confirm.close).props('flat')

        body()
        error = problem_area()
        with ui.row():
            ui.button('Done', on_click=dialog.close)
            ui.button('Delete case…', on_click=confirm.open).props('flat no-caps').mark('case-delete')
    dialog.open()
