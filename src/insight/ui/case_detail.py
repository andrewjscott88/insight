"""One product (TIP 3.8 and 4.4, ADR 0029 and 0036): the product itself (bottom line, key judgements,
analysis, gaps, publishing), its evidence, working notes, timeline, and archiving or reopening it."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import CaseCloseInput, CaseNoteInput
from .messages import problem_area, tell
from .product_publish import render_publish
from .product_sections import KINDS, render_analysis, render_bottom_line, render_gaps, render_judgements
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

EVENTS: Final = {
    'case.open': 'Started',
    'case.update': 'Changed the text, kind or label',
    'case.item.add': 'Added',
    'case.item.remove': 'Removed',
    'case.note': 'Added a note',
    'case.judgement.add': 'Added a key judgement',
    'case.judgement.update': 'Changed a key judgement',
    'case.judgement.remove': 'Removed a key judgement',
    'case.gap.add': 'Added a gap',
    'case.gap.remove': 'Removed a gap',
    'case.gap.rfi': 'Asked a gap as a request',
    'case.publish': 'Published',
    'case.export': 'Downloaded',
    'case.close': 'Archived',
    'case.reopen': 'Reopened',
}


def _event_text(action: str, detail: str) -> str:
    words = EVENTS.get(action, action)
    try:
        facts = json.loads(detail)
    except ValueError:
        facts = {}
    if not isinstance(facts, dict):
        facts = {}
    if action in ('case.item.add', 'case.item.remove'):
        words = f'{words} a {KINDS.get(facts.get("kind", ""), "item").lower()}'
    if action == 'case.publish' and facts.get('version'):
        words = f'{words} version {facts["version"]}'
    return words


def open_case_dialog(ws: Workspace, case_id: str, *, changed: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ui.dialog().props('aria-label="Product"') as dialog, ui.card().classes('dialog-card w-full'):

        def write(action: Callable[[Any], object], done: str) -> None:
            if not ws.authorized():
                return
            try:
                with ws.write() as db:
                    action(db)
            except (services.CaseClosed, services.ProductIncomplete) as exc:
                error.set_text(str(exc))
                return
            except (ValidationError, ValueError, LookupError):
                error.set_text('That could not be saved. Check the text, the evidence and the sharing label.')
                return
            error.set_text('')
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
                    parts = services.product_parts(db, case_id, max_tlp=limit)
                    events = services.case_timeline(db, case_id, max_tlp=limit)
            except LookupError:
                ui.label('This product no longer exists.').classes('muted')
                return
            is_open = view.status == 'open'
            heading(view.title, 2)
            with ui.row().classes('items-center gap-2'):
                tlp_badge(view.tlp)
                ui.label('In progress' if is_open else f'Archived {(view.closed_at or "")[:10]}').classes(
                    'muted'
                )
            render_bottom_line(view, write, limit, is_open)
            render_judgements(view, parts, write, limit, is_open)
            render_analysis(view, write, limit, is_open)
            render_gaps(view, parts, write, limit, is_open)
            render_publish(view, parts, write, limit, is_open)

            heading('Evidence', 3)
            things = [i for i in view.items if i.kind != 'note']
            if not things:
                ui.label('Nothing yet. Use "Add to product" on a report or an indicator.').classes('muted')
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
                                'Removed from the product. It keeps its label.',
                            ),
                        ).props('flat dense no-caps')

            heading('Working notes', 3)
            ui.label('Notes stay in Insight. They are never part of a published product.').classes(
                'muted prose'
            )
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

            heading('Archive or reopen', 3)
            if is_open:
                outcome = (
                    ui.textarea('Why is the work finished?')
                    .props('outlined maxlength=10000')
                    .mark('case-close-note')
                )
                ui.button(
                    'Archive',
                    on_click=lambda: write(
                        lambda db: services.close_case(
                            db, case_id, CaseCloseInput(note=outcome.value or ''), max_tlp=limit
                        ),
                        'Archived.',
                    ),
                ).props('outline').mark('case-close')
            else:
                ui.label(view.close_note).classes('prose break-value')
                ui.button(
                    'Reopen',
                    on_click=lambda: write(
                        lambda db: services.reopen_case(db, case_id, max_tlp=limit), 'Reopened.'
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
            tell('Product deleted. What it held stays in Insight.', 'success')

        with ui.dialog().props('aria-label="Delete product"') as confirm, ui.card().classes('dialog-card'):
            ui.label(
                'Delete this product, its versions and its notes? Its reports and indicators stay.'
            ).classes('prose')
            with ui.row():
                ui.button('Delete product', on_click=delete).props('color=negative').mark(
                    'case-delete-confirm'
                )
                ui.button('Keep it', on_click=confirm.close).props('flat')

        body()
        error = problem_area()
        with ui.row():
            ui.button('Done', on_click=dialog.close)
            ui.button('Delete product…', on_click=confirm.open).props('flat no-caps').mark('case-delete')
    dialog.open()
