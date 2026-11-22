"""One requirement (TIP 4.1, ADR 0032): its criteria, the reports that address it, the reports cited as
evidence, and the current answer."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import AnswerInput, CriterionInput, EvidenceInput
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

CRITERIA: Final = {
    'term': 'A word or phrase in the text',
    'cve': 'A CVE it mentions',
    'technique': 'An ATT&CK technique tagged on it',
    'group': 'A threat group linked to it (G0016 or your actor)',
    'campaign': 'One of your campaigns linked to it',
}
KIND_NAMES: Final = {
    'pir': 'Priority requirement',
    'ir': 'Narrower requirement',
    'rfi': 'Request for information',
}


def _criteria(view: services.RequirementView, changeable: bool, write: Callable[..., None], rid: str) -> None:
    heading('What makes a report relevant', 3)
    if not view.criteria:
        ui.label('No criteria yet. Add one so that reports can match.').classes('muted')
    for c in view.criteria:
        with ui.row().classes('items-center gap-2').mark(f'req-criterion-{c.id}'):
            ui.label(f'{c.kind}: {c.name}').classes('break-value')
            tlp_badge(c.tlp)
            if changeable:
                ui.button(
                    'Remove',
                    on_click=lambda c=c: write(
                        lambda db, limit: services.remove_criterion(db, rid, c.id, max_tlp=limit),
                        'Criterion removed. The requirement keeps its label.',
                    ),
                ).props('flat dense no-caps')
    if changeable:
        with ui.row().classes('items-end gap-2 w-full'):
            kind = ui.select(CRITERIA, value='term', label='Add a criterion').props('outlined dense')
            value = ui.input('Value').props('outlined dense maxlength=120').mark('req-criterion-value')
            ui.button(
                'Add',
                on_click=lambda: write(
                    lambda db, limit: services.add_criterion(
                        db, rid, CriterionInput(kind=kind.value, value=value.value or ''), max_tlp=limit
                    ),
                    'Criterion added.',
                ),
            ).props('outline').mark('req-criterion-add')


def open_requirement_dialog(ws: Workspace, requirement_id: str, *, changed: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with ui.dialog().props('aria-label="Requirement"') as dialog, ui.card().classes('dialog-card w-full'):

        def write(action: Callable[[Any, str], object], done: str) -> None:
            if not ws.authorized():
                return
            try:
                with ws.write() as db:
                    action(db, limit)
            except (services.RequirementRetired, services.RequirementInUse) as exc:
                error.set_text(str(exc))
                return
            except ValidationError:
                error.set_text('That could not be saved. Check the text and its sharing label.')
                return
            except ValueError as exc:  # The services' own messages: a bad ID, a limit, a label.
                error.set_text(str(exc))
                return
            except LookupError as exc:
                error.set_text(f'{exc}.')
                return
            error.set_text('')
            body.refresh()
            changed()
            tell(done, 'success')

        def read_report(document_id: str) -> None:
            dialog.close()
            ws.show_inbox()
            ws.open_document(document_id)

        @ui.refreshable
        def body() -> None:
            try:
                with ws.read() as db:
                    view = services.get_requirement(db, requirement_id, max_tlp=limit)
            except LookupError:
                ui.label('This requirement no longer exists.').classes('muted')
                return
            s = view.summary
            changeable = s.status != 'retired'
            heading(s.question, 2)
            with ui.row().classes('items-center gap-2'):
                tlp_badge(s.tlp)
                facts = [KIND_NAMES[s.kind], f'{s.priority} priority', s.status]
                facts += [f'for {s.stakeholder}'] if s.stakeholder else []
                facts += [f'due {s.due_at[:10]}'] if s.due_at else []
                facts += [f'their reference {view.external_ref}'] if view.external_ref else []
                ui.label(' · '.join(facts)).classes('muted')
            if view.context:
                ui.label(view.context).classes('prose break-value')

            _criteria(view, changeable, write, requirement_id)

            heading('Reports that address it', 3)
            cited = {e.document_id for e in view.evidence}
            if not view.matches:
                ui.label('None you can see yet.').classes('muted')
            for match in view.matches:
                with ui.row().classes('items-center gap-2 w-full').mark(f'req-match-{match.document_id}'):
                    ui.button(match.title, on_click=lambda m=match: read_report(m.document_id)).props(
                        'flat dense no-caps align=left'
                    ).classes('break-value text-left')
                    tlp_badge(match.tlp)
                    ui.label(f'{match.created_at[:10]} · {"; ".join(match.because)}').classes('muted text-sm')
                    if changeable and match.document_id not in cited:
                        ui.button(
                            'Cite as evidence',
                            on_click=lambda m=match: write(
                                lambda db, lim: services.add_evidence(
                                    db, requirement_id, EvidenceInput(document_id=m.document_id), max_tlp=lim
                                ),
                                'Cited as evidence.',
                            ),
                        ).props('flat dense no-caps')

            heading('Evidence', 3)
            if not view.evidence:
                ui.label('No report cited yet.').classes('muted')
            for item in view.evidence:
                with ui.row().classes('items-center gap-2 w-full').mark(f'req-evidence-{item.document_id}'):
                    ui.button(item.title, on_click=lambda i=item: read_report(i.document_id)).props(
                        'flat dense no-caps align=left'
                    ).classes('break-value text-left')
                    tlp_badge(item.tlp)
                    if changeable:
                        ui.button(
                            'Remove',
                            on_click=lambda i=item: write(
                                lambda db, lim: services.remove_evidence(
                                    db, requirement_id, i.id, max_tlp=lim
                                ),
                                'Citation removed. The requirement keeps its label.',
                            ),
                        ).props('flat dense no-caps')

            heading('Answer', 3)
            if s.answered_at:
                ui.label(f'Last answered {s.answered_at[:10]}').classes('muted text-sm')
            if changeable:
                answer = (
                    ui.textarea('Current answer', value=view.answer)
                    .props('outlined maxlength=20000')
                    .mark('req-answer')
                )
                ui.button(
                    'Save answer',
                    on_click=lambda: write(
                        lambda db, lim: services.answer_requirement(
                            db, requirement_id, AnswerInput(answer=answer.value or ''), max_tlp=lim
                        ),
                        'Answer saved.',
                    ),
                ).mark('req-answer-save')
            elif view.answer:
                ui.label(view.answer).classes('prose break-value')

            if changeable:
                ui.button(
                    'Retire requirement',
                    on_click=lambda: write(
                        lambda db, lim: services.retire_requirement(db, requirement_id, max_tlp=lim),
                        'Retired.',
                    ),
                ).props('flat no-caps').mark('req-retire')
            else:
                ui.button(
                    'Reopen requirement',
                    on_click=lambda: write(
                        lambda db, lim: services.reopen_requirement(db, requirement_id, max_tlp=lim),
                        'Reopened.',
                    ),
                ).props('outline').mark('req-reopen')

        def delete() -> None:
            confirm.close()
            write(lambda db, lim: services.delete_requirement(db, requirement_id, max_tlp=lim), 'Deleted.')
            if not error.text:
                dialog.close()

        with (
            ui.dialog().props('aria-label="Delete requirement"') as confirm,
            ui.card().classes('dialog-card'),
        ):
            ui.label('Delete this requirement, its criteria and citations? The reports stay.').classes(
                'prose'
            )
            with ui.row():
                ui.button('Delete', on_click=delete).props('color=negative').mark('req-delete-confirm')
                ui.button('Keep it', on_click=confirm.close).props('flat')

        body()
        error = problem_area()
        with ui.row():
            ui.button('Done', on_click=dialog.close)
            ui.button('Delete…', on_click=confirm.open).props('flat no-caps').mark('req-delete')
    dialog.open()
