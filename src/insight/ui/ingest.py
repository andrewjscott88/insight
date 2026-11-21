"""Paste-in ingestion dialog."""

from __future__ import annotations

from typing import Any, Final

from nicegui import ui
from nicegui.elements.mixins.validation_element import ValidationElement
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from .. import services
from ..schemas import DocumentInput
from .messages import problem_area, tell
from .stix_import import build_stix_import
from .typography import heading
from .workspace import Workspace

TITLE: Final = 'Ingest intelligence'
#: What to do about a problem with each field, in plain words (WCAG 3.3.1, 3.3.3). Shown on the field itself.
FIELD_HELP: Final = {
    'title': 'Enter a title for the report (up to 300 characters).',
    'source_name': 'Enter where the report came from, such as a company or website (up to 160 characters).',
    'source_url': 'Enter a web address that starts with http:// or https://, or leave this empty.',
    'tlp': 'Choose a TLP label.',
    'body': 'Paste the text of the report (up to 200,000 characters).',
}


def build_ingest_dialog(ws: Workspace) -> ui.dialog:
    with (
        ui.dialog().props(f'aria-label="{TITLE}"') as dialog,
        ui.card().classes('panel dialog-card w-[42rem] max-w-full p-6 gap-4'),
    ):
        ui.label('Add to your workspace').classes('eyebrow')
        heading(TITLE, 2)
        build_stix_import(ws, dialog)
        ui.label(
            'Paste the text of a report. Insight finds the indicators in it, on this server, '
            'for you to check.'
        ).classes('muted prose')
        title_input = ui.input('Document title').props('outlined maxlength=300').classes('w-full')
        source_input = ui.input('Source name').props('outlined maxlength=160').classes('w-full')
        url_input = ui.input('Source URL (optional)').props('outlined maxlength=2000').classes('w-full')
        # Only labels this instance may store (INSIGHT_MAX_TLP); markings in the text are checked on submit.
        # Default AMBER (ADR 0009), or the most restrictive permitted label when the limit is below AMBER.
        levels = services.permitted_tlp_levels(ws.app.state.settings.max_tlp)
        default = 'AMBER' if 'AMBER' in levels else levels[-1]
        tlp_input = (
            ui.select(levels, value=default, label='Traffic Light Protocol (TLP): who may see it')
            .props('outlined')
            .classes('w-full')
        )
        body_input = ui.textarea('Source content').props('outlined rows=8 maxlength=200000').classes('w-full')
        fields = {
            'title': title_input,
            'source_name': source_input,
            'source_url': url_input,
            'tlp': tlp_input,
            'body': body_input,
        }

        def mark(control: ValidationElement[Any], message: str | None) -> None:
            """Show (or clear) the message under the field; Quasar announces it (role="alert")."""
            control.error = message
            control.props(f'aria-invalid={"true" if message else "false"}')

        for control in fields.values():  # An error goes away as soon as the field is changed.
            control.on_value_change(lambda _, control=control: mark(control, None))

        def show_errors(exc: ValidationError) -> None:
            """Explain each problem on its field and go to the first one, in the order they appear on screen.

            No separate message: the fields say it, and a message would wait behind the dialog.
            """
            failed = {str(error['loc'][0]) for error in exc.errors() if error['loc']}
            wrong = [name for name in fields if name in failed]
            for name in wrong:
                mark(fields[name], FIELD_HELP[name])
            fields[wrong[0]].run_method('focus')

        def submit() -> None:
            if not ws.authorized():
                return
            problem.set_text('')
            try:
                item = DocumentInput(
                    title=title_input.value or '',
                    source_name=source_input.value or '',
                    source_url=url_input.value or '',
                    tlp=tlp_input.value,
                    body=body_input.value or '',
                )
            except ValidationError as exc:
                show_errors(exc)
                return
            try:
                with ws.write() as db:
                    doc, created = services.ingest(db, item, max_tlp=ws.app.state.settings.max_tlp)
                    ws.state.selected = doc.id
            except (services.TlpNotPermitted, ValueError) as exc:  # The dialog stays open: say it there.
                problem.set_text(str(exc))
                return
            except IntegrityError:
                problem.set_text('Someone else changed the workspace at the same moment. Please try again.')
                return
            dialog.close()
            for control in (title_input, source_input, url_input, body_input):
                control.set_value('')
            ws.refresh_all()
            ws.show_inbox()
            done = 'Document ingested.' if created else 'You already have this report. Insight opened it.'
            if created and doc.tlp != item.tlp:
                # One message, not two: a second one would replace the first (see messages.py).
                tell(
                    f'{done} Handling label raised from TLP:{item.tlp} to TLP:{doc.tlp}: '
                    'the text carries that marking.',
                    'warning',
                )
            else:
                tell(done, 'success')

        problem = problem_area()
        with ui.row().classes('w-full justify-end'):
            ui.button('Cancel', on_click=dialog.close).props('flat')
            ui.button('Ingest document →', on_click=submit)
    return dialog
