"""Paste-in ingestion dialog."""

from __future__ import annotations

from nicegui import ui
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from .. import services
from ..schemas import TLP_LEVELS, DocumentInput
from .workspace import Workspace


def build_ingest_dialog(ws: Workspace) -> ui.dialog:
    with ui.dialog() as dialog, ui.card().classes('panel w-[650px] max-w-full p-6 gap-4'):
        ui.label('ADD TO YOUR WORKSPACE').classes('eyebrow')
        ui.label('Ingest intelligence').classes('text-2xl')
        ui.label('Paste source reporting. Indicators are extracted locally for review.').classes(
            'muted text-sm'
        )
        title_input = ui.input('Document title').props('outlined maxlength=300').classes('w-full')
        source_input = ui.input('Source name').props('outlined maxlength=160').classes('w-full')
        url_input = ui.input('Source URL (optional)').props('outlined maxlength=2000').classes('w-full')
        tlp_input = (
            ui.select(list(TLP_LEVELS), value='AMBER', label='Traffic Light Protocol')
            .props('outlined')
            .classes('w-full')
        )
        body_input = ui.textarea('Source content').props('outlined rows=8 maxlength=200000').classes('w-full')

        def submit() -> None:
            if not ws.authorized():
                return
            try:
                item = DocumentInput(
                    title=title_input.value or '',
                    source_name=source_input.value or '',
                    source_url=url_input.value or '',
                    tlp=tlp_input.value,
                    body=body_input.value or '',
                )
            except ValidationError as exc:
                first = exc.errors()[0]
                ui.notify(f'{first["loc"][0]}: {first["msg"]}', type='warning')
                return
            try:
                with ws.write() as db:
                    doc, created = services.ingest(db, item)
                    ws.state.selected = doc.id
            except ValueError as exc:
                ui.notify(str(exc), type='warning')
                return
            except IntegrityError:
                ui.notify('A concurrent import changed the workspace; please retry once.', type='warning')
                return
            dialog.close()
            for control in (title_input, source_input, url_input, body_input):
                control.set_value('')
            ws.refresh_all()
            ws.show_inbox()
            ui.notify('Document ingested.' if created else 'Exact duplicate found. Opened existing document.')
            if created and doc.tlp != item.tlp:
                ui.notify(
                    f'Handling label raised from TLP:{item.tlp} to TLP:{doc.tlp}: the text carries that '
                    'marking.',
                    type='warning',
                    timeout=10000,
                )

        with ui.row().classes('w-full justify-end'):
            ui.button('Cancel', on_click=dialog.close).props('flat')
            ui.button('Ingest document →', on_click=submit)
    return dialog
