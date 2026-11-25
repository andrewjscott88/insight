"""Which of your open requirements a report addresses (TIP 4.1, ADR 0032), shown at the top of the reader."""

from __future__ import annotations

from collections.abc import Callable

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..permissions import Permission
from ..schemas import EvidenceInput
from .messages import tell
from .workspace import Workspace

SHORT = {'pir': 'PIR', 'ir': 'IR', 'rfi': 'RFI'}


def render_report_requirements(ws: Workspace, document_id: str, refresh: Callable[[], object]) -> None:
    limit = ws.app.state.settings.max_tlp
    with ws.read() as db:
        found = services.document_requirements(db, document_id, max_tlp=limit)
    if not found:
        return

    def cite(requirement_id: str) -> None:
        if not ws.allowed(Permission.REQUIREMENTS):
            return
        try:
            with ws.write(Permission.REQUIREMENTS) as db:
                services.add_evidence(
                    db, requirement_id, EvidenceInput(document_id=document_id), max_tlp=limit
                )
        except ValidationError:
            tell('That could not be cited.', 'warning')
            return
        except (ValueError, LookupError) as exc:
            tell(str(exc), 'warning')
            return
        refresh()
        ws.refresh_all()
        tell('Cited as evidence.', 'success')

    with ui.column().classes('panel w-full p-3 gap-1').mark('report-requirements'):
        ui.label('Addresses your requirements').classes('font-semibold')
        for item in found:
            with ui.row().classes('items-center gap-2 w-full').mark(f'report-requirement-{item.id}'):
                ui.badge(SHORT[item.kind]).props('outline')
                ui.button(item.question, on_click=lambda i=item: ws.show_requirement(i.id)).props(
                    'flat dense no-caps align=left'
                ).classes('break-value text-left')
                ui.label('; '.join(item.because)).classes('muted text-sm')
                ui.button('Cite as evidence', on_click=lambda i=item: cite(i.id)).props('flat dense no-caps')
