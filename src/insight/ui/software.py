"""Catalog software, candidate reports and explicit, labelled report decisions."""

from __future__ import annotations

from collections.abc import Callable

from nicegui import ui

from .. import services
from ..attack import technique
from ..permissions import Permission
from ..schemas import SoftwareLinkInput
from ..threat_library import library
from .actors import _labels
from .messages import problem_area, tell
from .typography import heading, new_tab_link
from .workspace import Workspace


def _link_dialog(ws: Workspace, ref: str, doc_id: str, saved: Callable[[], object]) -> None:
    if not ws.authorized():
        return
    choices, start = _labels(ws)
    with (
        ui.dialog().props('aria-label="Link report to software"') as dialog,
        ui.card().classes('dialog-card w-full'),
    ):
        heading('Link report to software', 2)
        ui.label('This is your decision. A shared name alone does not prove use.').classes('muted prose')
        note = ui.textarea('Why this report is about the software').props('outlined maxlength=2000')
        label = ui.select(choices, value=start, label='Link sharing label').props('outlined')
        problem = problem_area()

        def save() -> None:
            if not ws.allowed(Permission.NOTES_AND_LINKS):
                return
            try:
                payload = SoftwareLinkInput.model_validate(
                    {
                        'document_id': doc_id,
                        'note': note.value or '',
                        'tlp': label.value,
                    }
                )
                with ws.write(Permission.NOTES_AND_LINKS) as db:
                    services.link_software_report(db, ref, payload, max_tlp=ws.app.state.settings.max_tlp)
            except (LookupError, ValueError) as exc:
                problem.set_text(str(exc))
                return
            dialog.close()
            saved()
            tell('Software link saved.', 'success')

        with ui.row():
            ui.button('Save software link', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def open_software(ws: Workspace, ref: str) -> None:
    if not ws.authorized():
        return
    with (
        ui.dialog().props('aria-label="Software details"').mark('software-detail') as dialog,
        ui.card().classes('dialog-card w-full'),
    ):

        def read_report(document_id: str) -> None:
            dialog.close()
            ws.show_inbox()
            ws.open_document(document_id)

        @ui.refreshable
        def contents() -> None:
            if not ws.authorized():
                return
            try:
                with ws.read() as db:
                    entry = services.software_detail(db, ref, max_tlp=ws.app.state.settings.max_tlp)
            except LookupError:
                ui.label('This software is no longer available.').classes('muted')
                return
            heading(f'{entry["name"]} ({entry["id"]})', 2)
            ui.label(f'{entry["type"]} · TLP:{entry["tlp"]}').classes('muted')
            if entry['retired']:
                ui.label('This item has left the catalog. Your saved links remain.').classes('muted prose')
            if entry['description']:
                ui.label(entry['description']).classes('prose break-value')
            if entry['aliases']:
                ui.label('Other names: ' + ', '.join(entry['aliases'])).classes('prose break-value')
            if entry['platforms']:
                ui.label('Platforms: ' + ', '.join(entry['platforms'])).classes('prose break-value')
            if entry['techniques'] or entry['groups']:
                with ui.expansion('Public catalog context').classes('w-full'):
                    ui.label('These public catalog claims are separate from your saved links.').classes(
                        'muted prose'
                    )
                    for technique_id in entry['techniques']:
                        found = technique(technique_id)
                        new_tab_link(
                            f'{technique_id} · {found.full_name if found else technique_id}',
                            f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/',
                        ).classes('break-value')
                    for group_id in entry['groups']:
                        group = library().group(group_id)
                        new_tab_link(
                            f'{group_id} · {group.name if group else group_id}',
                            f'https://attack.mitre.org/groups/{group_id}/',
                        ).classes('break-value')
            if entry['url']:
                new_tab_link('Read the public software entry', entry['url'])
            heading('Linked reports', 3)
            ui.label('Up to 50 saved report links are shown. Use the API for more.').classes('muted prose')
            for row in entry['reports']:
                with ui.row().classes('items-center w-full'):
                    ui.button(row['title'], on_click=lambda d=row['document_id']: read_report(d)).props(
                        'flat no-caps'
                    ).classes('break-value')
                    ui.label(f'TLP:{row["tlp"]}').classes('muted')

                    def remove(document_id: str = row['document_id']) -> None:
                        if not ws.allowed(Permission.NOTES_AND_LINKS):
                            return
                        try:
                            with ws.write(Permission.NOTES_AND_LINKS) as db:
                                services.unlink_software_report(
                                    db, ref, document_id, max_tlp=ws.app.state.settings.max_tlp
                                )
                        except LookupError as exc:
                            tell(str(exc), 'warning')
                        contents.refresh()

                    ui.button('Remove software link', on_click=remove).props('flat dense no-caps')
                if row['note']:
                    ui.label(row['note']).classes('prose break-value')
            if not entry['reports']:
                ui.label('No saved report links.').classes('muted')
            heading('Actors and campaigns linked to this software', 3)
            ui.label('These are explicit use decisions, separate from report links.').classes('muted prose')
            for use in entry['uses']:
                ui.label(f'{use["name"]} ({use["kind"]}) · TLP:{use["tlp"]}').classes('break-value')
            heading('Reports that name it', 3)
            ui.label('These are candidates, not saved links or proof of use. Up to 50 are shown.').classes(
                'muted prose'
            )
            if entry['scan_capped']:
                ui.label(f'Only the newest {entry["reports_scanned"]} reports were checked.').classes(
                    'text-warn'
                )
            for row in entry['candidates']:
                ui.button(row['title'], on_click=lambda d=row['document_id']: read_report(d)).props(
                    'flat no-caps'
                ).classes('break-value')
                if row['evidence']:
                    ui.label(row['evidence']).classes('evidence prose break-value')
                ui.button(
                    'Link this report',
                    on_click=lambda d=row['document_id']: _link_dialog(ws, ref, d, contents.refresh),
                ).props('outline no-caps')

        contents()
        ui.button('Close', on_click=dialog.close)
    dialog.open()


def render_software_search(ws: Workspace) -> None:
    with ui.expansion('Software library').classes('w-full'):
        ui.label(
            'Find malware and tools in the public catalog. Report links are your own decisions.'
        ).classes('muted prose')
        query = ui.input('Software name or ID').props('outlined debounce=250 maxlength=120')
        results = ui.column().classes('w-full').props('aria-live=polite')

        def show() -> None:
            results.clear()
            if not ws.authorized() or not (query.value or '').strip():
                return
            with results:
                for item in services.search_software(
                    q=query.value, limit=12, max_tlp=ws.app.state.settings.max_tlp
                ):
                    ui.button(
                        f'{item["name"]} ({item["id"]})', on_click=lambda r=item['id']: open_software(ws, r)
                    ).props('flat no-caps').classes('break-value')

        query.on_value_change(lambda _: show())


def render_report_software(ws: Workspace, doc_id: str, changed: Callable[[], object]) -> None:
    ceiling = ws.app.state.settings.max_tlp
    with ws.read() as db:
        items = services.report_software(db, doc_id, max_tlp=ceiling)
    heading('Software links', 3, 'subsection-title mt-4')
    for item in items:
        ui.button(f'{item["name"]} ({item["id"]})', on_click=lambda r=item['id']: open_software(ws, r)).props(
            'flat dense no-caps'
        ).classes('break-value')
    query = ui.input('Link software by name or ID').props('outlined debounce=250 maxlength=120')
    results = ui.column().classes('w-full').props('aria-live=polite')

    def show() -> None:
        results.clear()
        if not ws.authorized() or not (query.value or '').strip():
            return
        with results:
            for item in services.search_software(q=query.value, limit=8, max_tlp=ceiling):
                ui.button(
                    f'Link {item["name"]}', on_click=lambda r=item['id']: _link_dialog(ws, r, doc_id, changed)
                ).props('flat dense no-caps').classes('break-value')

    query.on_value_change(lambda _: show())
