"""The analyst's own threat data (TIP 2.5 minimum, TIP 2.10; ADR 0025): actors, industries, report links.

Each of these is a decision the analyst makes and Insight records with an audit event. Insight never links a
report to a group by itself, and never from shared indicators.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..industries import INDUSTRIES
from ..permissions import Permission
from ..schemas import TLP_LEVELS, ActorInput, ActorLinkInput, IndustryClaimInput
from ..threat_library import library
from .messages import problem_area, tell
from .typography import heading
from .workspace import Workspace


def _labels(ws: Workspace) -> tuple[list[str], str]:
    limit = ws.app.state.settings.max_tlp
    return [t for t in TLP_LEVELS if services.tlp_permitted(t, limit)], services.stricter_limit(
        'AMBER', limit
    ) or 'AMBER'


def open_actor_dialog(ws: Workspace, on_created: Callable[[str], Any]) -> None:
    if not ws.authorized():
        return
    choices, start = _labels(ws)
    with (
        ui.dialog().props('aria-label="Track your own actor"') as dialog,
        ui.card().classes('panel dialog-card w-[36rem] max-w-full p-6 gap-3'),
    ):
        heading('Track your own actor', 2)
        ui.label('Use this for a group that is not in ATT&CK, or for your own name for one.').classes(
            'muted prose'
        )
        name = ui.input('Name').props('outlined maxlength=120 autofocus')
        aliases = ui.input('Other names, split by commas (optional)').props('outlined maxlength=2000')
        same = ui.input('Same as ATT&CK group (optional), such as G0016').props('outlined maxlength=5')
        about = ui.textarea('About this actor (optional)').props('outlined maxlength=5000').classes('w-full')
        label = ui.select(choices, value=start, label='TLP').props('outlined')
        problem = problem_area()

        def save() -> None:
            if not ws.allowed(Permission.NOTES_AND_LINKS):
                return
            try:
                payload = ActorInput.model_validate(
                    {
                        'name': name.value or '',
                        'aliases': [a.strip() for a in (aliases.value or '').split(',') if a.strip()],
                        'attack_group_id': (same.value or '').strip() or None,
                        'description': about.value or '',
                        'tlp': label.value,
                    }
                )
                with ws.write(Permission.NOTES_AND_LINKS) as db:
                    ref = services.create_actor(db, payload, max_tlp=ws.app.state.settings.max_tlp).id
            except ValidationError:
                problem.set_text('Give the actor a name. A group ID looks like G0016.')
                return
            except ValueError as exc:
                problem.set_text(str(exc))
                return
            dialog.close()
            tell('Actor saved.', 'success')
            on_created(ref)

        with ui.row():
            ui.button('Save', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def open_industry_dialog(ws: Workspace, group_ref: str, on_saved: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    choices, start = _labels(ws)
    with (
        ui.dialog().props('aria-label="Add or remove an industry"') as dialog,
        ui.card().classes('panel dialog-card w-[36rem] max-w-full p-6 gap-3'),
    ):
        heading('Add or remove an industry', 2)
        ui.label(
            'To add an industry, give the web page or report that says so. To remove one, say why.'
        ).classes('muted prose')
        industry = ui.select({i.key: i.name for i in INDUSTRIES}, label='Industry').props('outlined')
        industry.mark('claim-industry')
        decision = ui.select({'added': 'Add it', 'removed': 'Remove it'}, value='added', label='What to do')
        decision.props('outlined')
        citation = (
            ui.input('Web page that says so (https)').props('outlined maxlength=2000').classes('w-full')
        )
        reason = ui.textarea('Why').props('outlined maxlength=2000').classes('w-full')
        label = ui.select(choices, value=start, label='TLP').props('outlined')
        problem = problem_area()

        def save() -> None:
            if not ws.allowed(Permission.NOTES_AND_LINKS):
                return
            try:
                payload = IndustryClaimInput.model_validate(
                    {
                        'industry': industry.value or '',
                        'decision': decision.value,
                        'citation_url': citation.value or '',
                        'reason': reason.value or '',
                        'tlp': label.value,
                    }
                )
                with ws.write(Permission.NOTES_AND_LINKS) as db:
                    services.record_industry_claim(
                        db, group_ref, payload, max_tlp=ws.app.state.settings.max_tlp
                    )
            except ValidationError:
                problem.set_text('Pick an industry. A web page must start with https.')
                return
            except (LookupError, ValueError) as exc:
                problem.set_text(str(exc))
                return
            dialog.close()
            on_saved()
            tell('Saved. The industry lists use it now.', 'success')

        with ui.row():
            ui.button('Save', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def render_report_groups(ws: Workspace, doc_id: str, on_changed: Callable[[], Any]) -> None:
    """The reader's section: groups this report is linked to, and a way to link one."""
    ceiling = ws.app.state.settings.max_tlp
    with ws.read() as db:
        try:
            groups = services.report_groups(db, doc_id, max_tlp=ceiling)
        except LookupError:
            return
    heading(f'Threat groups ({len(groups)})', 3, 'subsection-title mt-4')
    ui.label('Link this report to a group if it is about that group. Its guide will then list it.').classes(
        'muted prose'
    )
    for subject in groups:
        with ui.row().classes('items-center gap-2'):
            ui.button(
                f'{subject.name} ({subject.ref})', on_click=lambda r=subject.ref: ws.open_guide(r)
            ).props('flat dense no-caps')

            def unlink(ref: str = subject.ref) -> None:
                if not ws.allowed(Permission.NOTES_AND_LINKS):
                    return
                with ws.write(Permission.NOTES_AND_LINKS) as db:
                    services.unlink_report(db, ref, doc_id, max_tlp=ceiling)
                on_changed()

            if ws.can(Permission.NOTES_AND_LINKS):
                ui.button('Remove link', on_click=unlink).props('flat dense no-caps')
    if not ws.can(Permission.NOTES_AND_LINKS):
        return
    query = ui.input('Link to a group, such as APT29 or G0016').props(
        'outlined dense debounce=250 maxlength=100'
    )
    matches = ui.column().classes('w-full gap-1').props('aria-live=polite')

    def link(ref: str) -> None:
        if not ws.allowed(Permission.NOTES_AND_LINKS):
            return
        try:
            with ws.write(Permission.NOTES_AND_LINKS) as db:
                services.link_report(
                    db, ref, ActorLinkInput(document_id=doc_id), max_tlp=ceiling, preserve_note=True
                )
        except LookupError:
            tell('This item no longer exists.', 'warning')
            return
        on_changed()
        tell('Report linked.', 'success')

    def show(value: str | None) -> None:
        matches.clear()
        text = (value or '').strip()
        if not text:
            return
        with ws.read() as db:
            rows = [
                (a.id, a.name)
                for a in services.list_actors(db, max_tlp=ceiling)
                if text.casefold() in a.name.casefold()
            ]
        rows += [(g.id, f'{g.id} · {g.name}') for g in library().search(text, limit=8)]
        with matches:
            for ref, shown in rows[:8]:
                ui.button(shown, on_click=lambda r=ref: link(r)).props('flat dense no-caps align=left')

    query.on_value_change(lambda event: show(event.value))
