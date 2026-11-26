"""Recent activity in Settings → People: the audit trail with people named (ADR 0046).

Audit events store who acted as an ID (``user:<id>``), never an e-mail address. Only admins see this list,
with each person's name and e-mail; the API's audit log keeps the IDs, because viewers and read keys may
read it. A person who was removed is shown by ID.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from nicegui import ui

from .. import services
from ..permissions import Permission
from .workspace import Workspace

#: How many of the latest audit events the list shows.
SHOWN: Final = 50
#: Who acted, for actors that are not people.
ACTORS: Final = {
    'operator': 'Operator (workspace password)',
    'cli': 'Host command line',
    'schedule': 'A schedule',
    'lookup': 'An automatic lookup',
    'system': 'Insight itself',
}


def actor_name(actor: str, labels: dict[str, str]) -> str:
    """How the list names whoever acted: a person by name and e-mail, others in words."""
    kind, _, ref = actor.partition(':')
    if kind == 'user':
        return labels.get(ref, f'Removed person ({ref})')
    if kind == 'api-key':
        return f'API key {ref}'
    if kind == 'connector':
        return f'Source sync ({ref})'
    return ACTORS.get(actor, actor)


def build_activity(ws: Workspace) -> Callable[[], object]:
    """The latest audit events, newest first, in a section that is drawn only while it is open (it would add
    up to 150 elements to every admin's page). Returns what redraws it after a change."""
    opened = False

    @ui.refreshable
    def events() -> None:
        if not opened or not ws.authorized() or not ws.can(Permission.PEOPLE):
            return
        with ws.read() as db:
            found = [
                (e.created_at, e.actor, e.action, e.object_id, e.detail)
                for e in services.audit_events(db, limit=SHOWN)
            ]
            people = {a.removeprefix('user:') for _, a, *_ in found if a.startswith('user:')}
            people |= {o for _, _, action, o, _ in found if action.startswith('user.')}
            labels = services.user_labels(db, people)
        if not found:
            ui.label('Nothing has happened yet.').classes('muted text-sm')
        for created, actor, action, object_id, detail in found:
            about = actor_name(f'user:{object_id}', labels) if action.startswith('user.') else object_id
            with ui.column().classes('w-full gap-0'):
                ui.label(
                    f'{str(created)[:16].replace("T", " ")} UTC · {actor_name(actor, labels)} · {action}'
                ).classes('text-sm break-value')
                ui.label(' · '.join(part for part in (about, detail) if part)).classes(
                    'muted text-sm break-value prose'
                )

    def toggle(value: bool) -> None:
        nonlocal opened
        opened = value
        events.refresh()

    with (
        ui.expansion('Recent activity', icon='history', on_value_change=lambda e: toggle(bool(e.value)))
        .classes('w-full mt-4')
        .mark('recent-activity')
    ):
        ui.label(f'The latest {SHOWN} changes in this workspace, newest first, and who made them.').classes(
            'muted prose'
        )
        with ui.column().classes('w-full gap-2 mt-2'):
            events()
    return events.refresh
