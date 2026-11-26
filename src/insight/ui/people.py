"""Settings → People (ADR 0046): who signs in through the identity provider, and what each of them may do.

Only admins see this section, and every action checks ``Permission.PEOPLE`` again when it runs. A change
of role, turning someone off and removing them end that person's sessions, so the change applies at once. An
admin changes other people only: their own account is left to another admin, or to ``insight users`` on
the host, so nobody locks the last admin out by accident.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Final

from nicegui import ui
from sqlalchemy.orm import Session

from .. import services
from ..permissions import Permission, parse_role
from .activity import build_activity
from .messages import tell
from .typography import heading
from .workspace import Workspace

#: The role choices; ``none`` means waiting for approval, with no access.
ROLE_CHOICES: Final = {
    'none': 'None: waiting, no access',
    'viewer': 'Viewer: reads and downloads',
    'analyst': 'Analyst: intelligence work',
    'admin': 'Admin: also settings and people',
}
OWN_ACCOUNT: Final = 'This is you. Another admin, or insight users on the host, can change your account.'


def _when(stamp: str) -> str:
    return stamp[:16].replace('T', ' ') + ' UTC' if stamp else 'never'


def _intro(ws: Workspace) -> None:
    oidc = ws.app.state.settings.oidc
    ui.label(
        'People sign in through your identity provider. Someone new waits with no access until you give '
        'them a role. Each change here signs the person out, so it applies at once. The workspace password '
        'signs in the built-in operator, who is always an admin.'
    ).classes('muted prose')
    if oidc is None:
        ui.label(
            'Sign-in through an identity provider is off. Set INSIGHT_OIDC_ISSUER on the host to turn it on '
            '(the runbook explains each provider).'
        ).classes('muted text-sm prose')
    elif oidc.groups_mapped:
        ui.label(
            'Your provider groups set roles: someone in a mapped group gets that role at every sign-in. '
            'A role you give here lasts while their groups give none.'
        ).classes('muted text-sm prose')
    if oidc is not None and oidc.sso_only:
        ui.label('The workspace password is off (INSIGHT_SSO_ONLY).').classes('muted text-sm')


def build_people(ws: Workspace) -> None:
    """The People section of Settings; nothing at all for people whose role does not manage people."""
    if not ws.can(Permission.PEOPLE):
        return

    def change(person: services.UserView, act: Callable[[Session], object], done: str) -> None:
        if not ws.allowed(Permission.PEOPLE):
            return
        if person.id == ws.person:  # Also checked here: the page may be older than the account.
            tell(OWN_ACCOUNT, 'warning')
            return
        try:
            with ws.write(Permission.PEOPLE) as db:
                act(db)
        except LookupError:
            tell('This person has been removed in the meantime.', 'warning')
        else:
            tell(done, 'success')
        people.refresh()
        redraw_activity()

    def set_role(person: services.UserView, value: str | None) -> None:
        if value is None or value == (person.role or 'none'):
            return
        role = None if value == 'none' else parse_role(value)
        done = (
            f'{_name(person)} now waits with no access.'
            if role is None
            else f'{_name(person)} is now {"an" if role in ("admin", "analyst") else "a"} {role}.'
        )
        change(person, lambda db: services.set_user_role(db, person.id, role), done + ' They sign in again.')

    def confirm_remove(person: services.UserView) -> None:
        with ui.dialog() as dialog, ui.card().classes('gap-3 max-w-lg'):
            heading('Remove this person?', 2)
            ui.label(
                f'{person.label} is signed out and Insight forgets them. The audit trail keeps what they '
                'did. If they sign in through your provider again, they come back as someone new: waiting '
                'for a role, unless their groups give one.'
            ).classes('prose')

            def remove() -> None:
                dialog.close()
                change(
                    person, lambda db: services.remove_user(db, person.id), f'{_name(person)} was removed.'
                )

            with ui.row():
                ui.button('Remove', on_click=remove).mark('confirm-remove-person')
                ui.button('Cancel', on_click=dialog.close).props('flat')
        dialog.open()

    def card(person: services.UserView, me: str | None) -> None:
        with ui.column().classes('panel w-full p-3 gap-1').mark(f'person-{person.id}'):
            heading(_name(person), 4)
            if person.email and person.display_name:
                ui.label(person.email).classes('muted text-sm break-value')
            state = 'Waiting for approval' if person.role is None else f'Role: {person.role}'
            if person.role_from_groups:
                state += ', from provider groups'
            if person.disabled:
                state = 'Turned off · ' + state
            ui.label(state).classes('text-sm font-semibold')
            ui.label(
                f'Last signed in {_when(person.last_sign_in_at)} · {person.sessions} open session(s)'
            ).classes('muted text-sm')
            if person.id == me:
                ui.label(OWN_ACCOUNT).classes('muted text-sm prose')
                return
            with ui.row().classes('items-center gap-3 flex-wrap'):
                if person.role_from_groups:
                    ui.label('Change this role in your identity provider’s groups.').classes('muted text-sm')
                else:
                    ui.select(
                        ROLE_CHOICES,
                        value=person.role or 'none',
                        label='Role',
                        on_change=lambda e, p=person: set_role(p, e.value),
                    ).props('outlined dense').classes('min-w-[16rem]')
                turn = not person.disabled
                ui.button(
                    'Turn off' if turn else 'Turn on',
                    on_click=lambda p=person, t=turn: change(
                        p,
                        lambda db: services.set_user_disabled(db, p.id, t),
                        f'{_name(p)} is turned {"off and signed out" if t else "on again"}.',
                    ),
                ).props('outline no-caps')
                ui.button(
                    'Sign out',
                    on_click=lambda p=person: change(
                        p,
                        lambda db: services.sign_out_user(db, p.id),
                        f'{_name(p)} is signed out everywhere.',
                    ),
                ).props('flat no-caps').set_enabled(person.sessions > 0)
                ui.button('Remove', on_click=lambda p=person: confirm_remove(p)).props(
                    f'flat no-caps aria-label="Remove {_name(person)}"'
                )

    @ui.refreshable
    def people() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            found = services.list_users(db, at=datetime.now(UTC))
        if not found:
            ui.label('Nobody has signed in through the identity provider yet.').classes('muted')
        me = ws.person
        for person in found:
            card(person, me)

    heading('People', 2)
    _intro(ws)
    with ui.column().classes('w-full gap-3 mt-2'):
        people()
    redraw_activity = build_activity(ws)
    ws.on_refresh(people.refresh)


def _name(person: services.UserView) -> str:
    return person.display_name or person.email or person.subject
