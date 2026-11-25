"""``insight users``: people and their roles, from the host (ADR 0046).

Admins manage people in the workspace (TIP 3.4b); this command does the same on the host, so it also works
as a break-glass when nobody who can sign in is an admin. Every change ends the person's sessions, so it
applies at once, and is audited with the actor ``cli``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from . import services
from .cli import _current_database
from .permissions import ROLES, parse_role

USER_HELP = 'the ID from `insight users list`, or the e-mail address'


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='insight users',
        description='People who sign in through your identity provider, and their roles: '
        f'{", ".join(ROLES)}. The password sign-in is the built-in operator, always an admin.',
    )
    actions = parser.add_subparsers(dest='action', required=True, metavar='ACTION')
    actions.add_parser('list', help='everyone who has signed in, people waiting for approval first')
    role = actions.add_parser('role', help='give a person a role, or none to take it away (approves them)')
    role.add_argument('user', help=USER_HELP)
    role.add_argument('role', choices=[*ROLES, 'none'], type=str.lower)
    for action, text in (
        ('disable', 'stop a person signing in, and end their sessions'),
        ('enable', 'let a disabled person sign in again'),
        ('sign-out', "end a person's sessions everywhere"),
    ):
        actions.add_parser(action, help=text).add_argument('user', help=USER_HELP)
    remove = actions.add_parser('remove', help='remove a person; signing in again makes them wait again')
    remove.add_argument('user', help=USER_HELP)
    remove.add_argument('--yes', action='store_true', help='do not ask for confirmation')
    return parser


def _plural(count: int, noun: str) -> str:
    return f'{count} {noun}' if count == 1 else f'{count} {noun}s'


def _listing(people: Sequence[services.UserView]) -> str:
    if not people:
        return 'Nobody has signed in through the identity provider yet.'
    lines = []
    for person in people:
        role = person.role or 'waiting for approval'
        notes = [role + (' (from provider groups)' if person.role_from_groups else '')]
        if person.disabled:
            notes.append('disabled')
        notes.append(f'last signed in {person.last_sign_in_at[:16]}')
        notes.append(_plural(person.sessions, 'open session'))
        lines.append(f'{person.id}  {person.label}  ({"; ".join(notes)})')
    return '\n'.join(lines)


def _ask_to_remove(summary: str) -> bool:
    answer = input(f'This removes {summary}. Their audit events stay.\nType remove to go ahead: ')
    return answer.strip().lower() == 'remove'


def run_users(argv: Sequence[str], confirm: Callable[[str], bool] | None = _ask_to_remove) -> str:
    """Run one ``insight users`` action and return what to print. Raises ``ValueError`` for a person who
    cannot be found (or an e-mail address several people use); ``SystemExit`` for bad arguments."""
    args = _parser().parse_args(argv)
    with _current_database() as sessions, sessions.begin() as db:
        services.set_actor(db, 'cli')
        if args.action == 'list':
            return _listing(services.list_users(db, at=datetime.now(UTC)))
        try:
            person = services.find_user(db, args.user, at=datetime.now(UTC))
        except LookupError:
            raise ValueError(f'nobody matches {args.user!r}; see `insight users list`') from None
        if args.action == 'role':
            role = None if args.role == 'none' else parse_role(args.role)
            ended = services.set_user_role(db, person.id, role)
            if role is None:
                message = f'{person.label} has no role now and waits for approval.'
            else:
                message = f'{person.label} is now {"a" if role == "viewer" else "an"} {role}.'
        elif args.action in ('disable', 'enable'):
            ended = services.set_user_disabled(db, person.id, args.action == 'disable')
            message = f'{person.label} is {args.action}d.'
        elif args.action == 'sign-out':
            ended = services.sign_out_user(db, person.id)
            message = f'{person.label} is signed out.'
        else:
            if not args.yes and confirm is not None and not confirm(person.label):
                return 'Cancelled; nothing was removed.'
            ended = services.remove_user(db, person.id)
            message = f'Removed {person.label}.'
    return f'{message} {_plural(ended, "session")} ended.' if ended else message
