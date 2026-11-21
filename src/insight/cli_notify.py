"""Host-side alert destination management, using the same services as the workspace."""

from __future__ import annotations

import sys
from getpass import getpass

from . import services
from .models import SessionFactory


def manage_destination(
    sessions: SessionFactory,
    action: str,
    *,
    name: str | None,
    style: str | None,
    target_id: str | None,
    max_tlp: str | None,
) -> str:
    if action == 'add':
        if not name or not style or target_id:
            raise ValueError('Use notify add --name NAME --style chat|json|email [--max-tlp LABEL].')
        # Webhook paths can be credentials. Never put them in argv, the process list or shell history.
        address = getpass('Destination address: ') if sys.stdin.isatty() else input()
        with sessions.begin() as db:
            services.set_actor(db, 'cli')
            target = services.add_target(
                db, name=name, style=style, address=address, max_tlp=(max_tlp or 'AMBER').upper()
            )
            message = f'Added {target.id} ({target.name}).'
            if target.secret:
                message += f'\nSigning secret (shown once): {target.secret}'
        return message
    if name is not None or style is not None or max_tlp is not None:
        raise ValueError('--name, --style and --max-tlp are only used with notify add.')
    if action == 'list' and not target_id:
        with sessions() as db:
            return (
                '\n'.join(
                    f'{t.id}  {t.name}  {t.style}  TLP:{t.max_tlp}  {"on" if t.enabled else "off"}'
                    for t in services.list_targets(db)
                )
                or 'No alert destinations.'
            )
    if action not in ('enable', 'disable', 'remove') or not target_id:
        raise ValueError('Use notify list, add, or enable|disable|remove --target ID.')
    with sessions.begin() as db:
        services.set_actor(db, 'cli')
        try:
            if action == 'remove':
                services.delete_target(db, target_id)
                return f'Removed destination {target_id} and its queued alerts.'
            target = services.set_target_enabled(db, target_id, action == 'enable')
            return f'{target.name}: {"on" if target.enabled else "off"}.'
        except LookupError as exc:
            raise ValueError('Unknown destination ID. Use notify list to see destinations.') from exc
