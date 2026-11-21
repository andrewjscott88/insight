"""Host-side alert destination management, using the same services as the workspace."""

from __future__ import annotations

import os
import sys
from contextlib import ExitStack
from getpass import getpass
from pathlib import Path

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
    secret_out: Path | None,
) -> str:
    if secret_out is not None and (action != 'add' or style != 'json'):
        raise ValueError('--secret-out is only used with notify add --style json.')
    if action == 'add':
        if not name or not style or target_id:
            raise ValueError('Use notify add --name NAME --style chat|json|email [--max-tlp LABEL].')
        if style == 'json' and secret_out is None:
            raise ValueError('Use --secret-out FILE to save the JSON signing key in a new private file.')
        # Webhook paths can be credentials. Never put them in argv, the process list or shell history.
        address = getpass('Destination address: ') if sys.stdin.isatty() else input()
        with ExitStack() as cleanup:
            with sessions.begin() as db:
                services.set_actor(db, 'cli')
                target = services.add_target(
                    db, name=name, style=style, address=address, max_tlp=(max_tlp or 'AMBER').upper()
                )
                if secret_out is not None and target.secret:
                    fd = os.open(secret_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    # A write or commit failure must leave neither a destination nor an orphaned key.
                    cleanup.callback(secret_out.unlink, missing_ok=True)
                    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                        stream.write(target.secret + '\n')
                message = f'Added {target.id} ({target.name}).'
            cleanup.pop_all()
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
