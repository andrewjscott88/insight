"""Settings controls offered only to the roles that may use them (ADR 0046).

Everyone else sees the setting in words instead of a control they cannot use. Hiding is a courtesy: each
callback still checks the role (``ws.allowed``, then ``ws.write``), and that check is the control.
"""

from __future__ import annotations

from collections.abc import Callable

from nicegui import ui

from ..permissions import Permission
from .workspace import Workspace


def setting_switch(
    ws: Workspace,
    permission: Permission,
    label: str,
    value: bool,
    on_change: Callable[[bool], object],
    *,
    state: tuple[str, str] | None = None,
) -> ui.switch | None:
    """A switch for a role that ``permission`` allows; otherwise the setting as text (``state``: the words
    for on and off) and ``None``."""
    if ws.can(permission):
        return ui.switch(label, value=value, on_change=lambda e: on_change(bool(e.value)))
    on, off = state or (f'{label}: on', f'{label}: off')
    ui.label(on if value else off).classes('text-sm')
    return None
