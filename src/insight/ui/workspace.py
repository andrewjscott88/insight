"""Per-page state and cross-panel coordination."""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from fastapi import FastAPI, Request
from nicegui import ui
from sqlalchemy.orm import Session

from ..models import SessionFactory
from ..permissions import NOT_PERMITTED, Permission
from .messages import tell

ALL_STATUSES: Final = 'All statuses'
ALL_TLP: Final = 'All TLP levels'


@dataclass(slots=True)
class WorkspaceState:
    """What the analyst is looking at. One instance per open browser tab."""

    selected: str | None = None
    q: str = ''
    status: str = ALL_STATUSES
    tlp: str = ALL_TLP
    include_superseded: bool = False
    entity_q: str = ''
    #: The period of the threat landscape, in days.
    landscape_days: int = 30
    #: The period on the ATT&CK techniques tab, in days (0: all time).
    technique_days: int = 30
    #: The period on the prioritised CVE tab, in days.
    cve_days: int = 30
    #: The industry on the industry threats tab (TIP 2.10).
    threat_industry: str = 'government'
    #: Unsaved note text per document. Panels re-render whenever anything changes (a review, a finished source
    #: sync in the background, ...); without this, re-rendering silently discarded the analyst's typing.
    note_drafts: dict[str, str] = field(default_factory=dict)


def _noop(*_: Any) -> None:
    return None


class NotPermitted(PermissionError):
    """The current session's role does not allow this workspace action (ADR 0046)."""


class _Caller(Protocol):
    """Who a session signs in (``web.auth.Caller``; the workspace does not import the web front end)."""

    @property
    def actor(self) -> str: ...

    def may(self, permission: Permission) -> bool: ...


@dataclass(slots=True)
class Workspace:
    """Shared context handed to every panel.

    Panels register their refresh functions with :meth:`on_refresh` and publish navigation hooks
    (``open_document``, ``show_inbox``, ``show_entity``) so other panels can use them without importing each
    other.
    """

    app: FastAPI
    sessions: SessionFactory
    request: Request
    state: WorkspaceState = field(default_factory=WorkspaceState)
    refreshers: list[Callable[[], Any]] = field(default_factory=list)
    open_document: Callable[[str], None] = _noop
    show_inbox: Callable[[], None] = _noop
    #: Look up one indicator in the entity explorer (set by the entities panel).
    find_entity: Callable[[str], None] = _noop
    #: Switch to the entity explorer and look up one indicator (set by the page).
    show_entity: Callable[[str], None] = _noop
    #: Switch the side menu to a section (``triage``...) and Investigate to a tab (set by the page).
    show_section: Callable[..., None] = _noop
    #: Open one requirement's dialog in the Requirements section (set by that section).
    show_requirement: Callable[[str], None] = _noop
    #: Search the inbox for a word, as if typed into its search box (set by the inbox).
    search_reports: Callable[[str], None] = _noop
    #: Open a group's threat guide by its ATT&CK ID or actor ID (set by the industry threats tab).
    open_guide: Callable[[str], None] = _noop

    def authorized(self) -> bool:
        """Re-checked on every callback: signing out in another tab revokes this page immediately."""
        if not self.app.state.is_authenticated(self.request.session):
            ui.navigate.to('/login')
            return False
        return True

    def _caller(self) -> _Caller | None:
        caller: _Caller | None = self.app.state.session_caller(self.request.session)
        return caller

    def allowed(self, permission: Permission) -> bool:
        """``authorized`` plus the role, checked on every callback: says so when it does not allow this.

        Only spares the person an error; ``write`` and ``actor`` check again and are the control.
        """
        caller = self._caller()
        if caller is None:
            ui.navigate.to('/login')
            return False
        if not caller.may(permission):
            tell(NOT_PERMITTED, 'warning')
            return False
        return True

    def actor(self, permission: Permission) -> str:
        """Who audit events name for ``permission`` done outside :meth:`write` (an outside lookup, a sync).

        The current session's role is checked now; raises :class:`NotPermitted`.
        """
        caller = self._caller()
        if caller is None or not caller.may(permission):
            raise NotPermitted(f'{NOT_PERMITTED} ({permission})')
        return caller.actor

    def on_refresh(self, refresh: Callable[[], Any]) -> None:
        self.refreshers.append(refresh)

    def refresh_all(self) -> None:
        for refresh in self.refreshers:
            refresh()

    @contextmanager
    def read(self) -> Generator[Session, None, None]:
        with self.sessions() as db:
            yield db

    @contextmanager
    def write(self, permission: Permission) -> Generator[Session, None, None]:
        """A write transaction for ``permission``. The current session's role is checked here, on every
        callback, so a role change or a disabled account applies at once (raises :class:`NotPermitted`).
        Audit events name the person: ``operator``, or ``user:<id>``."""
        actor = self.actor(permission)
        with self.sessions.begin() as db:
            db.info['actor'] = actor
            yield db
