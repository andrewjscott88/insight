"""Per-page state and cross-panel coordination."""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final

from fastapi import FastAPI, Request
from nicegui import ui
from sqlalchemy.orm import Session

from ..models import SessionFactory

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
    #: Unsaved note text per document. Panels re-render whenever anything changes (a review, a finished source
    #: sync in the background, ...); without this, re-rendering silently discarded the analyst's typing.
    note_drafts: dict[str, str] = field(default_factory=dict)


def _noop(*_: Any) -> None:
    return None


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

    def authorized(self) -> bool:
        """Re-checked on every callback: signing out in another tab revokes this page immediately."""
        if not self.app.state.is_authenticated(self.request.session):
            ui.navigate.to('/login')
            return False
        return True

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
    def write(self) -> Generator[Session, None, None]:
        """A write transaction; its audit events name the ``operator`` (only the operator uses the UI)."""
        with self.sessions.begin() as db:
            db.info['actor'] = 'operator'
            yield db
