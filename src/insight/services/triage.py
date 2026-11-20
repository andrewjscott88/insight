"""Review status, notes and watch terms."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Document,
    Note,
    Observation,
    WatchTerm,
)
from ..schemas import (
    DOCUMENT_STATUSES,
    REVIEW_STATUSES,
)
from .audit import audit
from .common import fold
from .documents import get_document

MAX_WATCH_TERM_LENGTH: Final = 120


def set_document_status(
    db: Session, doc_id: str, status: str, *, max_tlp: str | None = None
) -> Document | None:
    """Set the triage status; ``None`` if the report does not exist or is above the caller's TLP limit."""
    if status not in DOCUMENT_STATUSES:
        raise ValueError(f'Unknown document status: {status}')
    doc = get_document(db, doc_id, max_tlp=max_tlp)
    if doc is not None:
        doc.status = status
        audit(db, 'document.review', doc.id, status)
    return doc


def set_observation_status(
    db: Session, obs_id: str, status: str, *, max_tlp: str | None = None
) -> Observation | None:
    """Review a mention; ``None`` if it does not exist or its report is above the caller's TLP limit."""
    if status not in REVIEW_STATUSES:
        raise ValueError(f'Unknown review status: {status}')
    obs = db.get(Observation, obs_id)
    if obs is not None and get_document(db, obs.document_id, max_tlp=max_tlp) is None:
        obs = None
    if obs is not None:
        obs.review_status = status
        audit(db, 'observation.review', obs.id, status)
    return obs


def add_note(db: Session, doc_id: str, body: str, *, max_tlp: str | None = None) -> Note | None:
    """Add an analyst note; ``None`` if the report does not exist or is above the caller's TLP limit."""
    if get_document(db, doc_id, max_tlp=max_tlp) is None:
        return None
    note = Note(document_id=doc_id, body=body)
    db.add(note)
    db.flush()
    audit(db, 'note.add', note.id, doc_id)
    return note


def list_watch_terms(db: Session) -> list[WatchTerm]:
    return list(db.scalars(select(WatchTerm).order_by(WatchTerm.term)))


def add_watch_term(db: Session, term: str) -> WatchTerm | None:
    """Add a watch term. Returns ``None`` if it already exists (case-insensitively)."""
    term = term.strip()
    if not term or len(term) > MAX_WATCH_TERM_LENGTH:
        raise ValueError(f'Enter a term between 1 and {MAX_WATCH_TERM_LENGTH} characters.')
    if any(fold(t) == fold(term) for t in db.scalars(select(WatchTerm.term))):
        return None
    obj = WatchTerm(term=term)
    db.add(obj)
    db.flush()
    audit(db, 'watch_term.create', obj.id, term)
    return obj


def remove_watch_term(db: Session, term_id: str) -> bool:
    obj = db.get(WatchTerm, term_id)
    if obj is None:
        return False
    audit(db, 'watch_term.remove', term_id, obj.term)
    db.delete(obj)
    db.flush()
    return True


def watch_matches(terms: Sequence[str], text: str) -> list[str]:
    """Watch terms that occur in ``text`` (literal substring, folded exactly like search)."""
    haystack = fold(text)
    return [t for t in terms if fold(t) in haystack]
