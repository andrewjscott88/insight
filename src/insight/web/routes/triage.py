"""Review decisions and notes."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request

from ... import services
from ...models import SessionFactory
from ...schemas import (
    DocumentReview,
    NoteInput,
    ObservationReview,
)
from ..auth import AuthDependency, acting, reader_limit


def _register_triage_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Analyst actions: report triage status, observation review and notes (all audited)."""

    @app.post('/api/documents/{doc_id}/review', dependencies=[Depends(require_auth)])
    def review_document(request: Request, doc_id: str, payload: DocumentReview) -> dict[str, str]:
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            if services.set_document_status(db, doc_id, payload.status, max_tlp=limit) is None:
                raise HTTPException(404, 'Report not found')
        return {'status': payload.status}

    @app.post('/api/observations/{obs_id}/review', dependencies=[Depends(require_auth)])
    def review_observation(request: Request, obs_id: str, payload: ObservationReview) -> dict[str, str]:
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            if services.set_observation_status(db, obs_id, payload.status, max_tlp=limit) is None:
                raise HTTPException(404, 'Observation not found')
        return {'status': payload.status}

    @app.post('/api/documents/{doc_id}/notes', dependencies=[Depends(require_auth)])
    def add_note(request: Request, doc_id: str, payload: NoteInput) -> dict[str, str]:
        with acting(sessions, request) as db:
            note = services.add_note(db, doc_id, payload.body, max_tlp=reader_limit(request))
            if note is None:
                raise HTTPException(404, 'Report not found')
            return {'id': note.id}
