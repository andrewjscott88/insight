"""Entities and pivots, and analysts' verdicts on them."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from ... import services
from ...flags import flags
from ...models import EntityAssessment, SessionFactory
from ...schemas import AssessmentInput
from ..auth import AuthDependency, acting, reader_limit
from .confidence import confidence_view
from .cves import exploit_view


def assessment_view(assessment: EntityAssessment | None) -> dict[str, Any] | None:
    if assessment is None:
        return None
    return {
        'verdict': assessment.verdict,
        'reason': assessment.reason,
        'tlp': assessment.tlp,
        'valid_until': assessment.valid_until,
        'decided_at': assessment.decided_at,
        'actor': assessment.actor,
    }


def _register_entity_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Canonical indicators and their cross-report pivots."""

    @app.get('/api/entities', dependencies=[Depends(require_auth)])
    def entities(request: Request, q: str = '') -> list[dict[str, Any]]:
        with sessions() as db:
            return [
                {'id': e.id, 'kind': e.kind, 'value': e.value, 'document_count': count}
                for e, count in services.list_entities(db, q, max_tlp=reader_limit(request))
            ]

    @app.get('/api/entities/{entity_id}', dependencies=[Depends(require_auth)])
    def entity(request: Request, entity_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        max_tlp = reader_limit(request)
        with sessions() as db:
            e = services.get_entity(db, entity_id)
            # An entity mentioned only in reports the caller cannot see does not exist for that caller.
            count = 0 if e is None else services.count_entity_documents(db, e.id, max_tlp=max_tlp)
            if e is None or (max_tlp is not None and count == 0):
                raise HTTPException(404, 'Entity not found')
            docs = services.entity_documents(db, e.id, offset=offset, limit=limit, max_tlp=max_tlp)
            first_seen, last_seen = services.entity_seen(db, e.id, max_tlp=max_tlp)
            # TIP 3.3: exploit availability for a CVE, from reports this caller may see and VulnCheck KEV.
            exploit = (
                services.exploit_context(db, [e.value], max_tlp=max_tlp).get(e.value)
                if e.kind == 'cve'
                else None
            )
            return {
                'id': e.id,
                'kind': e.kind,
                'value': e.value,
                'flags': list(flags(e.kind, e.value)),
                'assessment': assessment_view(services.entity_assessment(db, e.id, max_tlp=max_tlp)),
                'first_seen_at': first_seen,
                'last_seen_at': last_seen,
                'document_count': count,
                'offset': max(0, offset),
                'documents': services.summaries(db, docs),
                'exploit': exploit_view(exploit),
                # TIP 4.2: how strongly the reports this caller may see support it.
                'confidence': confidence_view(services.indicator_confidence(db, e.id, max_tlp=max_tlp)),
            }

    @app.post('/api/entities/{entity_id}/assessment', dependencies=[Depends(require_auth)])
    def assess(request: Request, entity_id: str, payload: AssessmentInput) -> dict[str, Any]:
        """Record an analyst's verdict (``unknown`` clears it). Audited as ``entity.assess``."""
        try:
            with acting(sessions, request) as db:
                assessment = services.assess_entity(db, entity_id, payload, max_tlp=reader_limit(request))
                view = assessment_view(assessment)
        except LookupError as exc:
            raise HTTPException(404, 'Entity not found') from exc
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc
        return view or {'verdict': 'unknown'}
