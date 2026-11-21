"""Hunt records and detection rules for threat guides (TIP 2.10; TIP 2.7 minimum; ADR 0025).

Rules are carried as text: stored, linked and exported, never compiled or run. Hunts record what was checked
for each hypothesis. Every change is audited; labels above the caller's or the instance's limit are refused.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from ... import services
from ...models import DetectionRule, Hunt, SessionFactory
from ...schemas import HuntCheckInput, HuntInput, HuntUpdate, RuleInput, RuleLinkInput, RuleTarget
from ..auth import AuthDependency, acting, reader_limit
from .threats import write_limit


def hunt_view(hunt: Hunt, checks: dict[str, tuple[str, str, str, str, str]]) -> dict[str, Any]:
    return {
        'id': hunt.id,
        'ref': hunt.group_ref,
        'title': hunt.title,
        'status': hunt.status,
        'summary': hunt.summary,
        'tlp': hunt.effective_tlp,
        'created_at': hunt.created_at,
        'updated_at': hunt.updated_at,
        'created_by': hunt.actor,
        'checks': [
            {'technique': t, 'result': c[0], 'data_checked': c[1], 'from': c[2], 'to': c[3], 'notes': c[4]}
            for t, c in checks.items()
        ],
    }


def rule_view(
    rule: DetectionRule, links: tuple[tuple[str, str], ...] | list[tuple[str, str]], tlp: str
) -> dict[str, Any]:
    return {
        'id': rule.id,
        'kind': rule.kind,
        'name': rule.name,
        'source_url': rule.source_url,
        'licence': rule.licence,
        'sha256': rule.content_hash,
        'tlp': tlp,
        'created_at': rule.created_at,
        'created_by': rule.actor,
        'linked_to': [{'kind': k, 'id': i} for k, i in links],
        'body': rule.body,
    }


def _errors(exc: Exception) -> HTTPException:
    if isinstance(exc, services.TlpNotPermitted):
        return HTTPException(403, str(exc))
    if isinstance(exc, LookupError):
        return HTTPException(404, str(exc).strip("'"))
    return HTTPException(422, str(exc))


def _register_hunting_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Hunts started from a guide, and the YARA and Sigma rules linked to groups and techniques."""

    @app.get('/api/actors/{ref}/hunts', dependencies=[Depends(require_auth)])
    def hunts(request: Request, ref: str) -> list[dict[str, Any]]:
        limit = reader_limit(request)
        with sessions() as db:
            try:
                subject = services.resolve_group(db, ref, max_tlp=limit)
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            return [
                hunt_view(h, services.hunt_checks(db, h.id))
                for h in services.hunts_for(db, subject.ref, max_tlp=limit)
            ]

    @app.post('/api/actors/{ref}/hunts', status_code=201, dependencies=[Depends(require_auth)])
    def start(request: Request, ref: str, payload: HuntInput) -> dict[str, Any]:
        """Start a hunt record for the group. Audited as ``hunt.start``."""
        try:
            with acting(sessions, request) as db:
                return hunt_view(services.start_hunt(db, ref, payload, max_tlp=write_limit(app, request)), {})
        except (LookupError, ValueError) as exc:
            raise _errors(exc) from exc

    @app.get('/api/hunts/{hunt_id}', dependencies=[Depends(require_auth)])
    def hunt(request: Request, hunt_id: str) -> dict[str, Any]:
        with sessions() as db:
            found = services.get_hunt(db, hunt_id, max_tlp=reader_limit(request))
            if found is None:
                raise HTTPException(404, 'Hunt not found')
            return hunt_view(found, services.hunt_checks(db, found.id))

    @app.put('/api/hunts/{hunt_id}', dependencies=[Depends(require_auth)])
    def update(request: Request, hunt_id: str, payload: HuntUpdate) -> dict[str, Any]:
        """Close or reopen a hunt and set its summary. Audited as ``hunt.update``."""
        try:
            with acting(sessions, request) as db:
                found = services.update_hunt(db, hunt_id, payload, max_tlp=reader_limit(request))
                return hunt_view(found, services.hunt_checks(db, found.id))
        except (LookupError, ValueError) as exc:
            raise _errors(exc) from exc

    @app.put('/api/hunts/{hunt_id}/checks/{technique_id}', dependencies=[Depends(require_auth)])
    def check(request: Request, hunt_id: str, technique_id: str, payload: HuntCheckInput) -> dict[str, Any]:
        """Record what was checked for one hypothesis, over which dates, and the result. Audited."""
        try:
            with acting(sessions, request) as db:
                row = services.record_check(db, hunt_id, technique_id, payload, max_tlp=reader_limit(request))
                return {'hunt': hunt_id, 'technique': row.technique_id, 'result': row.result}
        except (LookupError, ValueError) as exc:
            raise _errors(exc) from exc

    @app.get('/api/rules', dependencies=[Depends(require_auth)])
    def rules(
        request: Request,
        kind: Literal['yara', 'sigma'] | None = None,
        target_kind: RuleTarget | None = None,
        target_id: Annotated[str | None, Query(min_length=1, max_length=36)] = None,
    ) -> list[dict[str, Any]]:
        if (target_kind is None) != (target_id is None):
            raise HTTPException(422, 'Provide target_kind and target_id together')
        target = (
            RuleLinkInput(target_kind=target_kind, target_id=target_id) if target_kind and target_id else None
        )
        try:
            with sessions() as db:
                return [
                    rule_view(r.rule, r.links, r.tlp)
                    for r in services.list_rules(db, max_tlp=reader_limit(request), kind=kind, target=target)
                ]
        except (LookupError, ValueError) as exc:
            raise _errors(exc) from exc

    @app.post('/api/rules', status_code=201, dependencies=[Depends(require_auth)])
    def add(request: Request, payload: RuleInput) -> dict[str, Any]:
        """Store a YARA or Sigma rule (carried as text, never run). Audited as ``rule.add``."""
        try:
            with acting(sessions, request) as db:
                rule = services.add_rule(db, payload, max_tlp=write_limit(app, request))
                return rule_view(rule, [], rule.tlp)
        except ValueError as exc:
            raise _errors(exc) from exc

    @app.get('/api/rules/{rule_id}', dependencies=[Depends(require_auth)])
    def rule(request: Request, rule_id: str) -> dict[str, Any]:
        with sessions() as db:
            found = services.get_rule(db, rule_id, max_tlp=reader_limit(request))
            if found is None:
                raise HTTPException(404, 'Rule not found')
            linked = services.linked_rules(db, [found], max_tlp=reader_limit(request))[0]
            return rule_view(found, linked.links, linked.tlp)

    @app.get('/api/rules/{rule_id}/export', dependencies=[Depends(require_auth)], response_class=Response)
    def download_rule(request: Request, rule_id: str) -> Response:
        try:
            with acting(sessions, request) as db:
                archive = services.export_rule(db, rule_id, max_tlp=write_limit(app, request))
        except LookupError as exc:
            raise _errors(exc) from exc
        return Response(
            archive,
            media_type='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="insight-rule-{rule_id}.zip"',
                'Cache-Control': 'no-store',
            },
        )

    @app.delete('/api/rules/{rule_id}', dependencies=[Depends(require_auth)])
    def delete(request: Request, rule_id: str) -> dict[str, str]:
        """Delete a rule and its links. Audited as ``rule.delete``."""
        try:
            with acting(sessions, request) as db:
                services.delete_rule(db, rule_id, max_tlp=reader_limit(request))
        except LookupError as exc:
            raise _errors(exc) from exc
        return {'deleted': rule_id}

    @app.post('/api/rules/{rule_id}/links', dependencies=[Depends(require_auth)])
    def link(request: Request, rule_id: str, payload: RuleLinkInput) -> dict[str, str]:
        """Link a rule to a group, an ATT&CK technique or a report. Audited as ``rule.link``."""
        try:
            with acting(sessions, request) as db:
                row = services.link_rule(db, rule_id, payload, max_tlp=reader_limit(request))
                return {'rule': rule_id, 'kind': row.target_kind, 'id': row.target_id}
        except (LookupError, ValueError) as exc:
            raise _errors(exc) from exc

    @app.delete('/api/rules/{rule_id}/links', dependencies=[Depends(require_auth)])
    def unlink(request: Request, rule_id: str, payload: RuleLinkInput) -> dict[str, str]:
        """Remove a link made by ``POST /api/rules/{id}/links``. Audited as ``rule.unlink``."""
        try:
            with acting(sessions, request) as db:
                services.unlink_rule(db, rule_id, payload, max_tlp=reader_limit(request))
        except (LookupError, ValueError) as exc:
            raise _errors(exc) from exc
        return {'unlinked': rule_id}
