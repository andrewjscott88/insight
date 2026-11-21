"""Industry threat profiles and actor threat guides (TIP 2.10, ADR 0025): industries, groups, guides, exports.

Reads take the caller's TLP limit; writes that carry a label also respect the instance limit
(``INSIGHT_MAX_TLP``). Guide exports may be made at a stricter label than the caller's (``max_tlp``) and are
audited, like every other export.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from ... import services
from ...industries import INDUSTRIES
from ...models import SessionFactory, ThreatActor
from ...schemas import TLP, ActorInput, ActorLinkInput, IndustryClaimInput
from ...threat_guide import ThreatGuide, compose, guide_json, navigator_layer, sweep_csv, sweep_json
from ...threat_guide_markdown import to_markdown
from ...threat_library import Claim, Group, library
from ..auth import AuthDependency, acting, reader_limit

Top = Annotated[int, Query(ge=1, le=10, description='How many groups to list (at most 10)')]
Days = Annotated[int, Query(ge=1, le=3650, description='Count reports naming each group in the last N days')]
ExportTlp = Annotated[TLP | None, Query(description='Leave out anything above this label')]
LinkedOnly = Annotated[
    bool,
    Query(
        description='Sweep list indicators only from reports linked to the group (default). '
        'false also takes them from reports that only name it; such reports are listed either way'
    ),
]


def write_limit(app: FastAPI, request: Request) -> str | None:
    """The label a write may carry: the stricter of the instance limit and the caller's."""
    return services.stricter_limit(app.state.settings.max_tlp, reader_limit(request))


def claim_view(claim: Claim) -> dict[str, Any]:
    return {
        'industries': list(claim.industries),
        'source': claim.source_name,
        'evidence': claim.evidence,
        'url': claim.url,
        'citations': [{'name': c.name, 'url': c.url} for c in claim.citations],
        'match': claim.match,
    }


def group_summary(group: Group) -> dict[str, Any]:
    return {
        'ref': group.id,
        'kind': 'catalog',
        'name': group.name,
        'aliases': list(group.aliases),
        'url': group.url,
        'industries': list(group.industries),
        'techniques': len(group.techniques),
    }


def actor_view(actor: ThreatActor) -> dict[str, Any]:
    return {
        'ref': actor.id,
        'kind': 'analyst',
        'name': actor.name,
        'aliases': [a for a in actor.aliases.split('\n') if a],
        'description': actor.description,
        'attack_group_id': actor.attack_group_id,
        'tlp': actor.tlp,
        'created_at': actor.created_at,
        'created_by': actor.actor,
    }


def entry_view(rank: int, entry: services.ProfileEntry) -> dict[str, Any]:
    subject = entry.subject
    activity = entry.last_activity
    return {
        'rank': rank,
        'ref': subject.ref,
        'kind': subject.kind,
        'name': subject.name,
        'aliases': list(subject.aliases),
        'tlp': subject.tlp,
        'reports_naming_it': entry.mentions,
        'last_named_at': entry.last_mention,
        'latest_public_activity': None
        if activity is None
        else {
            'campaign': activity.id,
            'name': activity.name,
            'last_seen': activity.last_seen,
            'url': activity.url,
        },
        'attack_techniques': entry.techniques,
        'evidence': [claim_view(c) for c in entry.claims],
        'reasons': list(entry.reasons),
    }


def _download(body: str, media_type: str, filename: str) -> Response:
    return Response(
        body, media_type=media_type, headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


def _register_threat_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Industries, the groups that target them, the analyst's actors, and threat guides."""

    @app.get('/api/industries', dependencies=[Depends(require_auth)])
    def industries(request: Request) -> dict[str, Any]:
        """The industries, each with how many groups a cited source names for it."""
        with sessions() as db:
            counts = services.industry_counts(db, max_tlp=reader_limit(request))
        lib = library()
        return {
            'library': {'edition': lib.edition, 'attack': lib.attack_version, 'sources': lib.sources},
            'industries': [
                {'key': i.key, 'name': i.name, 'covers': i.covers, 'groups': counts[i.key]}
                for i in INDUSTRIES
            ],
        }

    @app.get('/api/industries/{key}/actors', dependencies=[Depends(require_auth)])
    def industry_actors(request: Request, key: str, days: Days = 90, top: Top = 10) -> dict[str, Any]:
        """The top groups that cited sources name for the industry, with the evidence for each."""
        with sessions() as db:
            try:
                profile = services.industry_profile(
                    db, key, max_tlp=reader_limit(request), now=datetime.now(UTC), days=days, top=top
                )
            except LookupError as exc:
                raise HTTPException(404, 'Unknown industry') from exc
        return {
            'industry': {'key': profile.industry.key, 'name': profile.industry.name},
            'tlp': profile.tlp,
            'days': profile.days,
            'candidates': profile.candidates,
            'reports_read': profile.scanned,
            'reports_capped': profile.capped,
            'ranking': 'Reports naming the group in the period, then latest public activity, then techniques',
            'actors': [entry_view(n, e) for n, e in enumerate(profile.entries, start=1)],
            'removed_by_you': [
                {'ref': r.group_ref, 'reason': r.reason, 'tlp': r.effective_tlp} for r in profile.removed
            ],
        }

    @app.get('/api/actors', dependencies=[Depends(require_auth)])
    def actors(
        request: Request, q: Annotated[str, Query(max_length=100)] = '', limit: int = 50
    ) -> dict[str, Any]:
        """Groups in the threat library (searched by ID or name) and the actors you created."""
        with sessions() as db:
            own = services.list_actors(db, max_tlp=reader_limit(request))
        needle = q.strip().casefold()
        mine = [actor_view(a) for a in own if not needle or needle in f'{a.name}\n{a.aliases}'.casefold()]
        return {
            'library': {'edition': library().edition, 'attack': library().attack_version},
            'groups': [group_summary(g) for g in library().search(q, limit=min(max(1, limit), 200))],
            'actors': mine,
        }

    @app.post('/api/actors', status_code=201, dependencies=[Depends(require_auth)])
    def create(request: Request, payload: ActorInput) -> dict[str, Any]:
        """Create an actor you track, optionally the same as an ATT&CK group. Audited as ``actor.create``."""
        try:
            with acting(sessions, request) as db:
                return actor_view(services.create_actor(db, payload, max_tlp=write_limit(app, request)))
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get('/api/actors/{ref}', dependencies=[Depends(require_auth)])
    def actor(request: Request, ref: str) -> dict[str, Any]:
        """One group or actor: names, the industry claims with their sources, and linked reports."""
        limit = write_limit(app, request)
        with sessions() as db:
            try:
                subject = services.resolve_group(db, ref, max_tlp=limit)
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            mine = services.analyst_claims(db, max_tlp=limit, group_ref=subject.ref)
            linked = services.linked_reports(db, subject.ref, max_tlp=limit)
            group = subject.catalog
            return {
                'ref': subject.ref,
                'kind': subject.kind,
                'name': subject.name,
                'aliases': list(subject.aliases),
                'description': subject.description,
                'tlp': subject.tlp,
                'attack_group': None if group is None else group_summary(group),
                'industry_claims': [claim_view(c) for c in (group.claims if group else ())],
                'your_industry_decisions': [
                    {
                        'industry': c.industry,
                        'decision': c.decision,
                        'citation_url': c.citation_url,
                        'document_id': c.document_id,
                        'reason': c.reason,
                        'tlp': c.effective_tlp,
                        'by': c.actor,
                        'at': c.created_at,
                    }
                    for c in mine
                ],
                'linked_reports': [
                    {
                        'id': d.id,
                        'title': d.title,
                        'tlp': d.tlp,
                        'note': link.note,
                        'link_tlp': link.tlp,
                        'linked_at': link.created_at,
                    }
                    for d, link in linked
                ],
            }

    @app.post('/api/actors/{ref}/documents', status_code=201, dependencies=[Depends(require_auth)])
    def link(request: Request, ref: str, payload: ActorLinkInput) -> dict[str, str]:
        """Link a report to the group (your decision, never inferred). Audited as ``actor.link``."""
        try:
            with acting(sessions, request) as db:
                row = services.link_report(db, ref, payload, max_tlp=write_limit(app, request))
                return {'ref': row.group_ref, 'document_id': row.document_id, 'note': row.note}
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.delete('/api/actors/{ref}/documents/{doc_id}', dependencies=[Depends(require_auth)])
    def unlink(request: Request, ref: str, doc_id: str) -> dict[str, str]:
        """Remove a link from the group to a report. Audited as ``actor.unlink``."""
        try:
            with acting(sessions, request) as db:
                services.unlink_report(db, ref, doc_id, max_tlp=write_limit(app, request))
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {'unlinked': doc_id}

    @app.post('/api/actors/{ref}/industries', dependencies=[Depends(require_auth)])
    def industry_claim(request: Request, ref: str, payload: IndustryClaimInput) -> dict[str, Any]:
        """Add an industry with a citation, or remove a catalog claim with a reason. Audited."""
        try:
            with acting(sessions, request) as db:
                row = services.record_industry_claim(db, ref, payload, max_tlp=write_limit(app, request))
                return {
                    'ref': row.group_ref,
                    'industry': row.industry,
                    'decision': row.decision,
                    'tlp': row.tlp,
                }
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    def build_guide(
        request: Request, ref: str, export_tlp: str | None, linked_only: bool, what: str
    ) -> ThreatGuide:
        limit = services.stricter_limit(export_tlp, reader_limit(request), app.state.settings.max_tlp)
        now = datetime.now(UTC)
        with acting(sessions, request) as db:
            try:
                data = services.guide_data(db, ref, max_tlp=limit, now=now, linked_only=linked_only)
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            detail = {'what': what, 'tlp': data.tlp, 'max_tlp': limit, 'linked_only': linked_only}
            services.audit(db, 'actor.guide', data.subject.ref, json.dumps(detail, sort_keys=True))
        return compose(data, library())

    @app.get('/api/actors/{ref}/guide', dependencies=[Depends(require_auth)])
    def guide(
        request: Request,
        ref: str,
        format: Literal['json', 'md'] = 'json',
        max_tlp: ExportTlp = None,
        linked_only: LinkedOnly = True,
    ) -> Response:
        """The threat guide as JSON or Markdown, marked with its TLP label. Audited as ``actor.guide``."""
        built = build_guide(request, ref, max_tlp, linked_only, f'guide.{format}')
        slug = built.data.subject.ref
        if format == 'md':
            return _download(
                to_markdown(built), 'text/markdown; charset=utf-8', f'insight-threat-guide-{slug}.md'
            )
        return Response(json.dumps(guide_json(built), indent=2), media_type='application/json')

    @app.get('/api/actors/{ref}/navigator', dependencies=[Depends(require_auth)])
    def navigator(request: Request, ref: str, max_tlp: ExportTlp = None) -> Response:
        """The group's techniques as an ATT&CK Navigator layer, marked with its TLP label. Audited."""
        built = build_guide(request, ref, max_tlp, True, 'navigator')
        body = json.dumps(navigator_layer(built), indent=2)
        return _download(body, 'application/json', f'insight-attack-layer-{built.data.subject.ref}.json')

    @app.get('/api/actors/{ref}/sweep', dependencies=[Depends(require_auth)])
    def sweep(
        request: Request,
        ref: str,
        format: Literal['json', 'csv'] = 'json',
        max_tlp: ExportTlp = None,
        linked_only: LinkedOnly = True,
    ) -> Response:
        """The indicator sweep list as JSON or CSV (to search for, not attribution). Audited."""
        built = build_guide(request, ref, max_tlp, linked_only, f'sweep.{format}')
        slug = built.data.subject.ref
        if format == 'csv':
            return _download(sweep_csv(built), 'text/csv; charset=utf-8', f'insight-sweep-{slug}.csv')
        return Response(json.dumps(sweep_json(built), indent=2), media_type='application/json')
