"""The permission each API route needs (ADR 0046), looked up by ``require_auth`` for every request.

Routes are keyed by method and path template, exactly as registered. A route missing from this table is
refused, and ``tests/unit/test_architecture.py`` fails until it is added, so a new route never gets access by
accident. ``PUBLIC_ROUTES`` are the only routes without ``require_auth``.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from ..apikeys import FEEDBACK_INTAKE
from ..permissions import Permission, role_allows

log = logging.getLogger('insight.auth')

#: Reachable without signing in: liveness, and the sign-in and sign-out pages (each CSRF-protected).
PUBLIC_ROUTES: Final = frozenset(
    {('GET', '/health'), ('GET', '/login'), ('POST', '/login'), ('GET', '/logout'), ('POST', '/logout')}
)

_BY_PERMISSION: Final[dict[Permission, tuple[str, ...]]] = {
    Permission.READ: (
        'GET /api/actors',
        'GET /api/actors/{ref}',
        'GET /api/actors/{ref}/campaigns',
        'GET /api/actors/{ref}/guide',
        'GET /api/actors/{ref}/hunts',
        'GET /api/actors/{ref}/links',
        'GET /api/actors/{ref}/navigator',
        'GET /api/actors/{ref}/sweep',
        'GET /api/actors/{ref}/timeline',
        'GET /api/attack/navigator',
        'GET /api/attack/summary',
        'GET /api/attack/techniques',
        'GET /api/attack/techniques/{technique_id}/documents',
        'GET /api/audit',
        'GET /api/brief',
        'GET /api/campaigns',
        'GET /api/campaigns/{ref}',
        'GET /api/campaigns/{ref}/links',
        'GET /api/cases',
        'GET /api/cases/{case_id}',
        'GET /api/cases/{case_id}/export',
        'GET /api/cases/{case_id}/product',
        'GET /api/cases/{case_id}/timeline',
        'GET /api/cves',
        'GET /api/cves/{cve}/scores',
        'GET /api/documents',
        'GET /api/documents/{doc_id}',
        'GET /api/documents/{doc_id}/export',
        'GET /api/documents/{doc_id}/techniques',
        'GET /api/documents/{document_id}/requirements',
        'GET /api/documents/{document_id}/software',
        'GET /api/entities',
        'GET /api/entities/{entity_id}',
        'GET /api/entities/{entity_id}/confidence',
        'GET /api/graph',
        'GET /api/hunt-guides',
        'GET /api/hunt-guides/{kind}/{ref}',
        'GET /api/hunt-packages',
        'GET /api/hunt-packages/{package_id}',
        'GET /api/hunt-packages/{package_id}/stix',
        'GET /api/hunts/{hunt_id}',
        'GET /api/industries',
        'GET /api/industries/{key}/actors',
        'GET /api/iocs/blocklist',
        'GET /api/iocs/export',
        'GET /api/iocs/stix',
        'GET /api/ips/{ip}/censys',
        'GET /api/ips/{ip}/greynoise',
        'GET /api/ips/{ip}/shodan',
        'GET /api/jobs',
        'GET /api/landscape',
        'GET /api/landscape/briefing',
        'GET /api/operator-sources',
        'GET /api/operator-sources/{key}',
        'GET /api/pivots',
        'GET /api/requirements',
        'GET /api/requirements/{requirement_id}',
        'GET /api/rules',
        'GET /api/rules/{rule_id}',
        'GET /api/rules/{rule_id}/export',
        'GET /api/schedules',
        'GET /api/search',
        'GET /api/session',
        'GET /api/sightings',
        'GET /api/software',
        'GET /api/software/{ref}',
        'GET /api/software/{ref}/documents',
        'GET /api/software/{software_id}/navigator',
        'GET /api/source-ratings',
        'GET /api/sources',
        'GET /api/stats',
        'GET /api/watch-terms',
        'GET /taxii2/',
        'GET /taxii2/insight/',
        'GET /taxii2/insight/collections/',
        'GET /taxii2/insight/collections/{collection_id}/',
        'GET /taxii2/insight/collections/{collection_id}/manifest/',
        'GET /taxii2/insight/collections/{collection_id}/objects/',
        'GET /taxii2/insight/collections/{collection_id}/objects/{object_id}/',
        'GET /taxii2/insight/collections/{collection_id}/objects/{object_id}/versions/',
        # The MCP transport exposes only fixed read tools (ADR 0043).
        'POST /mcp',
    ),
    Permission.ADD_REPORTS: (
        'POST /api/documents',
        'POST /api/documents/pdf',
        'POST /api/import/stix',
    ),
    Permission.REVIEW: (
        'POST /api/documents/{doc_id}/review',
        'POST /api/observations/{obs_id}/review',
        'POST /api/entities/{entity_id}/assessment',
        'PUT /api/documents/{doc_id}/credibility',
        'PUT /api/source-ratings',
    ),
    Permission.NOTES_AND_LINKS: (
        'POST /api/documents/{doc_id}/notes',
        'POST /api/documents/{doc_id}/techniques',
        'DELETE /api/documents/{doc_id}/techniques/{technique_id}',
        'POST /api/actors',
        'POST /api/actors/{ref}/campaigns',
        'DELETE /api/actors/{ref}/campaigns/{campaign_id}',
        'POST /api/actors/{ref}/documents',
        'DELETE /api/actors/{ref}/documents/{doc_id}',
        'POST /api/actors/{ref}/industries',
        'POST /api/actors/{ref}/links',
        'DELETE /api/actors/{ref}/links/{target_kind}/{target_id}',
        'POST /api/campaigns',
        'POST /api/campaigns/{ref}/links',
        'DELETE /api/campaigns/{ref}/links/{target_kind}/{target_id}',
        'POST /api/software/{ref}/documents',
        'DELETE /api/software/{ref}/documents/{document_id}',
    ),
    Permission.PRODUCTS: (
        'POST /api/cases',
        'PATCH /api/cases/{case_id}',
        'DELETE /api/cases/{case_id}',
        'POST /api/cases/{case_id}/close',
        'POST /api/cases/{case_id}/reopen',
        'POST /api/cases/{case_id}/items',
        'DELETE /api/cases/{case_id}/items/{item_id}',
        'POST /api/cases/{case_id}/notes',
        'POST /api/cases/{case_id}/judgements',
        'PATCH /api/cases/{case_id}/judgements/{judgement_id}',
        'DELETE /api/cases/{case_id}/judgements/{judgement_id}',
        'POST /api/cases/{case_id}/gaps',
        'DELETE /api/cases/{case_id}/gaps/{gap_id}',
        'POST /api/cases/{case_id}/publish',
    ),
    Permission.REQUIREMENTS: (
        'POST /api/cases/{case_id}/gaps/{gap_id}/rfi',
        'POST /api/requirements',
        'PATCH /api/requirements/{requirement_id}',
        'DELETE /api/requirements/{requirement_id}',
        'POST /api/requirements/{requirement_id}/answer',
        'POST /api/requirements/{requirement_id}/reopen',
        'POST /api/requirements/{requirement_id}/retire',
        'POST /api/requirements/{requirement_id}/criteria',
        'DELETE /api/requirements/{requirement_id}/criteria/{criterion_id}',
        'POST /api/requirements/{requirement_id}/evidence',
        'DELETE /api/requirements/{requirement_id}/evidence/{evidence_id}',
        'POST /api/rfis',
    ),
    Permission.HUNTING: (
        'POST /api/actors/{ref}/hunts',
        'PUT /api/hunts/{hunt_id}',
        'PUT /api/hunts/{hunt_id}/checks/{technique_id}',
        'POST /api/hunt-packages',
        'PATCH /api/hunt-packages/{package_id}',
        'DELETE /api/hunt-packages/{package_id}',
        'POST /api/hunt-packages/{package_id}/items',
        'DELETE /api/hunt-packages/{package_id}/items/{item_id}',
        'POST /api/hunt-packages/{package_id}/publish',
        'POST /api/hunt-packages/{package_id}/retire',
        'POST /api/rules',
        'DELETE /api/rules/{rule_id}',
        'POST /api/rules/{rule_id}/links',
        'DELETE /api/rules/{rule_id}/links',
        'POST /api/sightings',
        'DELETE /api/sightings/{sighting_id}',
    ),
    Permission.SYNC_SOURCES: (
        'POST /api/sources/{key}/sync',
        'POST /api/sources/sync-all',
    ),
    Permission.LOOKUPS: (
        'POST /api/enrichment/{provider}/{cve}',
        'POST /api/enrichment/censys/{ip}',
        'POST /api/enrichment/greynoise/{ip}',
        'POST /api/enrichment/shodan/{ip}',
        'POST /api/pivots/{provider}',
    ),
    Permission.SOURCES: (
        'POST /api/operator-sources',
        'PUT /api/operator-sources/{key}',
        'DELETE /api/operator-sources/{key}',
        'PUT /api/operator-sources/{key}/switch',
    ),
    Permission.SCHEDULES: ('PUT /api/schedules/{key}',),
    Permission.DEMO: ('POST /api/demo',),
}


def _table(by_permission: Mapping[Permission, tuple[str, ...]]) -> Mapping[tuple[str, str], Permission]:
    table: dict[tuple[str, str], Permission] = {}
    for permission, routes in by_permission.items():
        for route in routes:
            method, _, path = route.partition(' ')
            if (method, path) in table:
                raise RuntimeError(f'{route} is listed twice in the route permissions')
            table[(method, path)] = permission
    return MappingProxyType(table)


#: ``(method, path template) -> permission`` for every route that requires authentication.
ROUTE_PERMISSIONS: Final = _table(_BY_PERMISSION)


def route_permission(method: str, template: str) -> Permission | None:
    """The permission a request to this route needs, or ``None`` (refused) when the route is not listed."""
    return ROUTE_PERMISSIONS.get(('GET' if method == 'HEAD' else method, template))


def route_allows(method: str, template: object, *, role: str | None, access: str) -> bool:
    """Whether a caller with ``role`` (and a key's ``access`` level) may use the matched route ``template``.

    Refuses by default: an unlisted route, or a request that matched none, is never allowed.
    """
    permission = route_permission(method, template) if isinstance(template, str) else None
    if permission is None:
        log.error('Refused %s %s: the route has no permission entry', method, template or '(none)')
        return False
    if role_allows(role, permission):
        return True
    # A read-feedback key acts as a viewer but may send these two kinds of feedback (TIP 4.1, 4.2).
    return access == 'read-feedback' and (method, template) in FEEDBACK_INTAKE
