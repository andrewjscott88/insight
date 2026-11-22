"""A read-only TAXII 2.1 server for SIEMs and TIPs that poll Insight (TIP 3.1, ADR 0026).

API keys only: a signed-in browser is refused, and the workspace keeps its own STIX download. Each key reads
within its TLP limit. Nothing here writes, and no request can create a collection.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import JSONResponse

from ... import services
from ...models import SessionFactory
from ...taxii import (
    API_ROOT,
    COLLECTIONS,
    DEFAULT_PAGE,
    MAX_PAGE,
    TAXII_MEDIA_TYPE,
    TaxiiError,
    TaxiiObject,
    accepts_taxii,
    date_headers,
    envelope,
    manifest,
    select_page,
)
from ..auth import AuthDependency, acting, caller_of, reader_limit
from ..boundary import MAX_BODY_BYTES

PREFIX = '/taxii2/'
ROOT = f'{PREFIX}{API_ROOT}/'
Limit = Annotated[int | None, Query(ge=1, le=MAX_PAGE, description=f'Default {DEFAULT_PAGE}')]
Text = Annotated[str | None, Query(max_length=8192)]


def _taxii(content: dict[str, Any], status: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(content, status_code=status, media_type=TAXII_MEDIA_TYPE, headers=headers)


def _check(request: Request) -> None:
    if caller_of(request).kind != 'api_key':
        raise TaxiiError(403, 'TAXII is for API keys', 'Send an API key as Authorization: Bearer <key>.')
    if not accepts_taxii(request.headers.get('accept', '')):
        raise TaxiiError(406, 'Not acceptable', f'This server answers with {TAXII_MEDIA_TYPE}.')


def _register_taxii_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    auth = [Depends(require_auth)]

    @app.exception_handler(TaxiiError)
    async def taxii_error(_request: Request, exc: TaxiiError) -> JSONResponse:
        return _taxii(exc.body(), exc.status)

    def objects_of(request: Request, collection_id: str) -> list[TaxiiObject]:
        _check(request)
        with acting(sessions, request) as db:
            return services.taxii_collection_objects(db, collection_id, max_tlp=reader_limit(request))

    @app.get(PREFIX, dependencies=auth)
    def discovery(request: Request) -> JSONResponse:
        _check(request)
        root = f'{str(request.base_url).rstrip("/")}{ROOT}'
        return _taxii(
            {
                'title': 'Insight TAXII server',
                'description': 'Read-only TAXII 2.1 collections of reviewed indicators from Insight.',
                'default': root,
                'api_roots': [root],
            }
        )

    @app.get(ROOT, dependencies=auth)
    def api_root(request: Request) -> JSONResponse:
        _check(request)
        return _taxii(
            {
                'title': 'Insight',
                'description': "Reviewed indicators, CVEs and their reports, within each key's TLP limit.",
                'versions': [TAXII_MEDIA_TYPE],
                'max_content_length': MAX_BODY_BYTES,
            }
        )

    @app.get(f'{ROOT}collections/', dependencies=auth)
    def collections(request: Request) -> JSONResponse:
        _check(request)
        return _taxii({'collections': list(COLLECTIONS.values())})

    @app.get(f'{ROOT}collections/{{collection_id}}/', dependencies=auth)
    def collection(request: Request, collection_id: str) -> JSONResponse:
        _check(request)
        if collection_id not in COLLECTIONS:
            raise TaxiiError(404, 'Collection not found')
        return _taxii(COLLECTIONS[collection_id])

    @app.get(f'{ROOT}collections/{{collection_id}}/objects/', dependencies=auth)
    def objects(
        request: Request,
        collection_id: str,
        added_after: Text = None,
        limit: Limit = None,
        next: Text = None,
        match_id: Annotated[str | None, Query(alias='match[id]', max_length=8192)] = None,
        match_type: Annotated[str | None, Query(alias='match[type]', max_length=8192)] = None,
        match_version: Annotated[str | None, Query(alias='match[version]', max_length=8192)] = None,
        match_spec_version: Annotated[str | None, Query(alias='match[spec_version]', max_length=64)] = None,
    ) -> JSONResponse:
        page = select_page(
            objects_of(request, collection_id),
            added_after=added_after,
            match_id=match_id,
            match_type=match_type,
            match_version=match_version,
            match_spec_version=match_spec_version,
            limit=limit,
            next_token=next,
        )
        return _taxii(envelope(page), headers=date_headers(page))

    @app.get(f'{ROOT}collections/{{collection_id}}/manifest/', dependencies=auth)
    def manifest_of(
        request: Request,
        collection_id: str,
        added_after: Text = None,
        limit: Limit = None,
        next: Text = None,
        match_id: Annotated[str | None, Query(alias='match[id]', max_length=8192)] = None,
        match_type: Annotated[str | None, Query(alias='match[type]', max_length=8192)] = None,
        match_version: Annotated[str | None, Query(alias='match[version]', max_length=8192)] = None,
    ) -> JSONResponse:
        page = select_page(
            objects_of(request, collection_id),
            added_after=added_after,
            match_id=match_id,
            match_type=match_type,
            match_version=match_version,
            limit=limit,
            next_token=next,
        )
        return _taxii(manifest(page), headers=date_headers(page))

    @app.get(f'{ROOT}collections/{{collection_id}}/objects/{{object_id}}/', dependencies=auth)
    def one_object(request: Request, collection_id: str, object_id: str) -> JSONResponse:
        page = select_page(objects_of(request, collection_id), match_id=object_id, limit=1)
        if not page.objects:
            raise TaxiiError(404, 'Object not found', 'It does not exist or is above your TLP limit.')
        return _taxii(envelope(page), headers=date_headers(page))

    @app.get(f'{ROOT}collections/{{collection_id}}/objects/{{object_id}}/versions/', dependencies=auth)
    def versions(request: Request, collection_id: str, object_id: str) -> JSONResponse:
        page = select_page(objects_of(request, collection_id), match_id=object_id, limit=1)
        if not page.objects:
            raise TaxiiError(404, 'Object not found', 'It does not exist or is above your TLP limit.')
        return _taxii({'more': False, 'versions': [page.objects[0].version]}, headers=date_headers(page))
