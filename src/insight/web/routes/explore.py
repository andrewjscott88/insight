"""Ranked search and the link graph (TIP 3.2, ADR 0027). Both read only what the caller's TLP limit allows."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from ... import services
from ...models import SessionFactory
from ...schemas import TLP, DocumentStatus
from ...services.graph import MAX_DEPTH
from ...services.search import MAX_PAGE_SIZE, MAX_QUERY_LENGTH
from ..auth import AuthDependency, reader_limit


def graph_view(graph: services.Graph) -> dict[str, Any]:
    return {
        'seed': graph.seed,
        'capped': graph.capped,
        'nodes': [
            {
                'id': n.id,
                'type': n.type,
                'label': n.label,
                'detail': n.detail,
                'depth': n.depth,
                'truncated': n.truncated,
            }
            for n in graph.nodes
        ],
        'edges': [{'source': e.source, 'target': e.target, 'kind': e.kind} for e in graph.edges],
    }


def _register_explore_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    @app.get('/api/search', dependencies=[Depends(require_auth)])
    def search(
        request: Request,
        q: Annotated[str, Query(min_length=1, max_length=MAX_QUERY_LENGTH)],
        status: DocumentStatus | None = None,
        tlp: TLP | None = None,
        include_superseded: bool = False,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    ) -> dict[str, Any]:
        """Reports matching every word of ``q`` (quotes keep a phrase together), best first."""
        with sessions() as db:
            page = services.ranked_search(
                db,
                q,
                status=status,
                tlp=tlp,
                include_superseded=include_superseded,
                max_tlp=reader_limit(request),
                offset=offset,
                limit=limit,
            )
            return {
                'terms': list(page.terms),
                'total': page.total,
                'capped': page.capped,
                'results': [
                    {
                        **services.summary(db, hit.document),
                        'score': round(hit.score, 4),
                        'matched_in_title': list(hit.matched_in_title),
                        'snippet': hit.snippet,
                    }
                    for hit in page.hits
                ],
            }

    @app.get('/api/graph', dependencies=[Depends(require_auth)])
    def graph(
        request: Request,
        node: Annotated[str, Query(min_length=3, max_length=60, pattern=r'^[a-z]+:[A-Za-z0-9._-]+$')],
        depth: Annotated[int, Query(ge=1, le=MAX_DEPTH)] = 1,
    ) -> dict[str, Any]:
        """Links around one node: ``report:<id>``, ``indicator:<entity id>``, ``technique:T1059``,
        ``group:G0016``, ``actor:<id>`` or ``campaign:<id>``."""
        with sessions() as db:
            try:
                return graph_view(services.build_graph(db, node, depth=depth, max_tlp=reader_limit(request)))
            except LookupError:
                raise HTTPException(404, 'Not found') from None
