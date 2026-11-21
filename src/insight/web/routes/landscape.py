"""The threat landscape: what is trending in the caller's reports, as JSON and as a Markdown briefing."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request, Response

from ... import __version__, services
from ...brief import DEMO, MAX_DAYS, window_start
from ...briefing import to_markdown
from ...landscape import Landscape, compose, period_start
from ...models import SessionFactory
from ..auth import AuthDependency, acting, reader_limit

Days = Annotated[
    int, Query(ge=1, le=MAX_DAYS, description='The last N days, compared with the 4 periods before')
]


def _register_landscape_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    def build(request: Request, days: int, now: datetime) -> Landscape:
        since = window_start(now, days)
        limit = reader_limit(request)
        with sessions() as db:
            data = services.landscape_data(db, start=period_start(now, days), max_tlp=limit, ignore=DEMO)
            brief = services.brief_data(db, since=since, max_tlp=limit)
        return compose(data, brief, since=since, days=days)

    @app.get('/api/landscape', dependencies=[Depends(require_auth)])
    def landscape(request: Request, days: Days = 7) -> dict[str, Any]:
        """The threat landscape for the last ``days`` days, from the reports this caller may see."""
        return asdict(build(request, days, datetime.now(UTC)))

    @app.get('/api/landscape/briefing', dependencies=[Depends(require_auth)])
    def briefing(request: Request, days: Days = 7) -> Response:
        """The same as a Markdown briefing to share, marked with its TLP label. Audited."""
        now = datetime.now(UTC)
        result = build(request, days, now)
        with acting(sessions, request) as db:
            detail = {'days': days, 'tlp': result.tlp, 'max_tlp': reader_limit(request)}
            services.audit(db, 'landscape.briefing', 'landscape', json.dumps(detail, sort_keys=True))
        return Response(
            to_markdown(result, generated=services.stamp(now), version=__version__),
            media_type='text/markdown; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename="insight-threat-landscape-{days}d.md"'},
        )
