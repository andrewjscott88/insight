"""The prioritised CVE view as JSON (TIP 1.3): the CVEs in the caller's reports, most urgent first."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Query, Request

from ... import services
from ...brief import DEMO
from ...cve_priority import PrioritisedCve, details, rank
from ...models import SessionFactory
from ..auth import AuthDependency, reader_limit

MAX_CVE_DAYS: Final = 365


def cve_view(item: PrioritisedCve) -> dict[str, Any]:
    signal = item.signal
    kev = signal.kev
    return {
        'cve': signal.cve,
        'tier': item.tier,
        'label': item.label,
        'reason': item.reason,
        'details': details(item),
        'reports': signal.reports,
        'sources': signal.sources,
        'first_seen': signal.first_seen,
        'last_seen': signal.last_seen,
        'report': {'id': signal.report_id, 'title': signal.report_title},
        'kev': None
        if kev is None
        else {
            'date_added': kev.date_added,
            'due_date': kev.due_date,
            'ransomware': kev.ransomware,
            'name': kev.name,
            'document_id': kev.document_id or None,
        },
        'cvss': {'score': item.cvss, 'source': item.cvss_source or None, 'csaf': signal.csaf_score},
        'nvd': asdict(signal.scores.nvd) if signal.scores.nvd is not None else None,
        'epss': asdict(signal.scores.epss) if signal.scores.epss is not None else None,
    }


def _register_cve_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    @app.get('/api/cves', dependencies=[Depends(require_auth)])
    def prioritised_cves(
        request: Request,
        days: Annotated[int, Query(ge=1, le=MAX_CVE_DAYS)] = 30,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        """The CVEs that reports received in the last ``days`` days mention, most urgent first."""
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with sessions() as db:
            found = services.cve_signals(db, since=since, max_tlp=reader_limit(request), ignore=DEMO)
        ranked = rank(found.signals)
        return {
            'days': days,
            'since': since,
            'total': len(ranked),
            'truncated': found.truncated,
            'cves': [cve_view(item) for item in ranked[:limit]],
        }
