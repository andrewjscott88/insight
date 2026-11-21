"""Synthetic reviewed indicators and GreyNoise responses for offline tests."""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Observation
from insight.schemas import TLP, DocumentInput

IP = '8.8.8.8'
OTHER = '1.1.1.1'
ANSWER: dict[str, Any] = {
    'ip': IP,
    'classification': 'benign',
    'noise': True,
    'riot': False,
    'name': 'Synthetic Lab',
    'last_seen': '2026-11-20',
    'link': 'https://ignored.example/tracker',
    'message': 'untrusted words',
}


def reviewed(
    db: Session,
    ip: str = IP,
    *,
    tlp: TLP = 'CLEAR',
    status: str = 'accepted',
    source: services.SourceRef | None = None,
) -> str:
    doc, _ = services.ingest(
        db,
        DocumentInput(title='Synthetic observation', source_name='Fixture', body=f'Observed {ip}', tlp=tlp),
        ref=source,
    )
    for obs in db.scalars(select(Observation).where(Observation.document_id == doc.id)):
        obs.review_status = status
    return doc.id


def provider_error(code: int, wait: str = '') -> httpx.HTTPStatusError:
    req = httpx.Request('GET', 'https://synthetic.example/test')
    resp = httpx.Response(code, request=req, headers={'Retry-After': wait}, json={'message': 'PRIVATE-RAW'})
    return httpx.HTTPStatusError('PRIVATE-RAW', request=req, response=resp)
