"""Bounded MCP read projections, publisher rules, schemas and no intelligence writes."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy.orm import Session

from insight import services
from insight.mcp import TOOL_BY_NAME
from insight.schemas import (
    AssessmentInput,
    DocumentInput,
    McpInput,
    McpSearchInput,
)
from insight.source_registry import METADATA_ONLY


def call(db: Session, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return services.mcp_read(db, name, TOOL_BY_NAME[name].schema.model_validate(args), max_tlp='GREEN')


def test_report_search_and_summary_honor_publisher_reuse(db: Session) -> None:
    body = 'Publisher private words and 192.0.2.33.'
    _restricted, _ = services.ingest(
        db,
        DocumentInput(title='Permitted metadata', body=body, source_name='Publisher', tlp='GREEN'),
        ref=services.SourceRef(sorted(METADATA_ONLY)[0], 'sample'),
    )
    public, _ = services.ingest(
        db,
        DocumentInput(
            title='Permitted text', body='Public words 192.0.2.55.', source_name='Lab', tlp='GREEN'
        ),
    )
    result = call(db, 'search_reports', {'q': 'Publisher private'})['reports'][0]
    assert result['text_withheld']
    assert result['summary'] is None
    assert body not in json.dumps(result)
    searched = call(db, 'search_reports', {'q': 'Publisher private'})
    assert searched['total'] == 1
    assert searched['reports'][0]['summary'] is None
    assert call(db, 'search_reports', {'q': 'Public words'})['reports'][0]['summary'] == public.body


def test_indicator_uses_only_visible_verdict_confidence_and_dates(db: Session) -> None:
    green, _ = services.ingest(
        db, DocumentInput(title='Green', body='Observed 192.0.2.55.', source_name='Lab', tlp='GREEN')
    )
    amber, _ = services.ingest(
        db,
        DocumentInput(
            title='Secret',
            body='Observed 192.0.2.55 and 198.51.100.91.',
            source_name='Secret source',
            tlp='AMBER',
        ),
    )
    green.created_at = '2026-01-02T00:00:00+00:00'
    amber.created_at = '2026-01-01T00:00:00+00:00'
    entity = services.list_entities(db, '192.0.2.55')[0][0]
    services.assess_entity(
        db, entity.id, AssessmentInput(verdict='malicious', reason='Secret reason', tlp='AMBER')
    )
    result = call(db, 'get_indicator', {'id': entity.id})
    assert result['verdict'] == 'unknown'
    assert result['assessment'] is None
    assert result['reports'] == 1
    assert result['first_seen_at'] == green.created_at
    assert 'Secret' not in json.dumps(result)


@pytest.mark.parametrize('name', ['get_indicator'])
def test_missing_ids_are_not_found(db: Session, name: str) -> None:
    with pytest.raises(LookupError):
        call(db, name, {'id': 'missing'})


def test_unknown_or_mismatched_service_dispatch_is_refused(db: Session) -> None:
    with pytest.raises(ValueError, match='Unknown tool'):
        services.mcp_read(db, 'write', McpInput(), max_tlp='GREEN')
    with pytest.raises(ValueError, match='Unknown tool'):
        services.mcp_read(db, 'get_indicator', McpSearchInput(q='x'), max_tlp='GREEN')


def test_read_tools_do_not_change_intelligence(db: Session) -> None:
    from insight.models import Base

    services.ingest(
        db, DocumentInput(title='Sample', body='Observed 192.0.2.55.', source_name='Lab', tlp='GREEN')
    )
    entity = services.list_entities(db, '192.0.2.55')[0][0]
    db.flush()

    def snapshot() -> dict[str, list[tuple[Any, ...]]]:
        return {
            table.name: [tuple(row) for row in db.execute(table.select())]
            for table in Base.metadata.sorted_tables
        }

    before = snapshot()
    assert call(db, 'search_reports', {'q': 'Sample'})['total'] == 1
    assert call(db, 'get_indicator', {'id': entity.id})['reports'] == 1
    assert before == snapshot()
