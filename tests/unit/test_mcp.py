"""Bounded MCP read projections, publisher rules, schemas and no intelligence writes."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy.orm import Session

from insight import services
from insight.mcp import TOOL_BY_NAME
from insight.models import Base
from insight.schemas import (
    ActorInput,
    ActorLinkInput,
    AssessmentInput,
    DocumentInput,
    HuntPackageInput,
    HuntPackageItemInput,
    McpIdInput,
    McpInput,
    McpSearchInput,
    RequirementInput,
)
from insight.source_registry import METADATA_ONLY


def call(db: Session, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return services.mcp_read(db, name, TOOL_BY_NAME[name].schema.model_validate(args), max_tlp='GREEN')


def test_report_search_and_summary_honor_publisher_reuse(db: Session) -> None:
    body = 'Publisher private words and 192.0.2.33.'
    restricted, _ = services.ingest(
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
    result = call(db, 'get_report_summary', {'id': restricted.id})
    assert result['text_withheld']
    assert result['summary'] is None
    assert body not in json.dumps(result)
    assert call(db, 'get_report_summary', {'id': public.id})['summary'] == public.body


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


def test_requirement_hunt_group_and_landscape_reads_change_no_rows(db: Session) -> None:
    doc, _ = services.ingest(
        db,
        DocumentInput(
            title='Ransomware',
            body='Ransomware encrypted files at 192.0.2.55. PrivateWatchTerm.',
            source_name='Lab',
            tlp='GREEN',
        ),
    )
    requirement = services.create_requirement(
        db, RequirementInput(kind='rfi', question='Which files?', tlp='GREEN')
    )
    package = services.create_hunt_package(
        db,
        HuntPackageInput(
            title='Lab hunt',
            hypothesis='Look for files.',
            tlp='GREEN',
            items=[HuntPackageItemInput(kind='document', target_id=doc.id)],
        ),
    )
    actor = services.create_actor(db, ActorInput(name='Lab actor', tlp='GREEN'))
    services.add_watch_term(db, 'PrivateWatchTerm')
    db.flush()

    def snapshot() -> dict[str, list[tuple[Any, ...]]]:
        return {
            table.name: [tuple(row) for row in db.execute(table.select())]
            for table in Base.metadata.sorted_tables
        }

    before = snapshot()
    assert call(db, 'search_reports', {'q': 'Ransomware'})['total'] == 1
    entity = services.list_entities(db, '192.0.2.55')[0][0]
    assert call(db, 'get_indicator', {'id': entity.id})['reports'] == 1
    assert call(db, 'search_indicators', {'q': '192.0.2.55'})['indicators'][0]['id'] == entity.id
    assert call(db, 'get_report_summary', {'id': doc.id})['title'] == doc.title
    assert call(db, 'list_requirements', {'kind': 'rfi'})['requirements'][0]['id'] == requirement.id
    assert call(db, 'get_hunt_package', {'id': package.id})['items'][0]['target_id'] == doc.id
    assert call(db, 'get_threat_group', {'id': actor.id})['name'] == 'Lab actor'
    assert call(db, 'get_threat_group', {'id': 'G0016'})['techniques']
    landscape = call(db, 'get_landscape_summary', {'days': 7})
    assert landscape['reports'] >= 1
    assert 'PrivateWatchTerm' not in json.dumps(landscape)
    assert before == snapshot()


@pytest.mark.parametrize(
    'name', ['get_indicator', 'get_report_summary', 'get_hunt_package', 'get_threat_group']
)
def test_missing_ids_are_not_found(db: Session, name: str) -> None:
    with pytest.raises(LookupError):
        call(db, name, {'id': 'missing'})


def test_unknown_or_mismatched_service_dispatch_is_refused(db: Session) -> None:
    with pytest.raises(ValueError, match='Unknown tool'):
        services.mcp_read(db, 'write', McpInput(), max_tlp='GREEN')
    for name in ('get_report_summary', 'get_indicator'):
        with pytest.raises(ValueError, match='Unknown tool'):
            services.mcp_read(db, name, McpSearchInput(q='x'), max_tlp='GREEN')


def test_group_response_preserves_the_stricter_link_label(db: Session) -> None:
    """Regression: a CLEAR catalog group with an AMBER link must not label the combined profile CLEAR."""
    doc, _ = services.ingest(
        db, DocumentInput(title='Green report', body='Observed activity.', source_name='Lab', tlp='GREEN')
    )
    services.link_report(db, 'G0016', ActorLinkInput(document_id=doc.id, tlp='AMBER'))
    result = services.mcp_read(db, 'get_threat_group', McpIdInput(id='G0016'), max_tlp='AMBER')
    assert result['tlp'] == 'AMBER'
    assert result['subject_tlp'] == 'CLEAR'
    assert result['linked_reports'][0]['tlp'] == 'GREEN'
    assert result['linked_reports'][0]['link_tlp'] == 'AMBER'
    assert call(db, 'get_threat_group', {'id': 'G0016'})['linked_reports'] == []


def test_group_truncation_retains_omitted_source_labels(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: an omitted AMBER link must label the truncation flag it influences."""
    from insight.models import ActorDocument, Document
    from insight.services import mcp
    from insight.services.actors import MAX_LINKED_REPORTS

    visible = Document(id='visible', title='Visible', tlp='CLEAR', source_url='')
    hidden = Document(id='omitted', title='Omitted', tlp='CLEAR', source_url='')
    ordinary = ActorDocument(tlp='CLEAR')
    restricted = ActorDocument(tlp='AMBER')
    rows = [(visible, ordinary)] * 50 + [(hidden, restricted)]
    monkeypatch.setattr(mcp, 'linked_reports', lambda *args, **kwargs: rows)
    result = services.mcp_read(db, 'get_threat_group', McpIdInput(id='G0016'), max_tlp='AMBER')
    assert result['truncated']
    assert result['tlp'] == 'AMBER'
    assert all(item['tlp'] == item['link_tlp'] == 'CLEAR' for item in result['linked_reports'])
    rows[:] = [(visible, ordinary)] * MAX_LINKED_REPORTS
    assert services.mcp_read(db, 'get_threat_group', McpIdInput(id='G0016'), max_tlp=None)['tlp'] == 'RED'


def test_hunt_package_withholds_publisher_text_and_rule_code(db: Session) -> None:
    """Regression: hunt references must not become a second path for restricted publisher text."""
    doc, _ = services.ingest(
        db,
        DocumentInput(
            title='Permitted citation', body='Restricted publisher words.', source_name='Lab', tlp='GREEN'
        ),
        ref=services.SourceRef(sorted(METADATA_ONLY)[0], 'hunt-citation'),
    )
    package = services.create_hunt_package(
        db,
        HuntPackageInput(
            title='Analyst hunt',
            hypothesis='Analyst hypothesis.',
            tlp='GREEN',
            items=[HuntPackageItemInput(kind='document', target_id=doc.id)],
        ),
    )
    result = call(db, 'get_hunt_package', {'id': package.id})
    assert result['items'][0]['name'] == doc.title
    assert result['hypothesis'] == 'Analyst hypothesis.'
    assert doc.body not in json.dumps(result)
    assert set(result['items'][0]) == {'id', 'kind', 'target_id', 'name', 'tlp', 'added_at', 'added_by'}
