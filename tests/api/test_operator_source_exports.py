"""Operator feed rights apply to previously ingested reports in every sharing format."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pypdf
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.cli import main
from insight.mcp import PROTOCOL_VERSION
from insight.schemas import CaseInput, CaseItemInput, DocumentInput, OperatorSourceInput
from insight.taxii import INDICATORS_COLLECTION, TAXII_MEDIA_TYPE


@dataclass(frozen=True)
class Sample:
    document_id: str
    source_key: str
    title: str
    quotation: str
    address: str
    share_text: bool


@dataclass(frozen=True)
class Corpus:
    samples: list[Sample]
    token: str
    case_id: str


@pytest.fixture
def corpus(app: FastAPI) -> Corpus:
    samples = []
    with app.state.session_factory.begin() as db:
        case = services.create_case(db, CaseInput(title='Analyst review', tlp='GREEN'))
        for index, condition in enumerate(
            ('public', 'default', 'tightened', 'deleted', 'unknown', 'curated', 'publisher'), 1
        ):
            spec = OperatorSourceInput(
                name=f'Publisher {condition}', url=f'https://{condition}.example/feed', tlp='GREEN'
            )
            if condition in ('public', 'tightened', 'deleted', 'publisher'):
                spec = spec.model_copy(update={'reuse': 'public'})
            if condition == 'unknown':
                source_key = 'op-' + 'a' * 32
            elif condition == 'curated':
                source_key = 'sans-isc'
            else:
                source_key = services.create_operator_source(db, spec).key
            title = f'Ransomware bulletin {condition}'
            quotation = f'Unique publisher wording for {condition}'
            address = f'192.0.2.{index}'
            doc, _ = services.ingest(
                db,
                DocumentInput(
                    title=title,
                    body=f'Cozy Bear. {quotation}. Observed {address}.',
                    source_name=spec.name,
                    source_url=f'https://{condition}.example/article',
                    tlp='GREEN',
                ),
                ref=services.SourceRef(source_key, 'entry-1'),
                operator_publisher_metadata_only=condition == 'publisher',
            )
            [obs] = services.detail(db, doc)['observations']
            services.set_observation_status(db, obs['id'], 'accepted')
            services.add_case_item(db, case.id, CaseItemInput(kind='document', target_id=doc.id))
            if index == 1:
                services.add_case_item(
                    db, case.id, CaseItemInput(kind='indicator', target_id=obs['entity_id'])
                )
            if condition == 'tightened':
                services.update_operator_source(db, source_key, spec.model_copy(update={'reuse': 'metadata'}))
            if condition == 'deleted':
                services.delete_operator_source(db, source_key)
            samples.append(Sample(doc.id, source_key, title, quotation, address, condition == 'public'))
        _, token = services.create_api_key(db, name='test reader', access='read', max_tlp='GREEN')
        return Corpus(samples, token, case.id)


def _get(client: TestClient, url: str, **kwargs: Any) -> str:
    response = client.get(url, **kwargs)
    assert response.status_code == 200, response.text
    return response.text


def _mcp(client: TestClient, token: str, tool: str, arguments: dict[str, str]) -> str:
    response = client.post(
        '/mcp',
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': PROTOCOL_VERSION,
        },
        json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': tool, 'arguments': arguments},
        },
    )
    assert response.status_code == 200
    result = response.json()['result']
    assert not result.get('isError')
    assert json.loads(result['content'][0]['text']) == result['structuredContent']
    return response.text


def test_report_download_mcp_summary_and_search(corpus: Corpus, authed: TestClient) -> None:
    search = _mcp(authed, corpus.token, 'search_reports', {'q': 'Ransomware bulletin'})
    for sample in corpus.samples:
        report = _get(authed, f'/api/documents/{sample.document_id}/export')
        summary = _mcp(authed, corpus.token, 'get_report_summary', {'id': sample.document_id})
        for artifact in (report, search, summary):
            assert sample.title in artifact
            assert (sample.quotation in artifact) == sample.share_text
        assert sample.address in report


def test_indicator_exports_apply_live_rights_to_every_source(
    corpus: Corpus, authed: TestClient, database_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    iocs = _get(authed, '/api/iocs/export?evidence=true')
    stix = _get(authed, '/api/iocs/stix?evidence=true')
    taxii = _get(
        authed,
        f'/taxii2/insight/collections/{INDICATORS_COLLECTION}/objects/',
        headers={'Authorization': f'Bearer {corpus.token}', 'Accept': TAXII_MEDIA_TYPE},
    )
    monkeypatch.setenv('INSIGHT_DATABASE_URL', database_url)
    path = tmp_path / 'event.json'
    assert main(['misp-export', str(path), '--include-evidence']) == 0
    misp = path.read_text(encoding='utf-8')
    for artifact in (iocs, stix, taxii, misp):
        for sample in corpus.samples:
            assert sample.address in artifact
            assert (sample.quotation in artifact) == sample.share_text
    for artifact in (stix, taxii):
        reports = {obj['name']: obj for obj in json.loads(artifact)['objects'] if obj['type'] == 'report'}
        for sample in corpus.samples:
            assert reports[sample.title]['x_insight_metadata_only'] == (not sample.share_text)


def test_guides_briefings_and_case_products_preserve_citations(corpus: Corpus, authed: TestClient) -> None:
    guide = _get(authed, '/api/actors/G0016/guide')
    guide_md = _get(authed, '/api/actors/G0016/guide?format=md')
    briefing = _get(authed, '/api/landscape/briefing')
    product = f'/api/cases/{corpus.case_id}/export'
    product_md = _get(authed, product + '?format=md')
    product_stix = _get(authed, product + '?format=stix')
    response = authed.get(product + '?format=pdf')
    assert response.status_code == 200
    pdf = pypdf.PdfReader(io.BytesIO(response.content))
    product_pdf = ' '.join(page.extract_text() for page in pdf.pages)
    for sample in corpus.samples:
        assert sample.title in guide
        assert (sample.quotation in guide) == sample.share_text
        for artifact in (product_md, product_stix, product_pdf):
            assert sample.title in artifact
            assert sample.quotation not in artifact
        if not sample.share_text:
            assert sample.quotation not in guide_md
            assert sample.quotation not in briefing


def test_identical_content_keeps_its_manual_and_operator_source_identities(
    app: FastAPI, authed: TestClient
) -> None:
    payload = DocumentInput(
        title='Shared title', body='A syndicated passage beside 192.0.2.9.', source_name='Wire', tlp='GREEN'
    )
    spec = OperatorSourceInput(name='First wire', url='https://first.example/feed', tlp='GREEN')
    with app.state.session_factory.begin() as db:
        restricted = services.create_operator_source(db, spec)
        public = services.create_operator_source(
            db,
            spec.model_copy(
                update={'name': 'Second wire', 'url': 'https://second.example/feed', 'reuse': 'public'}
            ),
        )
        manual, _ = services.ingest(db, payload)
        ref = services.SourceRef(restricted.key, 'same-id')
        private_doc, _ = services.ingest(db, payload, ref=ref)
        public_doc, _ = services.ingest(db, payload, ref=services.SourceRef(public.key, 'same-id'))
        repeated, created = services.ingest(db, payload, ref=ref)
        assert (repeated.id, created) == (private_doc.id, False)
        assert len({manual.id, private_doc.id, public_doc.id}) == 3
    for doc, can_share in ((manual, True), (private_doc, False), (public_doc, True)):
        artifact = _get(authed, f'/api/documents/{doc.id}/export')
        assert '192.0.2.9' in artifact
        assert ('A syndicated passage' in artifact) == can_share


def test_taxii_polls_version_the_report_on_reuse_changes_and_source_deletion(
    corpus: Corpus, app: FastAPI, authed: TestClient
) -> None:
    sample = next(item for item in corpus.samples if item.share_text)
    collection = f'/taxii2/insight/collections/{INDICATORS_COLLECTION}/'
    headers = {'Authorization': f'Bearer {corpus.token}', 'Accept': TAXII_MEDIA_TYPE}
    objects = collection + 'objects/'
    manifest = collection + 'manifest/'
    initial = json.loads(_get(authed, objects, headers=headers))['objects']
    [report] = [item for item in initial if item.get('name') == sample.title]
    report_id = report['id']
    assert sample.quotation in report['description']
    modified = report['modified']
    unchanged = {
        item['id']: item
        for item in initial
        if item['type'] in ('indicator', 'report') and item['id'] != report_id
    }
    assert unchanged
    last = max(item['date_added'] for item in json.loads(_get(authed, manifest, headers=headers))['objects'])
    for change in ('metadata', 'public', 'delete'):
        with app.state.session_factory.begin() as db:
            source = services.get_operator_source(db, sample.source_key)
            if change == 'delete':
                services.delete_operator_source(db, source.key)
            else:
                updated = OperatorSourceInput.model_validate(
                    {'name': source.name, 'url': source.url, 'tlp': source.tlp, 'reuse': change}
                )
                services.update_operator_source(db, source.key, updated)
        delta = json.loads(_get(authed, objects, headers=headers, params={'added_after': last}))['objects']
        [changed] = [item for item in delta if item['type'] == 'report']
        assert changed['id'] == report_id
        assert changed['modified'] > modified
        assert changed['x_insight_metadata_only'] == (change != 'public')
        assert (sample.quotation in json.dumps(delta)) == (change == 'public')
        assert {item['id'] for item in delta}.isdisjoint(unchanged)
        complete = json.loads(_get(authed, objects, headers=headers))['objects']
        assert {item['id']: item for item in complete if item['id'] in unchanged} == unchanged
        [entry] = json.loads(_get(authed, manifest, headers=headers, params={'match[id]': report_id}))[
            'objects'
        ]
        assert entry['date_added'] > last
        assert entry['version'] == changed['modified']
        last, modified = entry['date_added'], changed['modified']
