"""Live contract tests against the real publishers (nightly, advisory).

These are the *only* tests allowed to use the network. They catch upstream changes (moved URLs, format
changes, new redirects) early, and never block merges: a publisher outage is not a defect in Insight.

    INSIGHT_LIVE_TESTS=1 pytest tests/live -m live
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from insight import connectors

pytestmark = pytest.mark.live

if os.environ.get('INSIGHT_LIVE_TESTS') != '1':
    pytest.skip('set INSIGHT_LIVE_TESTS=1 to contact real sources', allow_module_level=True)


@pytest.mark.parametrize('key', sorted(connectors.SOURCES))
def test_source_is_reachable_and_parsable(key: str) -> None:
    source = connectors.SOURCES[key]
    if source.kind == 'csaf':
        items, skipped = asyncio.run(connectors.fetch_csaf(source))
        assert skipped == 0, f'{key}: {skipped} of the newest advisories could not be read'
        assert len(items) == connectors.CSAF_INBOX_LIMIT
        assert all(item.external_id for item in items)
        return
    payload = asyncio.run(connectors.download(source.url))
    if source.kind == 'kev':
        rows = json.loads(payload)['vulnerabilities']
        assert len(rows) > 1000
        connectors._validate_kev_rows(payload)  # the full real catalogue must pass validation
    else:
        items = connectors.parse_feed(payload, source)
        assert items, f'{key} returned no feed items'
        assert all(item.external_id for item in items), f'{key} items lack a stable identity'


@pytest.mark.parametrize('provider', sorted(connectors.PROVIDERS))
def test_enrichment_provider_contract(provider: str) -> None:
    url, params = connectors.enrichment_request('CVE-2021-44228', provider)
    payload = json.loads(asyncio.run(connectors.download(url, params)))
    assert isinstance(payload, dict)
    expected_key = 'data' if provider == 'epss' else 'vulnerabilities'
    assert payload.get(expected_key), f'{provider} response shape changed: {sorted(payload)[:10]}'
