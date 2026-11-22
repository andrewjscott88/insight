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
from insight.abusech import parse_abusech
from insight.cve_scores import summarise_vulncheck
from insight.otx import parse_pulses

pytestmark = pytest.mark.live
LOG4SHELL = 'CVE-2021-44228'

if os.environ.get('INSIGHT_LIVE_TESTS') != '1':
    pytest.skip('set INSIGHT_LIVE_TESTS=1 to contact real sources', allow_module_level=True)


@pytest.mark.parametrize('key', sorted(connectors.SOURCES))
def test_source_is_reachable_and_parsable(key: str) -> None:
    source = connectors.SOURCES[key]
    if source.kind == 'otx':
        if not os.environ.get('INSIGHT_OTX_API_KEY'):
            pytest.skip('OTX subscriptions need INSIGHT_OTX_API_KEY')
        parse_pulses(asyncio.run(connectors.fetch_otx()), source)
        return
    if source.kind == 'csaf':
        items, skipped = asyncio.run(connectors.fetch_csaf(source))
        assert skipped == 0, f'{key}: {skipped} of the newest advisories could not be read'
        assert len(items) == connectors.CSAF_INBOX_LIMIT
        assert all(item.external_id for item in items)
        return
    if source.kind == 'abusech':
        if not os.environ.get('INSIGHT_ABUSECH_AUTH_KEY'):
            pytest.skip('set INSIGHT_ABUSECH_AUTH_KEY to test keyed indicator feeds')
        headers, body = connectors.abusech_request(source)
        payload = asyncio.run(connectors.download(source.fetch_urls[0], headers=headers, body=body))
        items = parse_abusech(payload, source)  # A short observation window may be empty.
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
    if provider in connectors.KEY_REQUIRED and not connectors.provider_key(provider):
        pytest.skip(f'{provider} needs {connectors.PROVIDER_KEYS[provider]}')
    url, params = connectors.enrichment_request(LOG4SHELL, provider)
    headers = connectors.provider_headers(provider)  # Empty unless the operator's key is set.
    payload = json.loads(asyncio.run(connectors.download(url, params, headers=headers)))
    assert isinstance(payload, dict)
    expected_key = 'vulnerabilities' if provider == 'nvd' else 'data'
    assert payload.get(expected_key), f'{provider} response shape changed: {sorted(payload)[:10]}'
    if provider == 'vulncheck':
        summary = summarise_vulncheck(payload, LOG4SHELL)
        assert summary['listed'], 'VulnCheck KEV no longer lists Log4Shell: its answer shape changed'
        assert summary['exploit_count'] > 0, 'VulnCheck KEV lists no public exploit for Log4Shell'
