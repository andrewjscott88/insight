"""An explicitly enabled contract check against a public, synthetic-example domain."""

from __future__ import annotations

import os

import pytest

from insight import pivots

pytestmark = pytest.mark.live


async def test_crtsh_public_domain_contract() -> None:
    if os.environ.get('INSIGHT_LIVE_PIVOTS') != '1':
        pytest.skip('Set INSIGHT_LIVE_PIVOTS=1 to approve the public example.com certificate lookup')
    result = await pivots._fetch('crtsh', 'example.com')
    assert result['found']
    assert len(result['certificates']) <= 500
    assert all(node['type'] == 'certificate_name' for node in result['nodes'])
