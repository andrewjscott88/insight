"""Explicitly approved Censys Platform contract check; consumes account credits when enabled."""

from __future__ import annotations

import os

import pytest

from insight import censys

pytestmark = pytest.mark.live


async def test_censys_platform_host_contract() -> None:
    if os.environ.get('INSIGHT_LIVE_CENSYS') != '1':
        pytest.skip(
            'Set INSIGHT_LIVE_CENSYS=1 to approve one public test-subject lookup and account credit use'
        )
    token, organization = censys._credentials()
    if not token:
        pytest.skip('The operator must configure a permitted Censys account for this live check')
    result = await censys._fetch('8.8.8.8', token, organization)
    assert isinstance(result['found'], bool)
    if result['found']:
        assert isinstance(result['services'], list)
        assert len(result['services']) <= censys.MAX_SERVICES
