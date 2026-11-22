"""Opt-in provider contract checks using public test subjects, never private instance intelligence."""

from __future__ import annotations

import os

import pytest

from insight import pivots

pytestmark = pytest.mark.live


@pytest.mark.parametrize(('provider', 'value'), [('rdap', 'example.com'), ('asn', '8.8.8.8')])
async def test_infrastructure_contract(provider: str, value: str) -> None:
    if os.environ.get('INSIGHT_LIVE_PIVOTS') != '1':
        pytest.skip('Set INSIGHT_LIVE_PIVOTS=1 to approve public test-subject provider checks')
    result = await pivots._fetch(provider, value)
    assert result['found'] is True
    assert isinstance(result['nodes'], list)
