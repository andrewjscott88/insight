"""Explicit opt-in, credentialed CIRCL public-example query; never part of offline checks."""

import os

import pytest

from insight import passive_dns, pivots

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get('INSIGHT_LIVE_PIVOTS') != '1' or not passive_dns.configured(),
        reason='Explicit live-pivot approval and operator CIRCL access are required',
    ),
]


async def test_circl_public_example_metadata() -> None:
    result = await pivots._fetch('circl', 'example.com')
    assert isinstance(result['found'], bool)
    assert len(result['records']) <= 500
    assert len(result['nodes']) <= 500
