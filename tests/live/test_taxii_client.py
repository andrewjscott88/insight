"""Explicitly configured, anonymously readable test collection; not part of the default live feeds."""

from __future__ import annotations

import os

import pytest

from insight import taxii_client

pytestmark = pytest.mark.live


async def test_operator_owned_test_collection() -> None:
    if os.environ.get('INSIGHT_LIVE_OPERATOR_TAXII') != '1':
        pytest.skip('Set INSIGHT_LIVE_OPERATOR_TAXII=1 to approve a configured test collection')
    api_root = os.environ.get('INSIGHT_LIVE_TAXII_ROOT', '')
    collection = os.environ.get('INSIGHT_LIVE_TAXII_COLLECTION', '')
    if not api_root or not collection:
        pytest.skip(
            'Set INSIGHT_LIVE_TAXII_ROOT and INSIGHT_LIVE_TAXII_COLLECTION for an anonymous test feed'
        )
    result = await taxii_client.fetch_collection(api_root, collection)
    assert 0 <= result.object_count <= taxii_client.MAX_OBJECTS
    assert bool(result.bundle) == bool(result.object_count)
