"""Explicit opt-in check against NASA's public news feed using a disposable operator configuration."""

from __future__ import annotations

import os

import pytest

from insight import connectors, services
from insight.models import SessionFactory
from insight.schemas import OperatorSourceInput

pytestmark = pytest.mark.live


async def test_public_space_news_operator_subscription(session_factory: SessionFactory) -> None:
    if os.environ.get('INSIGHT_LIVE_OPERATOR_RSS') != '1':
        pytest.skip('Set INSIGHT_LIVE_OPERATOR_RSS=1 to approve the NASA public feed check')
    with session_factory.begin() as db:
        source = services.create_operator_source(
            db, OperatorSourceInput(name='NASA news', url='https://www.nasa.gov/feed/', tlp='GREEN')
        )
        services.set_operator_source_enabled(db, source.key, True)
    message = await connectors.sync_source(session_factory, source.key)
    assert 'feed items' in message
