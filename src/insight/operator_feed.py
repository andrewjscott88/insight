"""Read one operator-configured feed; each response, source revision and validator commit together."""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from . import connectors, services
from .config import parse_max_tlp
from .feed_items import FeedItem
from .models import SessionFactory, SourceRun
from .services.operator_sources import OperatorSourceView, get_operator_source, list_operator_sources
from .source_registry import Source


def private_network() -> bool:
    value = os.environ.get('INSIGHT_SOURCES_PRIVATE_NETWORK', '').strip().lower()
    if value not in ('', 'off', 'on'):
        raise ValueError('INSIGHT_SOURCES_PRIVATE_NETWORK must be on or off')
    return value == 'on'


def _limit(max_tlp: str | None) -> str:
    return max_tlp or parse_max_tlp(os.environ.get('INSIGHT_MAX_TLP', ''))


def _source(view: OperatorSourceView) -> Source:
    return Source(view.key, view.name, view.url, 'rss', '', optional=True, reuse=view.reuse)


def enabled_sources(db: Session, *, max_tlp: str | None) -> list[Source]:
    return [_source(row) for row in list_operator_sources(db, max_tlp=_limit(max_tlp)) if row.enabled]


def _state_token(db: Session, key: str) -> str | None:
    state = services.get_fetch_state(db, key)
    return state.updated_at if state else None


def _start(sessions: SessionFactory, key: str, limit: str) -> tuple[OperatorSourceView, str | None]:
    with sessions() as db:
        row = get_operator_source(db, key, max_tlp=limit)
        if not row.enabled:
            raise connectors.SourceSwitchedOff(_source(row))
        return row, _state_token(db, key)


def _save(
    sessions: SessionFactory,
    source: OperatorSourceView,
    token: str | None,
    fetched: connectors.Fetched | None,
    items: list[FeedItem],
    limit: str,
    actor: str,
) -> str:
    with sessions.begin() as db:
        current = get_operator_source(db, source.key, lock=True, max_tlp=limit)
        if not current.enabled or current.revision != source.revision:
            raise LookupError('The source changed during the sync.')
        if token != _state_token(db, source.key):
            raise LookupError('Another sync has already stored a response.')
        message = connectors.UNCHANGED
        if fetched is not None:
            services.set_actor(db, f'connector:{source.key}')
            added = 0
            for item in items:
                if item.external_id is None:
                    raise ValueError('Operator feed item has no source identity')
                _, created = services.ingest(
                    db,
                    item.document,
                    ref=services.SourceRef(source.key, item.external_id),
                    max_tlp=limit,
                    preserve_source_tlp=True,
                    truncated=item.truncated,
                )
                added += created
            connectors._remember(db, [fetched])
            message = f'Read {len(items)} feed items; {added} new reports.'
        services.set_actor(db, actor)
        services.audit(db, 'source.sync', source.key, 'unchanged' if fetched is None else 'success')
        db.add(SourceRun(source_key=source.key, status='success', message=message))
        return message


def _failure(
    sessions: SessionFactory, source: OperatorSourceView, limit: str, actor: str, message: str
) -> None:
    with sessions.begin() as db:
        try:
            current = get_operator_source(db, source.key, lock=True, max_tlp=limit)
        except LookupError:
            return
        if current.enabled and current.revision == source.revision:
            services.set_actor(db, actor)
            services.audit(db, 'source.sync', source.key, 'error')
            db.add(SourceRun(source_key=source.key, status='error', message=message))


async def sync(sessions: SessionFactory, key: str, *, max_tlp: str | None, actor: str) -> str:
    limit = _limit(max_tlp)
    view, token = await asyncio.to_thread(_start, sessions, key, limit)
    try:
        host = urlsplit(view.url).hostname
        if not host:
            raise ValueError('Missing source host')
        fetched = await connectors.fetch_if_changed(
            sessions,
            view.url,
            state_key=key,
            allowed_hosts=frozenset({host}),
            allow_private=private_network(),
        )
        items = (
            await asyncio.to_thread(
                connectors.parse_feed, fetched.payload, _source(view), operator_tlp=view.tlp
            )
            if fetched is not None
            else []
        )
        return await asyncio.to_thread(_save, sessions, view, token, fetched, items, limit, actor)
    except LookupError:
        message = 'The source changed during the sync. Try again.'
    except services.TlpNotPermitted:
        message = 'The feed contains a report above the configured TLP limit.'
    except Exception:
        # Transport, XML, validation and database exceptions may contain URL, response text or credentials.
        message = 'The feed could not be fetched or imported.'
    await asyncio.to_thread(_failure, sessions, view, limit, actor, message)
    raise connectors.SourceSyncError(message)
