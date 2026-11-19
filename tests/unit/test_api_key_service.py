"""The API key lifecycle in the service layer: one active key, hash-only storage, audited changes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import apikeys, services
from insight.models import ApiKey, AuditEvent, now


def audit_actions(db: Session) -> list[str]:
    return [e.action for e in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))]


def test_create_stores_only_the_hash_and_audits_without_the_secret(db: Session) -> None:
    key, token = services.create_api_key(db, name='  siem  ', access='read', expires_days=30)
    assert key.name == 'siem'
    assert key.token_hash == apikeys.hash_token(token)
    stored = db.scalars(select(ApiKey)).one()
    assert token not in {stored.token_hash, stored.key_id, stored.name}
    expires = datetime.fromisoformat(key.expires_at)
    assert timedelta(days=29, hours=23) < expires - datetime.now(UTC) <= timedelta(days=30)
    event = db.scalars(select(AuditEvent)).one()
    assert (event.action, event.object_id) == ('api_key.create', key.id)
    assert json.loads(event.detail) == {
        'key_id': key.key_id,
        'name': 'siem',
        'access': 'read',
        'expires_at': key.expires_at,
        'max_tlp': None,
    }
    assert token not in event.detail


def test_only_one_key_may_be_active(db: Session) -> None:
    key, _ = services.create_api_key(db, name='siem', access='read')
    with pytest.raises(ValueError, match=f'{key.key_id} is already active'):
        services.create_api_key(db, name='second', access='read')


@pytest.mark.parametrize(
    ('name', 'access', 'days', 'message'),
    [
        ('', 'read', 90, 'name must be'),
        ('   ', 'read', 90, 'name must be'),
        ('x' * 101, 'read', 90, 'name must be'),
        ('siem', 'admin', 90, 'Access must be one of'),
        ('siem', 'read', 0, 'between 1 and 365'),
        ('siem', 'read', 366, 'between 1 and 365'),
    ],
)
def test_invalid_input_is_rejected(db: Session, name: str, access: str, days: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        services.create_api_key(db, name=name, access=access, expires_days=days)
    assert db.scalars(select(ApiKey)).all() == []


def test_verify_accepts_the_active_key(db: Session) -> None:
    key, token = services.create_api_key(db, name='siem', access='read-write')
    found, reason = services.verify_api_key(db, token)
    assert (found, reason) == (key, 'ok')


def test_verify_reasons(db: Session) -> None:
    key, token = services.create_api_key(db, name='siem', access='read')
    assert services.verify_api_key(db, 'not a key') == (None, 'malformed')
    assert services.verify_api_key(db, apikeys.generate().token) == (None, 'unknown')
    # Right key ID, wrong secret: treated exactly like an unknown key.
    forged = f'insk_{key.key_id}_' + 'A' * 43
    assert services.verify_api_key(db, forged) == (None, 'unknown')
    key.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert services.verify_api_key(db, token) == (None, 'expired')
    assert services.active_api_key(db) is None
    key.revoked_at = now()
    assert services.verify_api_key(db, token) == (None, 'revoked')


def test_an_expired_key_does_not_block_creating_a_new_one(db: Session) -> None:
    old, _ = services.create_api_key(db, name='siem', access='read')
    old.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    new, _ = services.create_api_key(db, name='siem', access='read')
    assert services.active_api_key(db) == new


def test_rotate_replaces_the_key_keeping_its_settings(db: Session) -> None:
    old, old_token = services.create_api_key(db, name='siem', access='read-write', expires_days=30)
    new, new_token = services.rotate_api_key(db)
    assert (new.name, new.access) == ('siem', 'read-write')
    assert new.key_id != old.key_id
    assert old.revoked_at is not None
    assert services.verify_api_key(db, old_token) == (None, 'revoked')
    assert services.verify_api_key(db, new_token) == (new, 'ok')
    assert services.active_api_key(db) == new
    assert audit_actions(db) == ['api_key.create', 'api_key.create', 'api_key.revoke']
    revoke = db.scalars(select(AuditEvent).where(AuditEvent.action == 'api_key.revoke')).one()
    assert json.loads(revoke.detail) == {'key_id': old.key_id, 'reason': 'rotated'}


def test_rotate_can_change_settings(db: Session) -> None:
    services.create_api_key(db, name='siem', access='read-write')
    new, _ = services.rotate_api_key(db, name='siem-2', access='read', expires_days=7)
    assert (new.name, new.access) == ('siem-2', 'read')


def test_rotate_without_an_active_key_fails(db: Session) -> None:
    with pytest.raises(ValueError, match='No active API key'):
        services.rotate_api_key(db)


def test_revoke(db: Session) -> None:
    assert services.revoke_api_key(db) is None
    key, token = services.create_api_key(db, name='siem', access='read')
    assert services.revoke_api_key(db) == key
    assert services.verify_api_key(db, token) == (None, 'revoked')
    assert services.revoke_api_key(db) is None
    assert audit_actions(db) == ['api_key.create', 'api_key.revoke']


def test_last_use_is_recorded_at_most_every_few_minutes(db: Session) -> None:
    key, token = services.create_api_key(db, name='siem', access='read')
    never: str | None = key.last_used_at
    assert never is None
    services.verify_api_key(db, token)
    first = key.last_used_at
    assert first is not None
    services.verify_api_key(db, token)
    assert key.last_used_at == first  # no write on every request
    stale = datetime.now(UTC) - services.API_KEY_TOUCH_INTERVAL - timedelta(seconds=1)
    key.last_used_at = stale.isoformat()
    services.verify_api_key(db, token)
    assert key.last_used_at > first
