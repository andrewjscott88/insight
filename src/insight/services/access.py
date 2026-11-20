"""API keys and the operator's second factor."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import apikeys, totp
from ..models import (
    ApiKey,
    OperatorMfa,
    now,
)
from ..schemas import (
    TLP_LEVELS,
)
from .audit import audit

#: ``api_keys.last_used_at`` is written at most this often, so API traffic does not become a stream of writes.
API_KEY_TOUCH_INTERVAL: Final = timedelta(minutes=5)

MAX_API_KEY_NAME_LENGTH: Final = 100


def active_api_key(db: Session) -> ApiKey | None:
    """The key that currently authenticates requests: not revoked and not expired."""
    return db.scalar(
        select(ApiKey)
        .where(ApiKey.revoked_at.is_(None), ApiKey.expires_at > now())
        .order_by(ApiKey.created_at.desc())
        .limit(1)
    )


def _issue_api_key(
    db: Session, *, name: str, access: str, expires_days: int, max_tlp: str | None
) -> tuple[ApiKey, str]:
    name = name.strip()
    if not 1 <= len(name) <= MAX_API_KEY_NAME_LENGTH:
        raise ValueError(f'Key name must be 1-{MAX_API_KEY_NAME_LENGTH} characters')
    if access not in apikeys.ACCESS_LEVELS:
        raise ValueError(f'Access must be one of: {", ".join(apikeys.ACCESS_LEVELS)}')
    apikeys.check_expiry_days(expires_days)
    if max_tlp is not None and max_tlp not in TLP_LEVELS:
        raise ValueError(f'TLP limit must be one of: {", ".join(TLP_LEVELS)}')
    if max_tlp == TLP_LEVELS[-1]:
        max_tlp = None  # A limit of RED hides nothing: store it as "no limit", which also lifts a limit.
    new = apikeys.generate()
    key = ApiKey(
        key_id=new.key_id,
        token_hash=new.token_hash,
        name=name,
        access=access,
        expires_at=(datetime.now(UTC) + timedelta(days=expires_days)).isoformat(),
        max_tlp=max_tlp,
    )
    db.add(key)
    db.flush()
    detail = {
        'key_id': key.key_id,
        'name': key.name,
        'access': key.access,
        'expires_at': key.expires_at,
        'max_tlp': key.max_tlp,
    }
    audit(db, 'api_key.create', key.id, json.dumps(detail, sort_keys=True))
    return key, new.token


def _revoke(db: Session, key: ApiKey, reason: str) -> None:
    key.revoked_at = now()
    audit(db, 'api_key.revoke', key.id, json.dumps({'key_id': key.key_id, 'reason': reason}, sort_keys=True))


def create_api_key(
    db: Session,
    *,
    name: str,
    access: str,
    expires_days: int = apikeys.DEFAULT_EXPIRY_DAYS,
    max_tlp: str | None = None,
) -> tuple[ApiKey, str]:
    """Issue the API key and return it with its plaintext token (show once; only the hash is stored).

    ``max_tlp`` limits what the key can read and write (``None``: whatever the instance stores). Raises
    ``ValueError`` for invalid input or when a key is already active (rotate or revoke it first).
    """
    if (current := active_api_key(db)) is not None:
        raise ValueError(f'API key {current.key_id} is already active; rotate or revoke it first')
    return _issue_api_key(db, name=name, access=access, expires_days=expires_days, max_tlp=max_tlp)


def rotate_api_key(
    db: Session,
    *,
    name: str | None = None,
    access: str | None = None,
    expires_days: int = apikeys.DEFAULT_EXPIRY_DAYS,
    max_tlp: str | None = None,
) -> tuple[ApiKey, str]:
    """Revoke the active key and issue its replacement in one step.

    Name, access and TLP limit carry over unless given; ``max_tlp='RED'`` removes the limit.
    """
    current = active_api_key(db)
    if current is None:
        raise ValueError('No active API key to rotate; create one')
    replacement = _issue_api_key(
        db,
        name=name or current.name,
        access=access or current.access,
        expires_days=expires_days,
        max_tlp=max_tlp or current.max_tlp,
    )
    _revoke(db, current, 'rotated')
    return replacement


def revoke_api_key(db: Session) -> ApiKey | None:
    """Revoke the active key immediately; ``None`` when there is none."""
    current = active_api_key(db)
    if current is not None:
        _revoke(db, current, 'revoked')
    return current


def verify_api_key(db: Session, token: str) -> tuple[ApiKey | None, str]:
    """``(key, 'ok')`` for a valid, active key, else ``(None, reason)``. Records use (rate-limited writes).

    ``reason`` (``malformed``, ``unknown``, ``revoked``, ``expired``) is for server logs only; callers must
    answer every failure identically.
    """
    key_id = apikeys.parse_key_id(token)
    if key_id is None:
        return None, 'malformed'
    key = db.scalar(select(ApiKey).where(ApiKey.key_id == key_id))
    if key is None or not apikeys.token_matches(token, key.token_hash):
        return None, 'unknown'
    if key.revoked_at is not None:
        return None, 'revoked'
    current = datetime.now(UTC)
    if key.expires_at <= current.isoformat():
        return None, 'expired'
    if key.last_used_at is None or key.last_used_at < (current - API_KEY_TOUCH_INTERVAL).isoformat():
        key.last_used_at = current.isoformat()
    return key, 'ok'


def mfa_paired(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(OperatorMfa)) != 0


def pair_mfa(db: Session, secret: str, confirmed_step: int) -> None:
    """Store a confirmed authenticator-app secret. Raises ``ValueError`` if an app is already paired.

    ``confirmed_step`` (the code the operator typed to prove the app was set up) is recorded as used, so that
    code cannot also sign in.
    """
    if mfa_paired(db):
        raise ValueError('An authenticator app is already paired; reset it first to pair a new one')
    row = OperatorMfa(secret=secret, last_step=confirmed_step)
    db.add(row)
    db.flush()
    audit(db, 'mfa.pair', row.id)


def reset_mfa(db: Session) -> bool:
    """Forget the paired app (e.g. a lost phone); ``False`` when none was paired."""
    rows = list(db.scalars(select(OperatorMfa)))
    for row in rows:
        db.delete(row)
        audit(db, 'mfa.reset', row.id)
    return bool(rows)


def verify_mfa_code(db: Session, code: str, at: float | None = None) -> bool:
    """True for a current code of the paired app that has not been used yet (it is then marked used).

    False when no app is paired (fail closed). A replayed code, or any code from an older time step than the
    last accepted one, is refused. Call it only after the password was verified, so guesses do not burn codes.
    """
    row = db.scalar(select(OperatorMfa).with_for_update())
    if row is None:
        return False
    step = totp.matching_step(row.secret, code, at, after=row.last_step)
    if step is None:
        return False
    row.last_step = step
    return True
