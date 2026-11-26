"""API keys, the operator's second factor and signed-in sessions."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import apikeys, totp
from ..mfa_crypto import decrypt_seed, encrypt_seed
from ..models import (
    ApiKey,
    OperatorMfa,
    OperatorSession,
    User,
    now,
)
from ..schemas import (
    TLP_LEVELS,
)
from .audit import audit
from .common import stamp

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


def pair_mfa(db: Session, secret: str, confirmed_step: int, *, session_secret: str) -> None:
    """Store a confirmed authenticator-app secret. Raises ``ValueError`` if an app is already paired.

    ``confirmed_step`` (the code the operator typed to prove the app was set up) is recorded as used, so that
    code cannot also sign in.
    """
    if mfa_paired(db):
        raise ValueError('An authenticator app is already paired; reset it first to pair a new one')
    row = OperatorMfa(secret=encrypt_seed(secret, session_secret), last_step=confirmed_step)
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


def verify_mfa_code(db: Session, code: str, at: float | None = None, *, session_secret: str) -> bool:
    """True for a current code of the paired app that has not been used yet (it is then marked used).

    False when no app is paired (fail closed). A replayed code, or any code from an older time step than the
    last accepted one, is refused. Call it only after the password was verified, so guesses do not burn codes.
    """
    row = db.scalar(select(OperatorMfa).with_for_update())
    if row is None:
        return False
    try:
        seed = decrypt_seed(row.secret, session_secret)
        step = totp.matching_step(seed, code, at, after=row.last_step)
    except ValueError:
        # An unreadable pairing must still require the second factor. Leave it intact for recovery.
        return False
    if step is None:
        return False
    row.last_step = step
    return True


# --------------------------------------------------------------------------- signed-in sessions (review B4)

#: How long a sign-in lasts, whatever the browser does in between (also the cookie's lifetime).
SESSION_TTL: Final = timedelta(hours=8)


def session_binding(session_secret: str, password: str, mfa: bool, provider: str | None = None) -> str:
    """A keyed fingerprint of what a sign-in proved. Stored session hashes include it, so changing the
    password or turning MFA on or off ends every session, as the restart such a change needs always did.

    ``provider`` names the identity provider sign-in (ADR 0046): its issuer, client ID and whether password
    sign-in is off. Changing any of them, or turning the provider on or off, ends every session too; without
    a provider the fingerprint is the one earlier versions stored.
    """
    message = f'{password}\0{"mfa" if mfa else "password"}'
    if provider is not None:
        message += f'\0{provider}'
    return hmac.new(session_secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _session_hash(session_id: str, binding: str) -> str:
    return hashlib.sha256(f'{binding}:{session_id}'.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    """Who a stored session belongs to (ADR 0046)."""

    #: The person (``users.id``); ``None`` for the built-in operator's password sign-in.
    user_id: str | None
    #: ``viewer``, ``analyst`` or ``admin``; ``None`` while the person waits for an admin's approval.
    role: str | None


#: The built-in operator: the password sign-in, an admin.
OPERATOR_PRINCIPAL: Final = SessionPrincipal(None, 'admin')


def start_operator_session(
    db: Session, *, binding: str, at: datetime, replaces: str | None = None, user_id: str | None = None
) -> str:
    """Store a new session and return its ID for the cookie; only a keyed hash of the ID is stored.

    ``replaces`` is the ID the browser had before, which ends here, so a sign-in never keeps an old ID
    (session fixation). Expired sessions are deleted on the way. ``user_id`` names the person who signed in
    (``None``: the operator).
    """
    if replaces:
        end_operator_session(db, replaces, binding=binding)
    db.execute(delete(OperatorSession).where(OperatorSession.expires_at <= stamp(at)))
    session_id = secrets.token_urlsafe(32)
    db.add(
        OperatorSession(
            id_hash=_session_hash(session_id, binding),
            created_at=stamp(at),
            expires_at=stamp(at + SESSION_TTL),
            user_id=user_id,
        )
    )
    return session_id


def session_principal(db: Session, session_id: str, *, binding: str, at: datetime) -> SessionPrincipal | None:
    """Who ``session_id`` signs in, while it names a stored, unexpired session made under the current
    credentials; ``None`` otherwise, and for a disabled or removed person."""
    if not session_id:
        return None
    row = db.get(OperatorSession, _session_hash(session_id, binding))
    if row is None or row.expires_at <= stamp(at):
        return None
    if row.user_id is None:
        return OPERATOR_PRINCIPAL
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    return SessionPrincipal(user.id, user.role)


def operator_session_valid(db: Session, session_id: str, *, binding: str, at: datetime) -> bool:
    """True while ``session_id`` names a stored, unexpired session made under the current credentials."""
    return session_principal(db, session_id, binding=binding, at=at) is not None


def end_operator_session(db: Session, session_id: str, *, binding: str) -> None:
    """Sign one browser out (nothing happens for an unknown ID)."""
    db.execute(delete(OperatorSession).where(OperatorSession.id_hash == _session_hash(session_id, binding)))


def sign_out(db: Session, session_id: str, *, binding: str, everywhere: bool) -> int:
    """Sign this browser out or, with ``everywhere``, every browser of the same person (the operator's, or
    one person's; other people stay signed in). Returns how many sessions ended everywhere (0 otherwise).
    The audit event names the person signing out."""
    row = db.get(OperatorSession, _session_hash(session_id, binding)) if session_id else None
    if row is None:
        return 0
    if not everywhere:
        end_operator_session(db, session_id, binding=binding)
        return 0
    db.info['actor'] = 'operator' if row.user_id is None else f'user:{row.user_id}'
    return end_own_sessions(db, row.user_id)


def end_own_sessions(db: Session, user_id: str | None) -> int:
    """Sign one person out of every browser: ``user_id``, or the operator when ``None``. Audited as
    ``session.end_all`` with the number of sessions that were open; other people stay signed in."""
    owner = OperatorSession.user_id.is_(None) if user_id is None else OperatorSession.user_id == user_id
    count = db.scalar(select(func.count()).select_from(OperatorSession).where(owner)) or 0
    db.execute(delete(OperatorSession).where(owner))
    audit(db, 'session.end_all', user_id or 'operator', f'{count} session(s) ended')
    return count


def end_all_operator_sessions(db: Session) -> int:
    """Sign everyone out of every browser. Audited as ``session.end_all`` with the number of sessions."""
    count = db.scalar(select(func.count()).select_from(OperatorSession)) or 0
    db.execute(delete(OperatorSession))
    audit(db, 'session.end_all', 'everyone', f'{count} session(s) ended')
    return count


def count_operator_sessions(db: Session, *, at: datetime) -> int:
    """Unexpired sessions (some may belong to an earlier password and no longer work)."""
    return (
        db.scalar(
            select(func.count()).select_from(OperatorSession).where(OperatorSession.expires_at > stamp(at))
        )
        or 0
    )
