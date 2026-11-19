"""API key format, generation and verification helpers. Pure functions: no database, no framework.

A key looks like ``insk_3f9a1c0b7d2e_<43 url-safe characters>``:

* ``insk_`` is a fixed prefix, so secret scanners (GitHub push protection, gitleaks) can recognise a leaked
  key;
* the 12 hex characters are the public **key ID**. It is stored in clear, shown by ``insight api-key status``
  and written to logs, and lets the server find the key with one indexed lookup;
* the rest is 32 random bytes (256 bits) of secret.

Only the SHA-256 of the whole key is stored. A slow password hash (bcrypt, Argon2) would add nothing for a
256-bit random secret and would let anyone burn server CPU on every request by sending bogus keys.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Final, Literal, get_args

PREFIX: Final = 'insk_'
KEY_PATTERN: Final = re.compile(r'insk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})')
#: ``read``: GET requests only. ``read-write``: every API route except session-only ones.
Access = Literal['read', 'read-write']
ACCESS_LEVELS: tuple[str, ...] = get_args(Access)
DEFAULT_EXPIRY_DAYS: Final = 90
MAX_EXPIRY_DAYS: Final = 365


@dataclass(frozen=True, slots=True)
class NewKey:
    """A freshly generated key. ``token`` is shown to the operator once and never stored."""

    key_id: str
    token: str
    token_hash: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate() -> NewKey:
    key_id = secrets.token_hex(6)
    token = f'{PREFIX}{key_id}_{secrets.token_urlsafe(32)}'
    return NewKey(key_id=key_id, token=token, token_hash=hash_token(token))


def parse_key_id(token: str) -> str | None:
    """The key ID of a well-formed key, else ``None`` (checked before any database lookup)."""
    match = KEY_PATTERN.fullmatch(token)
    return match.group(1) if match else None


def token_matches(token: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented key with the stored hash."""
    return hmac.compare_digest(hash_token(token).encode(), stored_hash.encode())


def bearer_token(authorization: str) -> str | None:
    """The credential from ``Authorization: Bearer <key>`` (scheme is case-insensitive), else ``None``."""
    scheme, _, credential = authorization.strip().partition(' ')
    credential = credential.strip()
    if scheme.lower() != 'bearer' or not credential:
        return None
    return credential


def check_expiry_days(days: int) -> int:
    if not 1 <= days <= MAX_EXPIRY_DAYS:
        raise ValueError(f'Expiry must be between 1 and {MAX_EXPIRY_DAYS} days')
    return days
