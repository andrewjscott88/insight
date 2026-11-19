"""Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30 seconds): the sign-in second factor.

Compatible with common authenticator apps (Google Authenticator, Microsoft Authenticator, 1Password, Aegis,
Bitwarden). Standard library only: no new dependency in the hash-pinned supply chain. Pure functions; storage
and replay protection live in ``services``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Final
from urllib.parse import quote, urlencode

DIGITS: Final = 6
PERIOD: Final = 30
#: Codes from one step before or after are accepted too, for clock drift between phone and server.
WINDOW: Final = 1
ISSUER: Final = 'Insight'


def generate_secret() -> str:
    """160 random bits (RFC 4226's recommended length) as unpadded base32, the format apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _key(secret: str) -> bytes:
    compact = secret.replace(' ', '').upper()
    return base64.b32decode(compact + '=' * (-len(compact) % 8))


def time_step(at: float | None = None) -> int:
    return int((time.time() if at is None else at) // PERIOD)


def code_at(secret: str, step: int) -> str:
    """The code for one time step (RFC 4226 HOTP with the step as counter)."""
    digest = hmac.new(_key(secret), struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack('>I', digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def matching_step(secret: str, code: str, at: float | None = None, *, after: int = 0) -> int | None:
    """The time step ``code`` belongs to (within the drift window), else ``None``.

    Only steps greater than ``after`` count, so an accepted code (and anything older) cannot be replayed.
    Spaces are ignored (apps often display ``123 456``). Comparisons are constant-time.
    """
    candidate = code.replace(' ', '').strip()
    # isascii() first: str.isdigit() accepts e.g. full-width digits, which compare_digest cannot compare.
    if len(candidate) != DIGITS or not (candidate.isascii() and candidate.isdigit()):
        return None
    now = time_step(at)
    found = None
    for step in range(now - WINDOW, now + WINDOW + 1):
        if step > after and hmac.compare_digest(code_at(secret, step), candidate):
            found = step
    return found


def provisioning_uri(secret: str, account: str = 'operator') -> str:
    """``otpauth://`` URI for authenticator apps (paste it, or turn it into a QR code locally)."""
    label = quote(f'{ISSUER}:{account}')
    query = urlencode({'secret': secret, 'issuer': ISSUER, 'digits': DIGITS, 'period': PERIOD})
    return f'otpauth://totp/{label}?{query}'
