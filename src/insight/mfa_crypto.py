"""Authenticated storage for the operator's TOTP seed (TIP 0.6)."""

from __future__ import annotations

import base64
import secrets
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import MIN_SECRET_LENGTH

_PREFIX: Final = 'v1:'
_CONTEXT: Final = b'insight:operator_mfa.secret:v1'
_NONCE_BYTES: Final = 12


def _cipher(session_secret: str) -> AESGCM:
    if len(session_secret) < MIN_SECRET_LENGTH:
        raise ValueError(f'MFA encryption needs INSIGHT_SESSION_SECRET ({MIN_SECRET_LENGTH}+ characters)')
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_CONTEXT).derive(session_secret.encode())
    return AESGCM(key)


def encrypt_seed(seed: str, session_secret: str) -> str:
    """Wrap a seed with a fresh 96-bit nonce on every write."""
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = _cipher(session_secret).encrypt(nonce, seed.encode('utf-8'), _CONTEXT)
    return _PREFIX + base64.b64encode(nonce + ciphertext).decode('ascii')


def decrypt_seed(envelope: str, session_secret: str) -> str:
    """Return the authenticated seed or raise ValueError without exposing secret material."""
    if not envelope.startswith(_PREFIX):
        raise ValueError('Unrecognized stored MFA seed format')
    cipher = _cipher(session_secret)
    try:
        packet = base64.b64decode(envelope[len(_PREFIX) :], validate=True)
        if len(packet) < _NONCE_BYTES + 16:  # GCM authentication tag
            raise ValueError
        return cipher.decrypt(packet[:_NONCE_BYTES], packet[_NONCE_BYTES:], _CONTEXT).decode('utf-8')
    except (InvalidTag, ValueError):
        raise ValueError('Cannot read the stored MFA seed with the configured session secret') from None
