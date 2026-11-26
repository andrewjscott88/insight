"""Checking an OpenID Connect ID token (ADR 0046). Pure: no network, no database.

Only ``RS256``, ``PS256`` and ``ES256`` signatures are accepted, verified with ``cryptography`` against a key
from the provider's key set; ``none``, every ``HS*`` algorithm and anything else are refused, and so are
headers that point at other keys (``jku``, ``jwk``, ``x5u``) or demand unknown extensions (``crit``). Then
the claims: the issuer exactly, the audience (and the authorised party when there are several audiences),
expiry and issue time within two minutes of clock skew, and the nonce of this sign-in.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

ALGORITHMS: Final = frozenset({'RS256', 'PS256', 'ES256'})
#: Seconds the provider's clock may differ from ours.
CLOCK_SKEW: Final = 120
MIN_RSA_BITS: Final = 2048
MAX_TOKEN_LENGTH: Final = 16_384
_REFUSED_HEADERS: Final = frozenset({'jku', 'jwk', 'x5u', 'crit'})


class InvalidToken(ValueError):
    """The ID token failed a check. The message is for logs only and never holds token contents."""


@dataclass(frozen=True, slots=True)
class Identity:
    """Who the provider vouches for."""

    subject: str
    #: Only an address the provider says is verified; otherwise empty.
    email: str
    display_name: str
    groups: tuple[str, ...]


def _b64(part: str) -> bytes:
    if not part or len(part) % 4 == 1:
        raise InvalidToken('malformed token')
    try:
        return base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))
    except (binascii.Error, ValueError):
        raise InvalidToken('malformed token') from None


def _json(part: str) -> dict[str, Any]:
    try:
        value = json.loads(_b64(part))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidToken('malformed token') from None
    if not isinstance(value, dict):
        raise InvalidToken('malformed token')
    return value


def _integer(value: object) -> int:
    if not isinstance(value, str):
        raise InvalidToken('malformed key')
    return int.from_bytes(_b64(value), 'big')


def _key_for(header: Mapping[str, Any], keys: Sequence[object]) -> Mapping[str, Any]:
    """The one key in the set that may verify this token: same ``kid`` (when given), signing use, and a key
    type and curve that fit the algorithm."""
    alg = header['alg']
    kty, crv = ('EC', 'P-256') if alg == 'ES256' else ('RSA', None)
    kid = header.get('kid')
    candidates: list[Mapping[str, Any]] = [
        key
        for key in keys
        if isinstance(key, Mapping)
        and key.get('kty') == kty
        and (crv is None or key.get('crv') == crv)
        and key.get('use', 'sig') == 'sig'
        and key.get('alg', alg) == alg
        and (kid is None or key.get('kid') == kid)
    ]
    if len(candidates) != 1:
        raise InvalidToken('no single matching signing key')
    return candidates[0]


def _verify_ec(key: Mapping[str, Any], signed: bytes, signature: bytes) -> None:
    if len(signature) != 64:  # JWS: r and s, 32 bytes each (RFC 7518 3.4), not DER.
        raise InvalidToken('bad signature')
    x, y = _integer(key.get('x')), _integer(key.get('y'))
    try:
        public = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError:  # Not a point on the curve.
        raise InvalidToken('malformed key') from None
    der = utils.encode_dss_signature(
        int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    )
    try:
        public.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise InvalidToken('bad signature') from None


def _verify_rsa(alg: str, key: Mapping[str, Any], signed: bytes, signature: bytes) -> None:
    e, n = _integer(key.get('e')), _integer(key.get('n'))
    try:
        public = rsa.RSAPublicNumbers(e, n).public_key()
    except ValueError:
        raise InvalidToken('malformed key') from None
    if public.key_size < MIN_RSA_BITS:
        raise InvalidToken('signing key too small')
    if alg == 'RS256':
        scheme: padding.AsymmetricPadding = padding.PKCS1v15()
    else:  # PS256: RFC 7518 3.5, with a salt as long as the hash.
        scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size)
    try:
        public.verify(signature, signed, scheme, hashes.SHA256())
    except InvalidSignature:
        raise InvalidToken('bad signature') from None


def _verify_signature(alg: str, key: Mapping[str, Any], signed: bytes, signature: bytes) -> None:
    if alg == 'ES256':
        _verify_ec(key, signed, signature)
    else:
        _verify_rsa(alg, key, signed, signature)


def _number(claims: Mapping[str, Any], name: str) -> float:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidToken(f'missing or bad {name}')
    return float(value)


def _check_claims(claims: Mapping[str, Any], *, issuer: str, client_id: str, nonce: str, now: float) -> None:
    if claims.get('iss') != issuer:
        raise InvalidToken('wrong issuer')
    audience = claims.get('aud')
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or not all(isinstance(a, str) for a in audiences):
        raise InvalidToken('bad audience')
    if client_id not in audiences:
        raise InvalidToken('wrong audience')
    azp = claims.get('azp')
    if (len(audiences) > 1 or azp is not None) and azp != client_id:
        raise InvalidToken('wrong authorised party')
    if _number(claims, 'exp') <= now - CLOCK_SKEW:
        raise InvalidToken('expired')
    if _number(claims, 'iat') > now + CLOCK_SKEW:
        raise InvalidToken('issued in the future')
    if 'nbf' in claims and _number(claims, 'nbf') > now + CLOCK_SKEW:
        raise InvalidToken('not valid yet')
    given = claims.get('nonce')
    if not isinstance(given, str) or not nonce or not hmac.compare_digest(given.encode(), nonce.encode()):
        raise InvalidToken('wrong nonce')
    subject = claims.get('sub')
    if not isinstance(subject, str) or not 0 < len(subject) <= 255:
        raise InvalidToken('bad subject')


def _identity(claims: Mapping[str, Any], groups_claim: str) -> Identity:
    email = claims.get('email')
    verified = claims.get('email_verified') is True and isinstance(email, str)
    name = next(
        (
            v
            for v in (claims.get('name'), claims.get('preferred_username'))
            if isinstance(v, str) and v.strip()
        ),
        '',
    )
    raw = claims.get(groups_claim)
    values: list[Any] = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    return Identity(
        subject=str(claims['sub']),
        email=str(email)[:320] if verified else '',
        display_name=name.strip()[:200],
        groups=tuple(g for g in values if isinstance(g, str))[:200],
    )


def verify_id_token(
    token: str,
    *,
    keys: Sequence[object],
    issuer: str,
    client_id: str,
    nonce: str,
    now: float,
    groups_claim: str = 'groups',
) -> Identity:
    """Check ``token`` and return who it names; raises :class:`InvalidToken` for any failed check."""
    if len(token) > MAX_TOKEN_LENGTH or token.count('.') != 2:
        raise InvalidToken('malformed token')
    header_part, claims_part, signature_part = token.split('.')
    header = _json(header_part)
    alg = header.get('alg')
    if alg not in ALGORITHMS:
        raise InvalidToken('algorithm not allowed')
    if _REFUSED_HEADERS & header.keys():
        raise InvalidToken('header not allowed')
    key = _key_for(header, keys)
    _verify_signature(str(alg), key, f'{header_part}.{claims_part}'.encode(), _b64(signature_part))
    claims = _json(claims_part)
    _check_claims(claims, issuer=issuer, client_id=client_id, nonce=nonce, now=now)
    return _identity(claims, groups_claim)
