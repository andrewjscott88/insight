"""ID token checks (ADR 0046): every check has a test that it refuses what it should."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from tests.oidc_fixtures import CLIENT_ID, ISSUER, Key, b64, claims, token

from insight.id_tokens import CLOCK_SKEW, InvalidToken, verify_id_token

NONCE = 'nonce-123'
RSA = Key.make('RS256')


def check(raw: str, keys: list[Any] | None = None, *, nonce: str = NONCE, **kwargs: Any) -> Any:
    return verify_id_token(
        raw,
        keys=[RSA.jwk()] if keys is None else keys,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        nonce=nonce,
        now=kwargs.pop('now', time.time()),
        **kwargs,
    )


@pytest.mark.parametrize('alg', ['RS256', 'PS256', 'ES256'])
def test_each_allowed_algorithm_verifies(alg: str) -> None:
    key = Key.make(alg)
    identity = check(token(key, claims(NONCE)), [key.jwk()])
    assert (identity.subject, identity.email, identity.display_name, identity.groups) == (
        'subject-1',
        'ann@example.org',
        'Ann Analyst',
        ('insight-analysts',),
    )


@pytest.mark.parametrize('alg', ['none', 'HS256', 'HS512', 'RS384', 'ES512', 'EdDSA', ''])
def test_other_algorithms_are_refused(alg: str) -> None:
    with pytest.raises(InvalidToken, match='algorithm not allowed'):
        check(token(RSA, claims(NONCE), alg=alg))


def test_an_unsigned_token_is_refused() -> None:
    head = b64(json.dumps({'alg': 'none'}).encode())
    with pytest.raises(InvalidToken):
        check(f'{head}.{b64(json.dumps(claims(NONCE)).encode())}.')


@pytest.mark.parametrize('name', ['jku', 'jwk', 'x5u', 'crit'])
def test_headers_that_point_elsewhere_are_refused(name: str) -> None:
    with pytest.raises(InvalidToken, match='header not allowed'):
        check(token(RSA, claims(NONCE), header={name: 'https://attacker.example/keys'}))


def test_the_signature_must_match() -> None:
    raw = token(RSA, claims(NONCE))
    head, _, signature = raw.split('.')
    forged = b64(json.dumps(claims(NONCE, sub='admin')).encode())
    with pytest.raises(InvalidToken, match='bad signature'):
        check(f'{head}.{forged}.{signature}')
    other = Key.make('RS256')
    with pytest.raises(InvalidToken, match='bad signature'):
        check(token(other, claims(NONCE)))


@pytest.mark.parametrize(
    'keys',
    [
        [],
        [Key.make('RS256', kid='other').jwk()],
        [RSA.jwk(use='enc')],
        [RSA.jwk(alg='PS256')],
        [RSA.jwk(), {**RSA.jwk(), 'n': RSA.jwk()['n']}],
        [Key.make('ES256', kid='key-1').jwk()],
        ['not a key'],
    ],
)
def test_exactly_one_fitting_key_must_be_found(keys: list[Any]) -> None:
    with pytest.raises(InvalidToken):
        check(token(RSA, claims(NONCE)), keys)


def test_a_small_rsa_key_is_refused() -> None:
    small = Key.make('RS256', bits=1024)
    with pytest.raises(InvalidToken, match='too small'):
        check(token(small, claims(NONCE)), [small.jwk()])


@pytest.mark.parametrize(
    ('changes', 'message'),
    [
        ({'iss': 'https://idp.example.org/realms/other'}, 'wrong issuer'),
        ({'iss': ISSUER + '/'}, 'wrong issuer'),
        ({'aud': 'someone-else'}, 'wrong audience'),
        ({'aud': ['someone-else', 'another']}, 'wrong audience'),
        ({'aud': [CLIENT_ID, 'another']}, 'wrong authorised party'),
        ({'aud': [CLIENT_ID, 'another'], 'azp': 'another'}, 'wrong authorised party'),
        ({'azp': 'another'}, 'wrong authorised party'),
        ({'aud': 7}, 'bad audience'),
        ({'exp': int(time.time()) - CLOCK_SKEW - 5}, 'expired'),
        ({'exp': None}, 'missing or bad exp'),
        ({'exp': True}, 'missing or bad exp'),
        ({'iat': int(time.time()) + CLOCK_SKEW + 60}, 'issued in the future'),
        ({'nbf': int(time.time()) + CLOCK_SKEW + 60}, 'not valid yet'),
        ({'nonce': 'replayed'}, 'wrong nonce'),
        ({'nonce': None}, 'wrong nonce'),
        ({'sub': None}, 'bad subject'),
        ({'sub': 'x' * 256}, 'bad subject'),
    ],
)
def test_claims_are_checked(changes: dict[str, Any], message: str) -> None:
    body = {key: value for key, value in {**claims(NONCE), **changes}.items() if value is not None}
    with pytest.raises(InvalidToken, match=message):
        check(token(RSA, body))


def test_several_audiences_need_this_client_as_the_authorised_party() -> None:
    identity = check(token(RSA, claims(NONCE, aud=[CLIENT_ID, 'another'], azp=CLIENT_ID)))
    assert identity.subject == 'subject-1'


def test_a_little_clock_skew_is_allowed() -> None:
    now = time.time()
    raw = token(RSA, claims(NONCE, exp=int(now) - 30, iat=int(now) + 30))
    assert check(raw, now=now).subject == 'subject-1'


def test_an_empty_expected_nonce_matches_nothing() -> None:
    with pytest.raises(InvalidToken, match='wrong nonce'):
        check(token(RSA, claims('')), nonce='')


@pytest.mark.parametrize(
    'raw', ['', 'a.b', 'a.b.c.d', '!!!.e30.sig', 'e30.e30.e30', 'x' * 20_000, f'{b64(b"[]")}.{b64(b"{}")}.x']
)
def test_malformed_tokens_are_refused(raw: str) -> None:
    with pytest.raises(InvalidToken):
        check(raw)


@pytest.mark.parametrize(
    ('changes', 'email'),
    [
        ({}, 'ann@example.org'),
        ({'email_verified': False}, ''),
        ({'email_verified': 'true'}, ''),
        ({'email_verified': None}, ''),
    ],
)
def test_an_email_is_used_only_when_verified(changes: dict[str, Any], email: str) -> None:
    assert check(token(RSA, claims(NONCE, **changes))).email == email


@pytest.mark.parametrize(
    ('groups', 'expected'),
    [(['a', 'b'], ('a', 'b')), ('solo', ('solo',)), ([1, 'b', None], ('b',)), ({'a': 1}, ()), (None, ())],
)
def test_groups_come_from_the_configured_claim(groups: Any, expected: tuple[str, ...]) -> None:
    raw = token(RSA, claims(NONCE, groups=None, roles=groups))
    assert check(raw, groups_claim='roles').groups == expected
