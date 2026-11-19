"""API key format, parsing and hashing (pure functions)."""

from __future__ import annotations

import pytest

from insight import apikeys


def test_generated_keys_are_well_formed_unique_and_only_hashed() -> None:
    first, second = apikeys.generate(), apikeys.generate()
    assert first.token.startswith('insk_')
    assert apikeys.parse_key_id(first.token) == first.key_id
    assert first.token_hash == apikeys.hash_token(first.token)
    assert first.token not in first.token_hash
    assert len({first.key_id, second.key_id}) == 2
    assert first.token != second.token


def test_token_matches_only_the_exact_key() -> None:
    key = apikeys.generate()
    assert apikeys.token_matches(key.token, key.token_hash)
    assert not apikeys.token_matches(key.token[:-1] + ('A' if key.token[-1] != 'A' else 'B'), key.token_hash)
    assert not apikeys.token_matches(apikeys.generate().token, key.token_hash)


@pytest.mark.parametrize(
    'token',
    [
        '',
        'insk_',
        'insk_0123456789ab',
        'insk_0123456789ab_' + 'A' * 42,  # secret too short
        'insk_0123456789ab_' + 'A' * 44,  # too long
        'insk_0123456789AB_' + 'A' * 43,  # key ID is lowercase hex
        'insk_0123456789ab_' + 'A' * 42 + '!',
        'xxxx_0123456789ab_' + 'A' * 43,
        ' insk_0123456789ab_' + 'A' * 43,
    ],
)
def test_malformed_keys_are_rejected_before_any_lookup(token: str) -> None:
    assert apikeys.parse_key_id(token) is None


@pytest.mark.parametrize(
    ('header', 'expected'),
    [
        ('Bearer abc', 'abc'),
        ('bearer abc', 'abc'),
        ('BEARER   abc  ', 'abc'),
        ('Bearer', None),
        ('Bearer ', None),
        ('Basic dXNlcjpwYXNz', None),  # e.g. basic auth added by a reverse proxy: not an API key
        ('', None),
        ('abc', None),
    ],
)
def test_bearer_token(header: str, expected: str | None) -> None:
    assert apikeys.bearer_token(header) == expected


@pytest.mark.parametrize('days', [0, -1, apikeys.MAX_EXPIRY_DAYS + 1])
def test_expiry_is_bounded(days: int) -> None:
    with pytest.raises(ValueError, match='between 1 and'):
        apikeys.check_expiry_days(days)


def test_expiry_bounds_are_inclusive() -> None:
    assert apikeys.check_expiry_days(1) == 1
    assert apikeys.check_expiry_days(apikeys.MAX_EXPIRY_DAYS) == apikeys.MAX_EXPIRY_DAYS
