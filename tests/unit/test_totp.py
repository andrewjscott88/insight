"""RFC 6238 TOTP: reference vectors, drift window, replay protection and the provisioning URI."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from insight import totp

RFC_SECRET = base64.b32encode(b'12345678901234567890').decode()  # RFC 6238 appendix B (SHA-1)


@pytest.mark.parametrize(
    ('at', 'eight_digits'),
    [
        (59, '94287082'),
        (1111111109, '07081804'),
        (1111111111, '14050471'),
        (1234567890, '89005924'),
        (2000000000, '69279037'),
        (20000000000, '65353130'),
    ],
)
def test_rfc_6238_reference_values(at: int, eight_digits: str) -> None:
    # The RFC lists 8-digit codes; 6-digit codes are the same value modulo 10**6.
    assert totp.code_at(RFC_SECRET, totp.time_step(at)) == eight_digits[-6:]


def test_secrets_are_160_bit_base32_and_unique() -> None:
    secrets = {totp.generate_secret() for _ in range(20)}
    assert len(secrets) == 20
    for secret in secrets:
        assert len(base64.b32decode(secret)) == 20
        assert secret.isalnum()
        assert secret.isupper()


def test_codes_from_adjacent_steps_are_accepted_for_clock_drift() -> None:
    at = 1_700_000_000.0
    step = totp.time_step(at)
    for drift in (-1, 0, 1):
        code = totp.code_at(RFC_SECRET, step + drift)
        assert totp.matching_step(RFC_SECRET, code, at) == step + drift
    for drift in (-2, 2):
        assert totp.matching_step(RFC_SECRET, totp.code_at(RFC_SECRET, step + drift), at) is None


def test_used_and_older_steps_are_refused() -> None:
    at = 1_700_000_000.0
    step = totp.time_step(at)
    code = totp.code_at(RFC_SECRET, step)
    assert totp.matching_step(RFC_SECRET, code, at, after=step - 1) == step
    assert totp.matching_step(RFC_SECRET, code, at, after=step) is None  # replay
    previous = totp.code_at(RFC_SECRET, step - 1)
    assert totp.matching_step(RFC_SECRET, previous, at, after=step) is None  # older than the last used


@pytest.mark.parametrize('code', ['', '12345', '1234567', 'abcdef', '12 34 5', '１２３４５６'])
def test_malformed_codes_are_refused(code: str) -> None:
    assert totp.matching_step(RFC_SECRET, code, 1_700_000_000.0) is None


def test_spaces_are_ignored() -> None:
    at = 1_700_000_000.0
    code = totp.code_at(RFC_SECRET, totp.time_step(at))
    assert totp.matching_step(RFC_SECRET, f' {code[:3]} {code[3:]} ', at) == totp.time_step(at)


def test_secret_may_be_typed_with_spaces_and_lowercase() -> None:
    spaced = ' '.join(RFC_SECRET[i : i + 4] for i in range(0, len(RFC_SECRET), 4)).lower()
    assert totp.code_at(spaced, 1) == totp.code_at(RFC_SECRET, 1)


def test_provisioning_uri() -> None:
    uri = totp.provisioning_uri(RFC_SECRET)
    parts = urlsplit(uri)
    assert (parts.scheme, parts.netloc, parts.path) == ('otpauth', 'totp', '/Insight%3Aoperator')
    assert parse_qs(parts.query) == {
        'secret': [RFC_SECRET],
        'issuer': ['Insight'],
        'digits': ['6'],
        'period': ['30'],
    }
