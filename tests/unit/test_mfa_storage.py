"""Authenticated encryption and replay protection for the operator's authenticator seed."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import services, totp
from insight.models import OperatorMfa

SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
SESSION_SECRET = 'first synthetic session secret for tests'
OTHER_SECRET = 'other synthetic session secret for tests'
STEP = 1_234_567


def test_regression_l2_the_totp_seed_is_not_stored_in_plain_text(
    session_factory: sessionmaker[Session],
) -> None:
    envelopes = []
    for _ in range(2):
        with session_factory.begin() as db:
            services.pair_mfa(db, SEED, STEP, session_secret=SESSION_SECRET)
        with session_factory.begin() as db:
            stored = db.scalars(select(OperatorMfa)).one()
            assert SEED not in stored.secret
            assert stored.last_step == STEP
            envelopes.append(stored.secret)
            assert services.reset_mfa(db)
    assert envelopes[0] != envelopes[1]


@pytest.mark.parametrize('key', ['', 'short'])
def test_pairing_requires_a_configured_encryption_key(db: Session, key: str) -> None:
    with pytest.raises(ValueError, match=r'(?i)session.secret'):
        services.pair_mfa(db, SEED, STEP, session_secret=key)
    assert not services.mfa_paired(db)


def test_a_different_key_cannot_consume_the_code_or_change_the_pairing(db: Session) -> None:
    services.pair_mfa(db, SEED, STEP, session_secret=SESSION_SECRET)
    row = db.scalars(select(OperatorMfa)).one()
    envelope = row.secret
    at = (STEP + 1) * totp.PERIOD
    code = totp.code_at(SEED, STEP + 1)
    assert not services.verify_mfa_code(db, code, at, session_secret=OTHER_SECRET)
    assert (row.secret, row.last_step) == (envelope, STEP)
    assert services.verify_mfa_code(db, code, at, session_secret=SESSION_SECRET)
    assert not services.verify_mfa_code(db, code, at, session_secret=SESSION_SECRET)


@pytest.mark.parametrize('stored_value', ['damaged envelope', SEED])
def test_unreadable_storage_never_authenticates_as_a_plaintext_seed(db: Session, stored_value: str) -> None:
    services.pair_mfa(db, SEED, STEP, session_secret=SESSION_SECRET)
    row = db.scalars(select(OperatorMfa)).one()
    row.secret = stored_value
    db.flush()
    code = totp.code_at(SEED, STEP + 1)
    assert not services.verify_mfa_code(db, code, (STEP + 1) * totp.PERIOD, session_secret=SESSION_SECRET)
    assert (row.secret, row.last_step) == (stored_value, STEP)
