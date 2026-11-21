"""How the authenticator-app seed is stored (code review L2, TIP 0.6)."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import services
from insight.models import OperatorMfa

SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'


@pytest.mark.xfail(
    strict=True,
    reason=(
        'Known defect, review L2 / TIP 0.6: the TOTP seed is stored in plain text. Encrypting it at rest '
        '(HKDF from INSIGHT_SESSION_SECRET, then AES-GCM) needs the cryptography package in the hash-pinned '
        'locks first. Remove this marker when the fix lands.'
    ),
)
def test_regression_l2_the_totp_seed_is_not_stored_in_plain_text(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        services.pair_mfa(db, SEED, 0)
    with session_factory() as db:
        stored = db.scalar(select(OperatorMfa.secret))
    assert stored is not None
    assert SEED not in stored
