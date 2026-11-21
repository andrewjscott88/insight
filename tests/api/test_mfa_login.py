"""Sign-in second factor: off by default; ``INSIGHT_MFA=on`` requires a code from a paired authenticator app.

Pairing (``insight mfa setup``) and the switch (``INSIGHT_MFA``, set by ``make mfa-enable``/``mfa-disable``)
are separate: an app can stay paired while MFA is off, and MFA switched on without a paired app locks sign-in
rather than silently falling back to the password alone.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import migrations, services, totp
from insight.config import Settings
from insight.main import create_app
from insight.models import AuditEvent, OperatorMfa, database

from ..conftest import PASSWORD
from ..conftest import SECRET as SESSION_SECRET

SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'


def current_code(offset_steps: int = 0) -> str:
    return totp.code_at(SECRET, totp.time_step() + offset_steps)


def wrong_code() -> str:
    return '000000' if current_code() != '000000' else '111111'


def pair(app: FastAPI) -> None:
    with app.state.session_factory.begin() as db:
        services.set_actor(db, 'cli')
        services.pair_mfa(db, SECRET, totp.time_step() - 5, session_secret=app.state.settings.session_secret)


@pytest.fixture
def mfa_app(settings: Settings) -> FastAPI:
    """INSIGHT_MFA=on with an app paired."""
    app = create_app(dataclasses.replace(settings, mfa=True), with_ui=False)
    pair(app)
    return app


@pytest.fixture
def mfa_client(mfa_app: FastAPI) -> TestClient:
    return TestClient(mfa_app, follow_redirects=False)


def sign_in(
    client: TestClient, csrf_token_from: Callable[[str], str], password: str, code: str | None
) -> int:
    page = client.get('/login')
    data = {'csrf_token': csrf_token_from(page.text), 'password': password}
    if code is not None:
        data['otp'] = code
    return client.post('/login', data=data).status_code


# --------------------------------------------------------------------------- off by default


def test_mfa_is_off_by_default(settings: Settings, client: TestClient) -> None:
    assert settings.mfa is False
    assert 'name="otp"' not in client.get('/login').text


def test_a_paired_app_is_not_required_while_mfa_is_off(
    app: FastAPI, client: TestClient, csrf_token_from: Callable[[str], str]
) -> None:
    """Pairing alone changes nothing: the switch decides (so `make mfa-disable` keeps the pairing)."""
    pair(app)
    assert 'name="otp"' not in client.get('/login').text
    assert sign_in(client, csrf_token_from, PASSWORD, None) == 303


# --------------------------------------------------------------------------- switched on


def test_the_form_asks_for_a_code(mfa_client: TestClient) -> None:
    page = mfa_client.get('/login').text
    assert 'name="otp"' in page
    assert 'autocomplete="one-time-code"' in page
    assert 'Sign-in is locked' not in page


def test_password_and_code_sign_in(
    mfa_client: TestClient, csrf_token_from: Callable[[str], str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger='insight.auth')
    assert sign_in(mfa_client, csrf_token_from, PASSWORD, current_code()) == 303
    assert mfa_client.get('/api/stats').status_code == 200
    assert 'Operator signed in (password and authentication code)' in caplog.text


@pytest.mark.parametrize(
    ('password', 'code'),
    [(PASSWORD, None), (PASSWORD, ''), (PASSWORD, 'wrong'), (PASSWORD, 'STALE'), ('wrong-password', 'GOOD')],
)
def test_one_generic_answer_for_either_wrong_factor(
    mfa_client: TestClient, csrf_token_from: Callable[[str], str], password: str, code: str | None
) -> None:
    code = {'GOOD': current_code(), 'STALE': current_code(-3), 'wrong': wrong_code()}.get(code or '', code)
    page = mfa_client.get('/login')
    data = {'csrf_token': csrf_token_from(page.text), 'password': password}
    if code is not None:
        data['otp'] = code
    response = mfa_client.post('/login', data=data)
    assert response.status_code == 401
    assert 'Incorrect password or authentication code.' in response.text
    assert mfa_client.get('/api/stats').status_code == 401


def test_restarting_with_a_different_session_secret_fails_closed_and_preserves_pairing(
    mfa_app: FastAPI,
    settings: Settings,
    csrf_token_from: Callable[[str], str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    rotated_secret = 'different disposable session secret for this test'
    changed = dataclasses.replace(settings, mfa=True, session_secret=rotated_secret)
    caplog.clear()
    with TestClient(create_app(changed, with_ui=False), follow_redirects=False) as client:
        assert sign_in(client, csrf_token_from, PASSWORD, current_code()) == 401
        assert client.get('/api/stats').status_code == 401
    assert SECRET not in caplog.text
    assert rotated_secret not in caplog.text
    with TestClient(
        create_app(dataclasses.replace(settings, mfa=True), with_ui=False), follow_redirects=False
    ) as restored:
        assert sign_in(restored, csrf_token_from, PASSWORD, current_code()) == 303
        assert restored.get('/api/stats').status_code == 200


def test_a_code_works_only_once(mfa_app: FastAPI, csrf_token_from: Callable[[str], str]) -> None:
    code = current_code()
    with TestClient(mfa_app, follow_redirects=False) as first:
        assert sign_in(first, csrf_token_from, PASSWORD, code) == 303
    with TestClient(mfa_app, follow_redirects=False) as second:
        assert sign_in(second, csrf_token_from, PASSWORD, code) == 401  # replayed, e.g. shoulder-surfed


def test_startup_migrates_an_existing_pair_and_the_same_authenticator_can_sign_in(
    empty_database_url: str,
    settings: Settings,
    csrf_token_from: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, legacy = database(empty_database_url, migrate=False)
    try:
        migrations.upgrade(engine, '0016')
        with legacy.begin() as db:
            db.add(OperatorMfa(secret=SECRET, last_step=totp.time_step() - 5))
    finally:
        engine.dispose()

    # The app may receive settings directly, even when the host environment contains a different key.
    monkeypatch.setenv('INSIGHT_SESSION_SECRET', 'different session secret for this migration test')
    app = create_app(dataclasses.replace(settings, database_url=empty_database_url, mfa=True), with_ui=False)
    with TestClient(app, follow_redirects=False) as client:
        with app.state.session_factory() as db:
            assert SECRET not in db.scalars(select(OperatorMfa.secret)).one()
        code = current_code()
        assert sign_in(client, csrf_token_from, PASSWORD, code) == 303
        assert client.get('/api/stats').status_code == 200
    with TestClient(app, follow_redirects=False) as client:
        assert sign_in(client, csrf_token_from, PASSWORD, code) == 401


def test_a_wrong_password_does_not_burn_the_code(
    mfa_client: TestClient, csrf_token_from: Callable[[str], str]
) -> None:
    code = current_code()
    assert sign_in(mfa_client, csrf_token_from, 'wrong-password', code) == 401
    assert sign_in(mfa_client, csrf_token_from, PASSWORD, code) == 303


def test_failures_count_towards_the_sign_in_throttle(
    mfa_app: FastAPI,
    mfa_client: TestClient,
    csrf_token_from: Callable[[str], str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger='insight.auth')
    sign_in(mfa_client, csrf_token_from, PASSWORD, wrong_code())
    assert len(mfa_app.state.failures) == 1
    assert 'Failed sign-in attempt: wrong authentication code (1 in the last minute)' in caplog.text


def test_regression_m1_the_right_password_and_code_pass_the_backstop(
    mfa_app: FastAPI, mfa_client: TestClient, csrf_token_from: Callable[[str], str]
) -> None:
    for _ in range(30):
        sign_in(mfa_client, csrf_token_from, 'wrong password', wrong_code())
    assert sign_in(mfa_client, csrf_token_from, PASSWORD, wrong_code()) == 429
    assert sign_in(mfa_client, csrf_token_from, PASSWORD, current_code()) == 303


@pytest.mark.parametrize('code', ['１２３４５６', '١٢٣٤٥٦', '12345\u00b2'])
def test_non_ascii_digits_are_refused_not_a_server_error(
    mfa_client: TestClient, csrf_token_from: Callable[[str], str], code: str
) -> None:
    """Regression: str.isdigit() accepts full-width/Arabic-Indic digits, and compare_digest raised on them."""
    assert sign_in(mfa_client, csrf_token_from, PASSWORD, code) == 401


# --------------------------------------------------------------------------- switched on, nothing paired


def test_on_without_a_paired_app_locks_sign_in_instead_of_falling_back(
    settings: Settings, csrf_token_from: Callable[[str], str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger='insight.auth')
    app = create_app(dataclasses.replace(settings, mfa=True), with_ui=False)
    assert 'no authenticator app is paired' in caplog.text  # at start-up
    with TestClient(app, follow_redirects=False) as client:
        page = client.get('/login').text
        assert 'Sign-in is locked' in page
        assert 'make mfa-enable' in page
        response = client.post(
            '/login', data={'csrf_token': csrf_token_from(page), 'password': PASSWORD, 'otp': '123456'}
        )
        assert response.status_code == 503
        assert 'Sign-in is locked' in response.text
        assert client.get('/api/stats').status_code == 401
        assert app.state.failures == []  # not a guess: nothing counts towards the throttle
        pair(app)
        assert sign_in(client, csrf_token_from, PASSWORD, current_code()) == 303


# --------------------------------------------------------------------------- start-up notes


def test_startup_notes(settings: Settings, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger='insight.auth')
    public = dataclasses.replace(settings, trusted_proxies=('10.0.0.2',), secure_cookies=True)
    create_app(public, with_ui=False)
    assert 'MFA is off (INSIGHT_MFA=off)' in caplog.text
    assert not [r for r in caplog.records if 'MFA' in r.getMessage() and r.levelno >= logging.WARNING]
    caplog.clear()
    app = create_app(dataclasses.replace(public, mfa=True), with_ui=False)
    pair(app)
    caplog.clear()
    create_app(dataclasses.replace(public, mfa=True), with_ui=False)
    assert 'MFA is on' in caplog.text


# --------------------------------------------------------------------------- service


def test_pair_verify_reset(db: Session) -> None:
    assert not services.mfa_paired(db)
    assert not services.verify_mfa_code(
        db, current_code(), session_secret=SESSION_SECRET
    )  # nothing paired: fail closed
    services.pair_mfa(db, SECRET, totp.time_step() - 5, session_secret=SESSION_SECRET)
    assert services.mfa_paired(db)
    with pytest.raises(ValueError, match='already paired'):
        services.pair_mfa(db, SECRET, 0, session_secret=SESSION_SECRET)
    code = current_code()
    assert services.verify_mfa_code(db, code, session_secret=SESSION_SECRET)
    assert not services.verify_mfa_code(db, code, session_secret=SESSION_SECRET)  # each code works once
    assert not services.verify_mfa_code(db, wrong_code(), session_secret=SESSION_SECRET)
    assert services.reset_mfa(db)
    assert not services.reset_mfa(db)
    assert [e.action for e in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))] == [
        'mfa.pair',
        'mfa.reset',
    ]


def test_the_pairing_code_cannot_also_sign_in(db: Session) -> None:
    services.pair_mfa(db, SECRET, totp.time_step(), session_secret=SESSION_SECRET)
    assert not services.verify_mfa_code(db, current_code(), session_secret=SESSION_SECRET)
