"""The sign-in form's POST: the operator's password, plus an authenticator code when MFA is on (ADR 0002)."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from ... import services
from ...config import Settings
from ...models import SessionFactory
from ..auth import (
    LOGIN_MAX_FAILURES,
    LOGIN_WINDOW_SECONDS,
    MFA_UNPAIRED,
    MFA_UNPAIRED_LOG,
    new_session_id,
    same_secret,
    set_session_cookie,
)
from ..boundary import tokens_match

log = logging.getLogger('insight.auth')


def _mfa_paired(sessions: SessionFactory) -> bool:
    with sessions() as db:
        return services.mfa_paired(db)


def _check_code(sessions: SessionFactory, code: str, session_secret: str) -> bool:
    """One transaction, so an accepted code is marked used atomically (False if no app is paired)."""
    with sessions.begin() as db:
        services.set_actor(db, 'operator')
        return services.verify_mfa_code(db, code, session_secret=session_secret)


def _register_login(app: FastAPI, settings: Settings, templates: Jinja2Templates) -> None:
    sessions: SessionFactory = app.state.session_factory

    @app.post('/login')
    async def login(request: Request) -> Response:
        form = await request.form(max_fields=4)
        csrf = request.session.get('csrf')
        if not tokens_match(form.get('csrf_token'), csrf):
            raise HTTPException(403, 'Invalid CSRF token')
        password = str(form.get('password', ''))
        code = str(form.get('otp', ''))
        mfa = settings.mfa
        if mfa and not await asyncio.to_thread(_mfa_paired, sessions):
            # Fail closed, before any password check: a switched-on second factor never silently disappears.
            log.error(MFA_UNPAIRED_LOG)
            return templates.TemplateResponse(
                request=request,
                name='login.html',
                status_code=503,
                context={'csrf_token': csrf, 'error': MFA_UNPAIRED, 'mfa': mfa},
            )
        # Checks run one at a time (the lock also keeps a code from being used twice), but the delay after a
        # failure is served outside the lock: the operator never waits behind other clients' failures (M1).
        # Once the backstop is reached, wrong passwords are refused, still after the delay; the right one
        # signs in, so a flood of bad guesses cannot lock the operator out (ADR 0002).
        async with app.state.login_lock:
            current = time.time()
            app.state.failures[:] = [t for t in app.state.failures if current - t < LOGIN_WINDOW_SECONDS]
            limited = len(app.state.failures) >= LOGIN_MAX_FAILURES
            password_ok = same_secret(password, settings.password)
            # The code is only checked (and consumed) once the password is right, so wrong guesses never burn
            # a valid code. One answer for either mistake: nothing tells a guesser which factor was wrong.
            code_ok = not mfa
            if password_ok and mfa:
                code_ok = await asyncio.to_thread(_check_code, sessions, code, settings.session_secret)
            failed = not (password_ok and code_ok)
            if failed and not limited:  # Bounded: at most LOGIN_MAX_FAILURES timestamps are kept.
                app.state.failures.append(current)
        if failed:
            reason = 'password' if not password_ok else 'authentication code'
            failures = len(app.state.failures)
            log.warning('Failed sign-in attempt: wrong %s (%d in the last minute)', reason, failures)
            await asyncio.sleep(settings.failed_login_delay)
            if limited:
                log.warning('Sign-in refused: %d failures in the last minute', failures)
                raise HTTPException(429, 'Too many login attempts; wait one minute')
            error = 'Incorrect password or authentication code.' if mfa else 'Incorrect password.'
            return templates.TemplateResponse(
                request=request,
                name='login.html',
                status_code=401,
                context={'csrf_token': csrf, 'error': error, 'mfa': mfa},
            )
        sid = await asyncio.to_thread(new_session_id, app, request.session.get('sid'), current)
        set_session_cookie(request, sid)
        log.info('Operator signed in%s', ' (password and authentication code)' if mfa else '')
        return RedirectResponse('/', status_code=303)
