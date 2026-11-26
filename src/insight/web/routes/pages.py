"""Health, the sign-in page and sign-out."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from ... import services
from ..auth import MFA_UNPAIRED, SessionCheck, _mfa_paired, end_sessions, start_session
from ..boundary import tokens_match

log = logging.getLogger('insight.auth')


def _waiting(app: FastAPI, session: Mapping[str, Any]) -> bool:
    """Whether this browser is signed in as a person who waits for an admin to give them a role."""
    sid = session.get('sid')
    if not (session.get('authenticated') and isinstance(sid, str) and sid):
        return False
    with app.state.session_factory() as db:
        principal = services.session_principal(
            db, sid, binding=app.state.session_binding, at=datetime.now(UTC)
        )
    return principal is not None and principal.user_id is not None and principal.role is None


def login_context(app: FastAPI, session: dict[str, Any]) -> dict[str, Any]:
    """What the sign-in page shows: the password form (unless sign-in is SSO only), the provider's button,
    and a note for a person waiting for approval (blocking: database)."""
    session.setdefault('csrf', secrets.token_urlsafe(32))
    settings = app.state.settings
    mfa: bool = settings.mfa
    locked = mfa and not _mfa_paired(app.state.session_factory)
    return {
        'csrf_token': session['csrf'],
        'error': MFA_UNPAIRED if locked else None,
        'mfa': mfa,
        'public_view': settings.public_view,
        'sso': settings.oidc is not None,
        'sso_only': settings.oidc is not None and settings.oidc.sso_only,
        'waiting': _waiting(app, session),
    }


def _register_page_routes(app: FastAPI, templates: Jinja2Templates) -> None:
    """Health check and the sign-in/sign-out pages (HTML forms, CSRF-protected)."""
    authenticated: SessionCheck = app.state.is_authenticated

    @app.get('/health')
    def health() -> dict[str, str]:
        return {'status': 'ok'}

    @app.get('/login')
    def login_page(request: Request) -> Response:
        if authenticated(request.session):
            return RedirectResponse('/', status_code=303)
        if app.state.settings.dev_no_auth:
            # This explicit mode skips only the password prompt. Every subsequent request still uses the
            # regular signed, stored session, same-origin checks, CSRF checks and rate limits.
            start_session(app, request, time.time())
            log.info('Password-free browser session started (temporary development access)')
            # Finish this navigation before continuing: browsers withhold SameSite=Strict cookies for an
            # entire cross-site HTTP redirect chain, including a cookie just set by this response.
            return templates.TemplateResponse(request=request, name='continue.html')
        return templates.TemplateResponse(
            request=request, name='login.html', context=login_context(app, request.session)
        )

    @app.get('/logout')
    def logout_page(request: Request) -> Response:
        if not authenticated(request.session):
            return RedirectResponse('/login', status_code=303)
        return templates.TemplateResponse(
            request=request,
            name='logout.html',
            context={
                'csrf_token': request.session['csrf'],
                'dev_no_auth': app.state.settings.dev_no_auth,
            },
        )

    @app.post('/logout')
    async def logout(request: Request) -> Response:
        form = await request.form(max_fields=4)
        if not tokens_match(form.get('csrf_token'), request.session.get('csrf')):
            raise HTTPException(403, 'Invalid CSRF token')
        everywhere = form.get('everywhere') == '1'
        caller = await asyncio.to_thread(app.state.session_caller, request.session) if everywhere else None
        ended = await asyncio.to_thread(end_sessions, app, request.session.get('sid'), everywhere=everywhere)
        if everywhere:
            who = caller.actor if caller is not None else 'someone'
            log.info('Signed out everywhere (%s): %d session(s) ended', who, ended)
        request.session.clear()
        return RedirectResponse('/login', status_code=303)
