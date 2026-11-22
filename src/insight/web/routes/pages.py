"""Health, the sign-in page and sign-out."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from ..auth import MFA_UNPAIRED, SessionCheck, _mfa_paired, end_sessions, start_session
from ..boundary import tokens_match

log = logging.getLogger('insight.auth')


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
        request.session.setdefault('csrf', secrets.token_urlsafe(32))
        mfa: bool = app.state.settings.mfa
        locked = mfa and not _mfa_paired(app.state.session_factory)
        return templates.TemplateResponse(
            request=request,
            name='login.html',
            context={
                'csrf_token': request.session['csrf'],
                'error': MFA_UNPAIRED if locked else None,
                'mfa': mfa,
            },
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
        ended = await asyncio.to_thread(end_sessions, app, request.session.get('sid'), everywhere=everywhere)
        if everywhere:
            log.info('Operator signed out everywhere: %d session(s) ended', ended)
        request.session.clear()
        return RedirectResponse('/login', status_code=303)
