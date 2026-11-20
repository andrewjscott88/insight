"""Health, the sign-in page and sign-out."""

from __future__ import annotations

import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from ... import __version__
from ..auth import MFA_UNPAIRED, SessionCheck, _mfa_paired
from ..boundary import tokens_match


def _register_page_routes(app: FastAPI, templates: Jinja2Templates) -> None:
    """Health check and the sign-in/sign-out pages (HTML forms, CSRF-protected)."""
    authenticated: SessionCheck = app.state.is_authenticated

    @app.get('/health')
    def health() -> dict[str, str]:
        return {'status': 'ok', 'version': __version__}

    @app.get('/login')
    def login_page(request: Request) -> Response:
        if authenticated(request.session):
            return RedirectResponse('/', status_code=303)
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
            request=request, name='logout.html', context={'csrf_token': request.session['csrf']}
        )

    @app.post('/logout')
    async def logout(request: Request) -> Response:
        form = await request.form(max_fields=4)
        if not tokens_match(form.get('csrf_token'), request.session.get('csrf')):
            raise HTTPException(403, 'Invalid CSRF token')
        app.state.active_sessions.pop(request.session.get('sid'), None)
        request.session.clear()
        return RedirectResponse('/login', status_code=303)
