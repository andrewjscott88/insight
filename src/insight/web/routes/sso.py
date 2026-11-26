"""Sign-in through the identity provider (ADR 0046): ``/login/sso`` sends the browser there, and the provider
sends it back to ``/login/sso/callback``.

The session cookie is ``SameSite=Strict``, so browsers leave it out when a provider on another site sends
them back. The callback's ``GET`` therefore only carries the code and state, unchecked, to a same-site form
``POST`` to the same address, which does get the cookie. There the state must match the one this browser
stored, at most ten minutes ago, once; the code is exchanged with the PKCE verifier, and the ID token is
checked (``insight.id_tokens``). Failed callbacks count against the address; once ten in a minute have
failed, callbacks from it are refused before anything reaches the provider.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from ... import services
from ...id_tokens import Identity
from ...oidc import Flow, OidcClient, SignInFailed
from ...ratelimit import SSO_FAILURES
from ..auth import new_session_id, set_session_cookie
from ..boundary import tokens_match
from .pages import login_context

log = logging.getLogger('insight.auth')

FAILED = 'Sign-in through your identity provider did not work. Try again, or ask your administrator.'
DISABLED = 'Your account is turned off. Ask an administrator of this workspace.'


def _record(app: FastAPI, identity: Identity, now: float) -> tuple[str, bool]:
    """Add or update the person (blocking: database); returns their ID and whether they are disabled."""
    oidc = app.state.settings.oidc
    with app.state.session_factory.begin() as db:
        user = services.record_sign_in(
            db,
            issuer=oidc.issuer,
            subject=identity.subject,
            email=identity.email,
            display_name=identity.display_name,
            group_role=oidc.role_for(identity.groups),
            groups_mapped=oidc.groups_mapped,
            at=datetime.fromtimestamp(now, UTC),
        )
        return user.id, user.disabled


def _register_sso_routes(app: FastAPI, templates: Jinja2Templates) -> None:
    def client() -> OidcClient:
        found: OidcClient | None = app.state.oidc_client
        if found is None:
            raise HTTPException(404, 'Not Found')
        return found

    async def refused(request: Request, error: str, status: int) -> Response:
        context = await asyncio.to_thread(login_context, app, request.session)
        return templates.TemplateResponse(
            request=request, name='login.html', status_code=status, context={**context, 'error': error}
        )

    @app.get('/login/sso')
    async def start(request: Request) -> Response:
        oidc = client()
        now = time.time()
        flow = Flow.new(now)
        try:
            target = await oidc.authorization_url(flow, now)
        except SignInFailed as exc:
            log.warning('SSO sign-in could not start: %s', exc)
            return await refused(request, FAILED, 502)
        request.session['oidc'] = flow.as_cookie()
        return RedirectResponse(target, status_code=303)

    @app.get('/login/sso/callback')
    def carry(request: Request) -> Response:
        client()
        params = request.query_params
        return templates.TemplateResponse(
            request=request,
            name='sso_continue.html',
            context={
                'code': params.get('code', '')[:4096],
                'state': params.get('state', '')[:512],
                'error': params.get('error', '')[:200],
            },
        )

    @app.post('/login/sso/callback')
    async def finish(request: Request) -> Response:
        oidc = client()
        form = await request.form(max_fields=4)
        flow = Flow.from_cookie(request.session.pop('oidc', None))  # Used once, whatever happens next.
        now = time.time()
        address = request.client.host if request.client else 'unknown'
        limiter = app.state.auth_failure_limiter
        if not limiter.allows(address, SSO_FAILURES):
            log.warning('Refused SSO callback from %s: too many failed sign-ins in the last minute', address)
            raise HTTPException(429, 'Too many failed sign-ins; wait one minute')
        problem = None
        if flow is None or flow.expired(now) or not tokens_match(form.get('state'), flow.state):
            problem = 'no matching sign-in in this browser, or it took over ten minutes'
        elif form.get('error'):
            problem = 'the provider did not sign the person in'
        if problem is not None or flow is None:
            log.warning('Refused SSO callback from %s: %s', address, problem)
            limiter.hit(address, SSO_FAILURES)
            return await refused(request, FAILED, 400)
        try:
            identity = await oidc.finish(str(form.get('code', '')), flow, now)
        except SignInFailed as exc:
            log.warning('Refused SSO sign-in from %s: %s', address, exc)
            limiter.hit(address, SSO_FAILURES)
            return await refused(request, FAILED, 400)
        user_id, disabled = await asyncio.to_thread(_record, app, identity, now)
        if disabled:
            log.warning('Refused SSO sign-in: user:%s is turned off', user_id)
            return await refused(request, DISABLED, 403)
        sid = await asyncio.to_thread(new_session_id, app, request.session.get('sid'), now, user_id=user_id)
        set_session_cookie(request, sid)
        log.info('Signed in through the identity provider: user:%s', user_id)
        return RedirectResponse('/', status_code=303)
