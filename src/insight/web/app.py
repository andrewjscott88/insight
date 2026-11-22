"""Application factory. One process, one local operator; no implicit network calls."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .. import __version__, services
from ..appearance import PAGE_BACKGROUND, TEXT_SIZE_COOKIE, THEME_COOKIE, text_size_choice, theme_choice
from ..config import Settings
from ..models import SessionFactory, database
from ..ratelimit import RateLimiter
from .auth import (
    MFA_UNPAIRED_LOG,
    SESSION_TTL_SECONDS,
    _register_login,
    api_key_verifier,
    auth_dependency,
    session_checker,
)
from .boundary import BoundaryMiddleware
from .routes.campaigns import _register_campaign_routes
from .routes.cves import _register_cve_routes
from .routes.documents import _register_document_routes
from .routes.entities import _register_entity_routes
from .routes.exports import _register_export_routes
from .routes.hunting import _register_hunting_routes
from .routes.imports import _register_import_routes
from .routes.landscape import _register_landscape_routes
from .routes.pages import _register_page_routes
from .routes.sources import _register_enrichment_route, _register_source_routes
from .routes.taxii import _register_taxii_routes
from .routes.techniques import _register_technique_routes
from .routes.threats import _register_threat_routes
from .routes.triage import _register_triage_routes
from .routes.workspace import _register_workspace_routes

log = logging.getLogger('insight.auth')

ROOT: Final = Path(__file__).resolve().parent.parent  # the insight package: templates/ and static/


def _init_state(app: FastAPI, settings: Settings, sessions: SessionFactory) -> None:
    app.state.settings = settings
    app.state.session_factory = sessions
    # Stored session hashes are keyed to this, so a new password or MFA setting ends every session (B4).
    app.state.session_binding = services.session_binding(
        settings.session_secret, settings.password, settings.mfa
    )
    if settings.dev_no_auth:
        # Keep open-access sessions separate. Turning the mode off must never turn an anonymous visitor's
        # existing cookie into a password-authenticated session, even with the same database and secret.
        app.state.session_binding = 'dev-no-auth:' + app.state.session_binding
    app.state.failures = []
    app.state.login_lock = asyncio.Lock()
    app.state.sync_lock = asyncio.Lock()
    app.state.is_authenticated = session_checker(app)
    # Two limiters so a flood of bad keys from many addresses can never evict a real caller's bucket.
    app.state.rate_limiter = RateLimiter()
    app.state.auth_failure_limiter = RateLimiter()


def _install_middleware(app: FastAPI, settings: Settings) -> None:
    """Added innermost first: requests pass ProxyHeaders (if configured), TrustedHost, Session, Boundary.

    ProxyHeaders must run first: the Boundary's Origin check needs the scheme the *browser* used (``https``
    at the proxy), and the invalid-key limiter needs the real client address. Headers are only believed from
    ``INSIGHT_TRUSTED_PROXIES``; from anyone else they are ignored, so clients cannot forge them.
    """
    app.add_middleware(BoundaryMiddleware, owner=app)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie='insight_session',
        max_age=SESSION_TTL_SECONDS,
        same_site='strict',
        https_only=settings.secure_cookies,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    if settings.trusted_proxies:
        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=list(settings.trusted_proxies))


def _log_deployment_warnings(settings: Settings, sessions: SessionFactory) -> None:
    """Start-up notes on settings that are valid but probably not what a public deployment wants."""
    if settings.dev_no_auth:
        log.warning(
            'INSIGHT_DEV_NO_AUTH=on: anyone who can reach this workspace can view and change its data'
        )
    if settings.trusted_proxies:
        log.info('Trusting X-Forwarded-For/-Proto from: %s', ', '.join(settings.trusted_proxies))
    if settings.require_hardened:
        log.info('INSIGHT_REQUIRE_HARDENED is on: secure cookies and MFA are required to start')
    elif settings.internet_facing() and (gaps := settings.hardening_gaps()):
        hosts = settings.public_hosts()
        log.warning(
            'This instance %s, so it may be reachable from the internet, but: %s. Fix these, then set '
            'INSIGHT_REQUIRE_HARDENED=on so Insight refuses to start without them (docs/RUNBOOK.md, '
            '"Reverse proxy").',
            f'answers to {", ".join(hosts)}' if hosts else 'trusts a reverse proxy',
            '; '.join(gaps),
        )
    with sessions() as db:
        above = services.count_documents_above(db, settings.max_tlp)
        paired = services.mfa_paired(db)
    if settings.mfa and not paired:
        log.error(MFA_UNPAIRED_LOG)
    elif settings.mfa:
        log.info('MFA is on: sign-in needs the password and an authenticator-app code')
    elif settings.trusted_proxies and not settings.dev_no_auth:
        log.info(
            'MFA is off (INSIGHT_MFA=off): sign-in needs the password only. '
            'To require an authenticator-app code: make mfa-enable'
        )
    if above:
        log.warning(
            '%d stored report(s) are labelled above INSIGHT_MAX_TLP=%s. They stay readable (also with the '
            'API key); new ones are refused. Review them (RUNBOOK section 9) before exposing this instance.',
            above,
            settings.max_tlp,
        )


def theme_context(settings: Settings) -> Callable[[Request], dict[str, Any]]:
    """Template context for the sign-in/sign-out pages: this device's theme (else the instance default) and
    text size."""

    def context(request: Request) -> dict[str, Any]:
        theme = theme_choice(request.cookies.get(THEME_COOKIE), settings.theme)
        text_size = text_size_choice(request.cookies.get(TEXT_SIZE_COOKIE))
        return {'theme': theme, 'text_size': text_size, 'page_background': PAGE_BACKGROUND}

    return context


def create_app(settings: Settings | None = None, *, with_ui: bool = True) -> FastAPI:
    """Build the FastAPI application (and, unless ``with_ui=False``, mount the NiceGUI workspace)."""
    settings = settings or Settings.from_env()
    engine, sessions = database(settings.database_url, session_secret=settings.session_secret)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
        stop = asyncio.Event()
        runner = None
        if settings.run_jobs:
            from ..jobs import JobLocks, run_forever  # Deferred: keeps `import insight.main` light.

            locks = JobLocks(sync=application.state.sync_lock)  # Manual syncs share the sync lane (L5).
            runner = asyncio.create_task(run_forever(sessions, locks, stop))
        try:
            yield
        finally:
            stop.set()
            if runner is not None:
                # A sync in progress gets a moment to finish; an unfinished job runs again at the next start.
                with contextlib.suppress(TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(runner, timeout=30)
            engine.dispose()  # Also on a failed shutdown, so pooled connections are always released.

    app = FastAPI(
        title='Insight',
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    _init_state(app, settings, sessions)
    _install_middleware(app, settings)
    _log_deployment_warnings(settings, sessions)
    templates = Jinja2Templates(directory=ROOT / 'templates', context_processors=[theme_context(settings)])
    require_auth = auth_dependency(
        app.state.is_authenticated,
        verify_key=api_key_verifier(sessions),
        limiter=app.state.rate_limiter,
        failure_limiter=app.state.auth_failure_limiter,
    )
    _register_page_routes(app, templates)
    _register_login(app, settings, templates)
    for register in (
        _register_workspace_routes,
        _register_landscape_routes,
        _register_cve_routes,
        _register_document_routes,
        _register_triage_routes,
        _register_export_routes,
        _register_import_routes,
        _register_entity_routes,
        _register_technique_routes,
        _register_threat_routes,
        _register_campaign_routes,
        _register_hunting_routes,
        _register_source_routes,
        _register_enrichment_route,
        _register_taxii_routes,
    ):
        register(app, sessions, require_auth)
    app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')

    if with_ui:
        from ..ui import register_ui  # Deferred: NiceGUI is heavy and holds process-global state.

        register_ui(app, sessions)
    return app
