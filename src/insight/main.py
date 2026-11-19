"""Application factory. One process, one local operator; no implicit network calls."""

from __future__ import annotations

import asyncio
import hmac
import logging
import secrets
import time
from collections.abc import AsyncGenerator, Callable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Final, Literal, TypeAlias

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from . import __version__, apikeys, services
from .appearance import PAGE_BACKGROUND, TEXT_SIZE_COOKIE, THEME_COOKIE, text_size_choice, theme_choice
from .config import Settings
from .connectors import SOURCES, ProviderError, SourceSyncError, enrich_cve, enrichment_request, sync_source
from .demo import seed
from .ioc_export import export_filename
from .models import Document, SessionFactory, database
from .ratelimit import AUTH_FAILURES, IOC_EXPORT, READ, WRITE, Policy, RateLimiter
from .schemas import (
    DocumentInput,
    DocumentReview,
    IocExportQuery,
    NoteInput,
    ObservationReview,
    validation_message,
)

ROOT: Final = Path(__file__).parent
MAX_BODY_BYTES: Final = 2_000_000
SESSION_TTL_SECONDS: Final = 8 * 60 * 60
LOGIN_WINDOW_SECONDS: Final = 60
#: Backstop only. The primary brute-force control is the per-failure delay with serialised checks, which
#: slows guessing without letting a third party lock the operator out (see docs/SECURITY.md).
LOGIN_MAX_FAILURES: Final = 30
ENRICHMENT_INTERVAL_SECONDS: Final = 6.5
SAFE_METHODS: Final = frozenset({'GET', 'HEAD', 'OPTIONS'})
#: Routes only a signed-in browser session may use (an API key has no CSRF token to fetch).
SESSION_ONLY_ROUTES: Final = frozenset({'/api/session'})
#: Routes a TLP-limited key may not use: the audit log and CVE enrichment reveal things about reports the
#: key cannot see (audit details, whether a CVE is mentioned anywhere).
UNLIMITED_READER_PREFIXES: Final = ('/api/audit', '/api/enrichment/')
HSTS: Final = (b'strict-transport-security', b'max-age=31536000')
#: Shown on the sign-in page while INSIGHT_MFA=on but no authenticator app is paired (sign-in is refused).
MFA_UNPAIRED: Final = (
    'Sign-in is locked: MFA is on (INSIGHT_MFA=on) but no authenticator app is paired yet. On the host, run '
    '"make mfa-enable" (Docker) or "insight mfa setup", or set INSIGHT_MFA=off.'
)
MFA_UNPAIRED_LOG: Final = (
    'INSIGHT_MFA=on but no authenticator app is paired: sign-in is refused until you run `make mfa-enable` '
    '(Docker) or `insight mfa setup`'
)
INVALID_KEY_HEADERS: Final = {'WWW-Authenticate': 'Bearer error="invalid_token"'}
#: How IOC export fields are named in the query string, for error messages that match what the caller sent.
IOC_EXPORT_PARAMETERS: Final = {
    'kinds': 'kind',
    'review_statuses': 'review_status',
    'document_ids': 'document_id',
    'include_evidence': 'evidence',
}

log = logging.getLogger('insight.auth')
SECURITY_HEADERS: Final = (
    (b'x-content-type-options', b'nosniff'),
    (b'x-frame-options', b'DENY'),
    # Not 'no-referrer': under that policy browsers send `Origin: null` on same-origin form POSTs, which the
    # Origin check below (correctly) rejects, so nobody could sign in from a real browser (0.1.0 bug, found
    # by the Playwright gate). 'same-origin' still never leaks URLs to other sites.
    (b'referrer-policy', b'same-origin'),
    (b'cache-control', b'no-store'),
)


def tokens_match(supplied: object, expected: object) -> bool:
    """Constant-time CSRF comparison that fails closed when either token is absent or empty."""
    if not isinstance(supplied, str) or not isinstance(expected, str) or not supplied or not expected:
        return False
    return hmac.compare_digest(supplied.encode(), expected.encode())


class BoundaryMiddleware:
    """Same-origin, socket-authentication and request-size boundary; adds defensive response headers."""

    def __init__(self, app: ASGIApp, owner: FastAPI) -> None:
        self.app, self.owner = app, owner

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] not in ('http', 'websocket'):
            await self.app(scope, receive, send)
            return
        # ASGI header values are raw bytes; HTTP permits obs-text (0x80-0xFF), so decode as latin-1.
        headers = {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in scope.get('headers', [])}
        origin = headers.get('origin')
        scheme = 'https' if scope.get('scheme') in ('https', 'wss') else 'http'
        expected = f'{scheme}://{headers.get("host", "")}'
        is_socket = scope['type'] == 'websocket' or '_nicegui_ws' in scope.get('path', '')
        if (origin and origin != expected) or (
            is_socket and not self.owner.state.is_authenticated(scope.get('session', {}))
        ):
            if scope['type'] == 'websocket':
                await send({'type': 'websocket.close', 'code': 1008})
                return
            await Response('Forbidden', status_code=403)(scope, receive, send)
            return
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        try:
            size = int(headers.get('content-length', '0'))
        except ValueError:
            size = MAX_BODY_BYTES + 1
        if size > MAX_BODY_BYTES:
            await Response('Request too large', status_code=413)(scope, receive, send)
            return
        if scope.get('method') in ('POST', 'PUT', 'PATCH'):
            chunks: list[Message] = []
            total = 0
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                total += len(message.get('body', b''))
                if total > MAX_BODY_BYTES:
                    await Response('Request too large', status_code=413)(scope, receive, send)
                    return
                chunks.append(message)
                if not message.get('more_body', False):
                    break
            original_receive = receive

            async def buffered_receive() -> Message:
                if chunks:
                    return chunks.pop(0)
                return await original_receive()

            receive = buffered_receive

        # Created here so the route's `request.state` and this middleware share one dict.
        state: dict[str, Any] = scope.setdefault('state', {})
        settings = getattr(self.owner.state, 'settings', None)
        secure = bool(getattr(settings, 'secure_cookies', False))

        async def secure_send(message: Message) -> None:
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                present = {name.lower() for name, _ in headers}
                # Rate-limit status for the caller (set by the auth dependency on every limited API request).
                for name, value in state.get('rate_limit_headers', {}).items():
                    if name.lower().encode() not in present:
                        headers.append((name.lower().encode('latin-1'), value.encode('latin-1')))
                # Never override a header the application set itself. NiceGUI serves its versioned assets
                # with `Cache-Control: immutable`; also appending `no-store` made browsers re-download ~1 MB
                # of JavaScript on every page load (0.1.0 bug). Sensitive pages and API responses set no
                # Cache-Control of their own, so they still get `no-store`.
                headers.extend((name, value) for name, value in SECURITY_HEADERS if name not in present)
                # HSTS only when the deployment says it is HTTPS-only; browsers ignore it over plain HTTP.
                if secure and HSTS[0] not in present:
                    headers.append(HSTS)
                message['headers'] = headers
            await send(message)

        await self.app(scope, receive, secure_send)


SessionCheck: TypeAlias = Callable[[Mapping[str, Any]], bool]
AuthDependency: TypeAlias = Callable[[Request], None]


@dataclass(frozen=True, slots=True)
class Caller:
    """Who made an API request: the signed-in operator, or the API key (named by its public key ID)."""

    kind: Literal['session', 'api_key']
    key_id: str | None = None
    access: apikeys.Access = 'read-write'
    #: Most restrictive TLP label this caller may read or write (``None``: no per-caller limit).
    max_tlp: str | None = None

    @property
    def limit_key(self) -> str:
        """Rate-limit bucket: the operator's browser and the API key never share a budget."""
        return 'session' if self.key_id is None else f'key:{self.key_id}'

    @property
    def actor(self) -> str:
        """How audit events name this caller."""
        return 'operator' if self.key_id is None else f'api-key:{self.key_id}'


SESSION_CALLER: Final = Caller('session')
#: ``verify(token) -> (caller or None, reason)``; ``reason`` is for logs only.
KeyVerifier: TypeAlias = Callable[[str], tuple[Caller | None, str]]


def session_checker(app: FastAPI) -> SessionCheck:
    """``check(session)``: True while the signed cookie names a live, unexpired server-side session."""

    def authenticated(session: Mapping[str, Any]) -> bool:
        sid = session.get('sid', '')
        expiry: float = app.state.active_sessions.get(sid, 0)
        return bool(session.get('authenticated') and expiry > time.time())

    return authenticated


def api_key_verifier(sessions: SessionFactory) -> KeyVerifier:
    """Check a presented key against the database (one indexed lookup; hash comparison in constant time)."""

    def verify(token: str) -> tuple[Caller | None, str]:
        with sessions.begin() as db:
            key, reason = services.verify_api_key(db, token)
            if key is None:
                return None, reason
            access: apikeys.Access = 'read-write' if key.access == 'read-write' else 'read'
            return Caller('api_key', key.key_id, access, key.max_tlp), reason

    return verify


def rate_limit_policy(method: str, path: str) -> Policy:
    """Which budget a request draws from. IOC exports are the expensive read and get their own."""
    if path == '/api/iocs/export':
        return IOC_EXPORT
    return READ if method in SAFE_METHODS else WRITE


def _client_address(request: Request) -> str:
    return request.client.host if request.client else 'unknown'


def auth_dependency(
    authenticated: SessionCheck,
    *,
    verify_key: KeyVerifier | None = None,
    limiter: RateLimiter | None = None,
    failure_limiter: RateLimiter | None = None,
) -> AuthDependency:
    """FastAPI dependency for every ``/api`` route.

    * ``Authorization: Bearer <key>``: the API key. No CSRF token is needed (a browser never attaches this
      header on its own, so a cross-site page cannot use it); a read-only key gets ``403`` for writes. Any
      cookie sent alongside is ignored.
    * Otherwise the browser session: ``401`` without one, ``403`` for a write without the matching CSRF
      header.

    Then the caller's rate limit is applied (``429`` with ``Retry-After`` when exhausted).
    """

    def key_caller(request: Request, token: str) -> Caller:
        caller, reason = verify_key(token) if verify_key is not None else (None, 'api keys disabled')
        if caller is None:
            client = _client_address(request)
            log.warning(
                'Rejected API key %s from %s: %s',
                apikeys.parse_key_id(token) or '(malformed)',
                client,
                reason,
            )
            if failure_limiter is not None:
                decision = failure_limiter.hit(client, AUTH_FAILURES)
                if not decision.allowed:
                    raise HTTPException(429, 'Too many invalid API key attempts', headers=decision.headers())
            # One answer for unknown, revoked, expired and malformed keys: nothing to learn by probing.
            raise HTTPException(401, 'Invalid or expired API key', headers=INVALID_KEY_HEADERS)
        return caller

    def require_auth(request: Request) -> None:
        method = request.method
        path: str = request.scope.get('path', '')
        token = apikeys.bearer_token(request.headers.get('authorization', ''))
        if token is not None:
            caller = key_caller(request, token)
            if path in SESSION_ONLY_ROUTES:
                raise HTTPException(403, 'Not available to API keys')
            if method not in SAFE_METHODS and caller.access != 'read-write':
                raise HTTPException(403, 'This API key is read-only')
            if caller.max_tlp is not None and path.startswith(UNLIMITED_READER_PREFIXES):
                raise HTTPException(403, 'Not available to TLP-limited API keys')
        else:
            if not authenticated(request.session):
                raise HTTPException(401, 'Sign in required')
            if method not in SAFE_METHODS and not tokens_match(
                request.headers.get('X-CSRF-Token'), request.session.get('csrf')
            ):
                raise HTTPException(403, 'Invalid CSRF token')
            caller = SESSION_CALLER
        request.state.caller = caller
        if limiter is not None:
            decision = limiter.hit(caller.limit_key, rate_limit_policy(method, path))
            request.state.rate_limit_headers = decision.headers()
            if not decision.allowed:
                log.warning('Rate limit %r exceeded by %s', decision.policy.name, caller.limit_key)
                raise HTTPException(
                    429,
                    f'Rate limit exceeded ({decision.policy.name}); retry in '
                    f'{decision.headers()["Retry-After"]} s',
                    headers=decision.headers(),
                )
        if caller.key_id is not None and method not in SAFE_METHODS:
            log.info('API key %s: %s %s', caller.key_id, method, path)

    return require_auth


def caller_of(request: Request) -> Caller:
    """The authenticated caller (set by the auth dependency; the operator's session if absent)."""
    caller = getattr(request.state, 'caller', None)
    return caller if isinstance(caller, Caller) else SESSION_CALLER


def reader_limit(request: Request) -> str | None:
    """The caller's TLP limit, passed to every service read so hidden reports never appear."""
    return caller_of(request).max_tlp


@contextmanager
def acting(sessions: SessionFactory, request: Request) -> Iterator[Session]:
    """A write transaction whose audit events name the caller (operator or API key)."""
    with sessions.begin() as db:
        yield services.set_actor(db, caller_of(request).actor)


def get_document_or_404(db: Session, doc_id: str, max_tlp: str | None = None) -> Document:
    """The report, or ``404`` if it does not exist or is above ``max_tlp`` (the two are indistinguishable)."""
    doc = services.get_document(db, doc_id, max_tlp=max_tlp)
    if doc is None:
        raise HTTPException(404, 'Report not found')
    return doc


def ioc_export_query(
    *,
    q: str,
    status: str,
    tlp: str,
    include_superseded: bool,
    kinds: list[str] | None,
    review_statuses: list[str] | None,
    max_tlp: str,
    defang: bool,
    document_ids: list[str] | None = None,
    include_evidence: bool = True,
) -> IocExportQuery:
    """Validate IOC export query parameters; empty strings and absent lists mean "use the default"."""
    params: dict[str, Any] = {
        'q': q,
        'status': status or None,
        'tlp': tlp or None,
        'include_superseded': include_superseded,
        'max_tlp': max_tlp or None,
        'defang': defang,
        'include_evidence': include_evidence,
    }
    if kinds:
        params['kinds'] = kinds
    if review_statuses:
        params['review_statuses'] = review_statuses
    if document_ids:
        params['document_ids'] = document_ids
    try:
        return IocExportQuery.model_validate(params)
    except ValidationError as exc:
        raise HTTPException(422, validation_message(exc, IOC_EXPORT_PARAMETERS)) from exc


def start_session(app: FastAPI, request: Request, now: float) -> None:
    """Replace the caller's session with a fresh server-side one (prevents session fixation)."""
    app.state.active_sessions.pop(request.session.get('sid'), None)
    app.state.active_sessions = {k: v for k, v in app.state.active_sessions.items() if v > now}
    sid = secrets.token_urlsafe(32)
    app.state.active_sessions[sid] = now + SESSION_TTL_SECONDS
    request.session.clear()
    request.session.update(authenticated=True, sid=sid, csrf=secrets.token_urlsafe(32))


def _init_state(app: FastAPI, settings: Settings, sessions: SessionFactory) -> None:
    app.state.settings = settings
    app.state.session_factory = sessions
    app.state.active_sessions = {}
    app.state.failures = []
    app.state.login_lock = asyncio.Lock()
    app.state.sync_lock = asyncio.Lock()
    app.state.last_lookup = 0.0
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
    if settings.trusted_proxies:
        log.info('Trusting X-Forwarded-For/-Proto from: %s', ', '.join(settings.trusted_proxies))
        if not settings.secure_cookies:
            log.warning('Behind an HTTPS proxy, set INSIGHT_SECURE_COOKIES=1 (cookies only over HTTPS)')
    with sessions() as db:
        above = services.count_documents_above(db, settings.max_tlp)
        paired = services.mfa_paired(db)
    if settings.mfa and not paired:
        log.error(MFA_UNPAIRED_LOG)
    elif settings.mfa:
        log.info('MFA is on: sign-in needs the password and an authenticator-app code')
    elif settings.trusted_proxies:
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


def _mfa_paired(sessions: SessionFactory) -> bool:
    with sessions() as db:
        return services.mfa_paired(db)


def _check_code(sessions: SessionFactory, code: str) -> bool:
    """One transaction, so an accepted code is marked used atomically (False if no app is paired)."""
    with sessions.begin() as db:
        services.set_actor(db, 'operator')
        return services.verify_mfa_code(db, code)


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
        # Checks run one at a time and each failure waits before answering: online guessing is slowed to
        # roughly one attempt per `failed_login_delay`, while the operator can always still sign in.
        async with app.state.login_lock:
            current = time.time()
            app.state.failures[:] = [t for t in app.state.failures if current - t < LOGIN_WINDOW_SECONDS]
            if len(app.state.failures) >= LOGIN_MAX_FAILURES:
                log.warning('Sign-in refused: %d failures in the last minute', len(app.state.failures))
                raise HTTPException(429, 'Too many login attempts; wait one minute')
            password_ok = hmac.compare_digest(password.encode(), settings.password.encode())
            # The code is only checked (and consumed) once the password is right, so wrong guesses never burn
            # a valid code. One answer for either mistake: nothing tells a guesser which factor was wrong.
            code_ok = not mfa
            if password_ok and mfa:
                code_ok = await asyncio.to_thread(_check_code, sessions, code)
            if not (password_ok and code_ok):
                app.state.failures.append(current)
                reason = 'password' if not password_ok else 'authentication code'
                failures = len(app.state.failures)
                log.warning('Failed sign-in attempt: wrong %s (%d in the last minute)', reason, failures)
                await asyncio.sleep(settings.failed_login_delay)
                error = 'Incorrect password or authentication code.' if mfa else 'Incorrect password.'
                return templates.TemplateResponse(
                    request=request,
                    name='login.html',
                    status_code=401,
                    context={'csrf_token': csrf, 'error': error, 'mfa': mfa},
                )
        start_session(app, request, current)
        log.info('Operator signed in%s', ' (password and authentication code)' if mfa else '')
        return RedirectResponse('/', status_code=303)


def _register_document_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Search, read and ingest reports."""

    @app.get('/api/documents', dependencies=[Depends(require_auth)])
    def documents(
        request: Request,
        q: str = '',
        status: str = '',
        tlp: str = '',
        include_superseded: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = services.DocumentQuery(
            q=q,
            status=status or None,
            tlp=tlp or None,
            include_superseded=include_superseded,
            offset=offset,
            limit=limit,
            max_tlp=reader_limit(request),
        )
        with sessions() as db:
            return services.summaries(db, services.search_documents(db, query))

    @app.get('/api/documents/{doc_id}', dependencies=[Depends(require_auth)])
    def document(request: Request, doc_id: str) -> dict[str, Any]:
        limit = reader_limit(request)
        with sessions() as db:
            return services.detail(db, get_document_or_404(db, doc_id, limit), max_tlp=limit)

    @app.post('/api/documents', dependencies=[Depends(require_auth)])
    def create_document(request: Request, item: DocumentInput) -> dict[str, Any]:
        # The stricter of the instance limit and the key's own: a key cannot store what it may not read.
        limit = services.stricter_limit(app.state.settings.max_tlp, reader_limit(request))
        try:
            with acting(sessions, request) as db:
                doc, created = services.ingest(db, item, max_tlp=limit)
                result = services.detail(db, doc, max_tlp=reader_limit(request))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(409, 'Concurrent import; retry once') from exc
        result['created'] = created
        # Set when a TLP marking in the text was more restrictive than the submitted label (never lowered).
        result['tlp_raised_from'] = item.tlp if created and result['tlp'] != item.tlp else None
        return result


def _register_triage_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Analyst actions: report triage status, observation review and notes (all audited)."""

    @app.post('/api/documents/{doc_id}/review', dependencies=[Depends(require_auth)])
    def review_document(request: Request, doc_id: str, payload: DocumentReview) -> dict[str, str]:
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            if services.set_document_status(db, doc_id, payload.status, max_tlp=limit) is None:
                raise HTTPException(404, 'Report not found')
        return {'status': payload.status}

    @app.post('/api/observations/{obs_id}/review', dependencies=[Depends(require_auth)])
    def review_observation(request: Request, obs_id: str, payload: ObservationReview) -> dict[str, str]:
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            if services.set_observation_status(db, obs_id, payload.status, max_tlp=limit) is None:
                raise HTTPException(404, 'Observation not found')
        return {'status': payload.status}

    @app.post('/api/documents/{doc_id}/notes', dependencies=[Depends(require_auth)])
    def add_note(request: Request, doc_id: str, payload: NoteInput) -> dict[str, str]:
        with acting(sessions, request) as db:
            note = services.add_note(db, doc_id, payload.body, max_tlp=reader_limit(request))
            if note is None:
                raise HTTPException(404, 'Report not found')
            return {'id': note.id}


def _register_export_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Audited JSON downloads: one report, or indicators across reports."""

    @app.get('/api/documents/{doc_id}/export', dependencies=[Depends(require_auth)])
    def export(request: Request, doc_id: str) -> JSONResponse:
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            doc = get_document_or_404(db, doc_id, limit)
            result = services.detail(db, doc, max_tlp=limit)
            result['format'] = 'insight-report-v1'
            result['handling_notice'] = (
                'Local backup/export only. Preserve TLP and publisher restrictions. Not STIX.'
            )
            services.audit(db, 'document.export', doc.id, doc.tlp)
        return JSONResponse(
            result, headers={'Content-Disposition': f'attachment; filename="insight-report-{doc.id}.json"'}
        )

    @app.get('/api/iocs/export', dependencies=[Depends(require_auth)])
    def export_iocs(
        request: Request,
        q: str = '',
        status: str = '',
        tlp: str = '',
        include_superseded: bool = False,
        kind: Annotated[list[str] | None, Query()] = None,
        review_status: Annotated[list[str] | None, Query()] = None,
        max_tlp: str = '',
        defang: bool = False,
        document_id: Annotated[list[str] | None, Query()] = None,
        evidence: bool = True,
    ) -> JSONResponse:
        """Cross-report IOC export (``insight-ioc-v1``). List parameters may be repeated."""
        query = ioc_export_query(
            q=q,
            status=status,
            tlp=tlp,
            include_superseded=include_superseded,
            kinds=kind,
            review_statuses=review_status,
            max_tlp=max_tlp,
            defang=defang,
            document_ids=document_id,
            include_evidence=evidence,
        )
        # A TLP-limited key exports at most its own limit, whatever `max_tlp` it asked for.
        limit = services.stricter_limit(query.max_tlp, reader_limit(request))
        if limit != query.max_tlp:
            query = query.model_copy(update={'max_tlp': limit})
        try:
            with acting(sessions, request) as db:
                result = services.export_iocs(db, query)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        filename = export_filename(result['generated_at'])
        return JSONResponse(result, headers={'Content-Disposition': f'attachment; filename="{filename}"'})


def _register_entity_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Canonical indicators and their cross-report pivots."""

    @app.get('/api/entities', dependencies=[Depends(require_auth)])
    def entities(request: Request, q: str = '') -> list[dict[str, Any]]:
        with sessions() as db:
            return [
                {'id': e.id, 'kind': e.kind, 'value': e.value, 'document_count': count}
                for e, count in services.list_entities(db, q, max_tlp=reader_limit(request))
            ]

    @app.get('/api/entities/{entity_id}', dependencies=[Depends(require_auth)])
    def entity(request: Request, entity_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        max_tlp = reader_limit(request)
        with sessions() as db:
            e = services.get_entity(db, entity_id)
            # An entity mentioned only in reports the caller cannot see does not exist for that caller.
            count = 0 if e is None else services.count_entity_documents(db, e.id, max_tlp=max_tlp)
            if e is None or (max_tlp is not None and count == 0):
                raise HTTPException(404, 'Entity not found')
            docs = services.entity_documents(db, e.id, offset=offset, limit=limit, max_tlp=max_tlp)
            return {
                'id': e.id,
                'kind': e.kind,
                'value': e.value,
                'document_count': count,
                'offset': max(0, offset),
                'documents': services.summaries(db, docs),
            }


def _register_source_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Curated connectors. Sync is the only route besides enrichment that makes outbound requests."""

    @app.get('/api/sources', dependencies=[Depends(require_auth)])
    def sources() -> list[dict[str, Any]]:
        with sessions() as db:
            return [
                {
                    'key': s.key,
                    'name': s.name,
                    'url': s.url,
                    'note': s.note,
                    'runs': [
                        {'status': r.status, 'message': r.message, 'created_at': r.created_at}
                        for r in services.recent_source_runs(db, s.key, limit=5)
                    ],
                }
                for s in SOURCES.values()
            ]

    @app.post('/api/sources/{key}/sync', dependencies=[Depends(require_auth)])
    async def sync(key: str) -> dict[str, str]:
        if key not in SOURCES:
            raise HTTPException(404, 'Unknown source')
        if app.state.sync_lock.locked():
            raise HTTPException(409, 'Another source job is running')
        async with app.state.sync_lock:
            try:
                return {'message': await sync_source(sessions, key)}
            except SourceSyncError as exc:
                raise HTTPException(502, str(exc)) from exc


def _register_enrichment_route(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Explicit, globally throttled CVE lookups (sends only the CVE identifier to the provider)."""

    @app.post('/api/enrichment/{provider}/{cve}', dependencies=[Depends(require_auth)])
    async def enrich(provider: str, cve: str) -> dict[str, Any]:
        try:
            enrichment_request(cve, provider)  # Reject bad input before it consumes the throttle window.
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if time.monotonic() - app.state.last_lookup < ENRICHMENT_INTERVAL_SECONDS:
            raise HTTPException(429, 'Wait at least 6.5 seconds between enrichment requests')
        app.state.last_lookup = time.monotonic()
        try:
            return await enrich_cve(sessions, cve, provider)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(502, 'Provider request failed; retry later') from exc


def _register_workspace_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Session token, counters, demo data, audit log and watch terms."""

    @app.get('/api/session', dependencies=[Depends(require_auth)])
    def session_info(request: Request) -> dict[str, str]:
        return {'csrf_token': request.session['csrf']}

    @app.get('/api/stats', dependencies=[Depends(require_auth)])
    def stats(request: Request) -> dict[str, int]:
        with sessions() as db:
            return services.stats(db, max_tlp=reader_limit(request))

    @app.post('/api/demo', dependencies=[Depends(require_auth)])
    def demo(request: Request) -> dict[str, int]:
        with acting(sessions, request) as db:
            return {'created': seed(db)}

    @app.get('/api/audit', dependencies=[Depends(require_auth)])
    def events() -> list[dict[str, str]]:
        with sessions() as db:
            return [
                {
                    'action': e.action,
                    'object_id': e.object_id,
                    'detail': e.detail,
                    'actor': e.actor,
                    'created_at': e.created_at,
                }
                for e in services.audit_events(db)
            ]

    @app.get('/api/watch-terms', dependencies=[Depends(require_auth)])
    def watch_terms() -> list[dict[str, str]]:
        with sessions() as db:
            return [{'id': w.id, 'term': w.term} for w in services.list_watch_terms(db)]


def create_app(settings: Settings | None = None, *, with_ui: bool = True) -> FastAPI:
    """Build the FastAPI application (and, unless ``with_ui=False``, mount the NiceGUI workspace)."""
    settings = settings or Settings.from_env()
    engine, sessions = database(settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        try:
            yield
        finally:
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
        _register_document_routes,
        _register_triage_routes,
        _register_export_routes,
        _register_entity_routes,
        _register_source_routes,
        _register_enrichment_route,
    ):
        register(app, sessions, require_auth)
    app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')

    if with_ui:
        from .ui import register_ui  # Deferred: NiceGUI is heavy and holds process-global state.

        register_ui(app, sessions)
    return app
