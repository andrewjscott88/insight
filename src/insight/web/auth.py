"""Callers, sessions, API keys and sign-in."""

from __future__ import annotations

import asyncio
import hmac
import logging
import secrets
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, TypeAlias, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.responses import Response

from .. import apikeys, services
from ..config import Settings
from ..models import SessionFactory
from ..ratelimit import AUTH_FAILURES, IOC_EXPORT, MCP, READ, TAXII, WRITE, Policy, RateLimiter
from .boundary import (
    SAFE_METHODS,
    SESSION_ONLY_ROUTES,
    SESSION_ONLY_WRITE_PREFIXES,
    UNLIMITED_READER_PREFIXES,
    tokens_match,
)

log = logging.getLogger('insight.auth')

SESSION_TTL_SECONDS: Final = int(services.SESSION_TTL.total_seconds())

LOGIN_WINDOW_SECONDS: Final = 60

#: Backstop: once this many sign-ins failed in the last minute, wrong passwords are refused with 429 (after
#: the usual delay). The right password still signs in, so nobody can lock the operator out (ADR 0002).
LOGIN_MAX_FAILURES: Final = 30

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


def _moment(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, UTC)


def session_checker(app: FastAPI) -> SessionCheck:
    """``check(session)``: True while the signed cookie names a stored, unexpired session (review B4).

    Sessions live in the database, so a restart keeps the operator signed in; ending one there ends it in
    every tab at once. The check is one primary-key lookup.
    """

    def authenticated(session: Mapping[str, Any]) -> bool:
        sid = session.get('sid')
        if not (session.get('authenticated') and isinstance(sid, str) and sid):
            return False
        with app.state.session_factory() as db:
            return services.operator_session_valid(
                db, sid, binding=app.state.session_binding, at=_moment(time.time())
            )

    return authenticated


def api_key_verifier(sessions: SessionFactory) -> KeyVerifier:
    """Check a presented key against the database (one indexed lookup; hash comparison in constant time)."""

    def verify(token: str) -> tuple[Caller | None, str]:
        with sessions.begin() as db:
            key, reason = services.verify_api_key(db, token)
            if key is None:
                return None, reason
            # Anything unexpected in the column reads as the narrowest access.
            known = key.access in apikeys.ACCESS_LEVELS
            access = cast(apikeys.Access, key.access) if known else 'read'
            return Caller('api_key', key.key_id, access, key.max_tlp), reason

    return verify


def rate_limit_policy(method: str, path: str) -> Policy:
    """Which budget a request draws from. IOC exports are the expensive read and get their own."""
    if (method, path) == ('POST', '/mcp'):
        return MCP
    if path in ('/api/iocs/export', '/api/iocs/stix', '/api/iocs/blocklist'):
        return IOC_EXPORT
    if path.startswith('/taxii2/insight/collections/') and (
        '/objects/' in path or path.endswith('/manifest/')
    ):
        return TAXII
    return READ if method in SAFE_METHODS else WRITE


#: The width both values are padded to before comparing; a longer stored secret sets its own width.
SECRET_WIDTH: Final = 256


def same_secret(supplied: str, expected: str) -> bool:
    """Constant-time comparison that does not reveal the expected secret's length (code review N4).

    ``hmac.compare_digest`` on the raw values returns early when the lengths differ, so response times could
    tell a guesser how long the password is. Both values are padded to one width that depends only on the
    stored secret (``SECRET_WIDTH``, or its own length if longer; a longer guess is cut to that width), and
    the lengths are compared separately without branching, so the comparison always takes the same path.
    No hash is used: a fast hash of a password is what code scanners rightly flag, and nothing here is
    stored.
    """
    guess = supplied.encode()
    secret = expected.encode()
    width = max(SECRET_WIDTH, len(secret))
    padded_guess = guess[:width].ljust(width, b'\0')
    padded_secret = secret.ljust(width, b'\0')
    same_length = len(guess) == len(secret)
    return hmac.compare_digest(padded_guess, padded_secret) & same_length


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
        # This exact transport POST exposes only fixed read tools. No other POST gains read-key access.
        mcp_read = (method, path) == ('POST', '/mcp')
        token = apikeys.bearer_token(request.headers.get('authorization', ''))
        if token is not None:
            caller = key_caller(request, token)
            if path in SESSION_ONLY_ROUTES:
                raise HTTPException(403, 'Not available to API keys')
            feedback = caller.access == 'read-feedback' and (method, path) in apikeys.FEEDBACK_INTAKE
            if method not in SAFE_METHODS and caller.access != 'read-write' and not (feedback or mcp_read):
                raise HTTPException(403, 'This API key is read-only')
            if method not in SAFE_METHODS and path.startswith(SESSION_ONLY_WRITE_PREFIXES):
                raise HTTPException(403, 'Change these settings from a signed-in workspace session')
            if caller.max_tlp is not None and path.startswith(UNLIMITED_READER_PREFIXES):
                raise HTTPException(403, 'Not available to TLP-limited API keys')
        else:
            if mcp_read:
                raise HTTPException(401, 'API key required', headers=INVALID_KEY_HEADERS)
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


def new_session_id(app: FastAPI, replaces: Any, now: float) -> str:
    """Store a fresh session, ending the one it replaces, and return its ID (blocking: database)."""
    with app.state.session_factory.begin() as db:
        return services.start_operator_session(
            db,
            binding=app.state.session_binding,
            at=_moment(now),
            replaces=replaces if isinstance(replaces, str) else None,
        )


def end_sessions(app: FastAPI, sid: Any, *, everywhere: bool) -> int:
    """Sign this browser out, or every browser (audited); returns how many sessions ended everywhere."""
    with app.state.session_factory.begin() as db:
        services.set_actor(db, 'operator')
        if everywhere:
            return services.end_all_operator_sessions(db)
        if isinstance(sid, str) and sid:
            services.end_operator_session(db, sid, binding=app.state.session_binding)
        return 0


def set_session_cookie(request: Request, sid: str) -> None:
    request.session.clear()
    request.session.update(authenticated=True, sid=sid, csrf=secrets.token_urlsafe(32))


def start_session(app: FastAPI, request: Request, now: float) -> None:
    """Replace the caller's session with a fresh stored one (prevents session fixation)."""
    set_session_cookie(request, new_session_id(app, request.session.get('sid'), now))


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
