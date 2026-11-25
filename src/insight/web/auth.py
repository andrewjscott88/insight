"""Callers, sessions, API keys and the auth dependency (the sign-in form is in ``routes/login.py``)."""

from __future__ import annotations

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
from sqlalchemy.orm import Session

from .. import apikeys, services
from ..models import SessionFactory
from ..permissions import NOT_PERMITTED, OPERATOR_ROLE, Permission, Role, is_role, key_role, role_allows
from ..ratelimit import AUTH_FAILURES, IOC_EXPORT, MCP, READ, TAXII, WRITE, Policy, RateLimiter
from .boundary import (
    SAFE_METHODS,
    SESSION_ONLY_ROUTES,
    SESSION_ONLY_WRITE_PREFIXES,
    UNLIMITED_READER_PREFIXES,
    tokens_match,
)
from .route_permissions import route_permission

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
    """Who made a request: the signed-in operator, a signed-in person, or the API key (named by its public
    key ID)."""

    kind: Literal['session', 'api_key']
    key_id: str | None = None
    access: apikeys.Access = 'read-write'
    #: Most restrictive TLP label this caller may read or write (``None``: no per-caller limit).
    max_tlp: str | None = None
    #: The signed-in person (``users.id``); ``None`` for the operator and for API keys.
    user_id: str | None = None
    #: What the caller may do (ADR 0046). Only a person's role is taken as given (``None``: nothing); a key's
    #: follows from its access level and the operator's is admin, whatever is passed.
    role: Role | None = None

    def __post_init__(self) -> None:
        if self.kind == 'api_key':
            object.__setattr__(self, 'role', key_role(self.access))  # never an admin
        elif self.user_id is None:
            object.__setattr__(self, 'role', OPERATOR_ROLE)

    @property
    def limit_key(self) -> str:
        """Rate-limit bucket: each person, the operator's browser and the API key have their own budget."""
        if self.key_id is not None:
            return f'key:{self.key_id}'
        return 'session' if self.user_id is None else f'user:{self.user_id}'

    @property
    def actor(self) -> str:
        """How audit events name this caller."""
        if self.key_id is not None:
            return f'api-key:{self.key_id}'
        return 'operator' if self.user_id is None else f'user:{self.user_id}'

    def may(self, permission: Permission) -> bool:
        """Whether this caller's role allows ``permission``."""
        return role_allows(self.role, permission)


SESSION_CALLER: Final = Caller('session')

#: ``lookup(session) -> caller``: who a signed session cookie belongs to, or ``None`` (not signed in).
SessionLookup: TypeAlias = Callable[[Mapping[str, Any]], Caller | None]

#: ``verify(token) -> (caller or None, reason)``; ``reason`` is for logs only.
KeyVerifier: TypeAlias = Callable[[str], tuple[Caller | None, str]]


def _moment(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, UTC)


def session_lookup(app: FastAPI) -> SessionLookup:
    """``lookup(session)``: the caller while the signed cookie names a stored, unexpired session (review B4)
    of the operator or of a person with a role (ADR 0046); ``None`` otherwise.

    Sessions live in the database, so a restart keeps people signed in; ending one there ends it in every tab
    at once, and a role change applies to the next request. The lookup is one or two primary-key reads. A
    person still waiting for approval, or disabled, is not signed in here.
    """

    def caller(session: Mapping[str, Any]) -> Caller | None:
        sid = session.get('sid')
        if not (session.get('authenticated') and isinstance(sid, str) and sid):
            return None
        with app.state.session_factory() as db:
            principal = services.session_principal(
                db, sid, binding=app.state.session_binding, at=_moment(time.time())
            )
        if principal is None or not is_role(principal.role):
            return None
        if principal.user_id is None:
            return SESSION_CALLER
        return Caller('session', user_id=principal.user_id, role=principal.role)

    return caller


def session_checker(app: FastAPI) -> SessionCheck:
    """``check(session)``: True while the signed cookie names someone signed in with a role."""
    lookup = session_lookup(app)
    return lambda session: lookup(session) is not None


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
    session_caller: SessionLookup,
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

    Then the route's permission is looked up by method and path template (``route_permissions``): a route
    with no entry is refused, and so is a caller whose role does not allow it (``403``, ADR 0046). Last, the
    caller's rate limit is applied (``429`` with ``Retry-After`` when exhausted).
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
            signed_in = session_caller(request.session)
            if signed_in is None:
                raise HTTPException(401, 'Sign in required')
            if method not in SAFE_METHODS and not tokens_match(
                request.headers.get('X-CSRF-Token'), request.session.get('csrf')
            ):
                raise HTTPException(403, 'Invalid CSRF token')
            caller = signed_in
        if not permitted(request, caller):
            raise HTTPException(403, NOT_PERMITTED.rstrip('.'))
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


def permitted(request: Request, caller: Caller) -> bool:
    """Whether ``caller`` may use the matched route. Refuses by default: an unlisted route, or a request that
    matched no route, is never permitted."""
    route = request.scope.get('route')
    template = getattr(route, 'path', None)
    permission = route_permission(request.method, template) if isinstance(template, str) else None
    if permission is None:
        log.error('Refused %s %s: the route has no permission entry', request.method, template or '(none)')
        return False
    if caller.may(permission):
        return True
    # A read-feedback key acts as a viewer but may send these two kinds of feedback (TIP 4.1, 4.2).
    return caller.access == 'read-feedback' and (request.method, template) in apikeys.FEEDBACK_INTAKE


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
    """Sign this browser out, or every browser of the same person (audited); returns how many sessions
    ended everywhere."""
    if not (isinstance(sid, str) and sid):
        return 0
    with app.state.session_factory.begin() as db:
        return services.sign_out(db, sid, binding=app.state.session_binding, everywhere=everywhere)


def set_session_cookie(request: Request, sid: str) -> None:
    request.session.clear()
    request.session.update(authenticated=True, sid=sid, csrf=secrets.token_urlsafe(32))


def start_session(app: FastAPI, request: Request, now: float) -> None:
    """Replace the caller's session with a fresh stored one (prevents session fixation)."""
    set_session_cookie(request, new_session_id(app, request.session.get('sid'), now))
