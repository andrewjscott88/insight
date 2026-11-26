"""Sign-in through an OpenID Connect provider (ADR 0046): discovery, the authorisation code flow with PKCE,
and the provider's key set.

Every request goes through ``connectors.download`` with its HTTPS egress checks, allowlisted to one host at a
time: the issuer's for discovery, then the hosts the discovery document names for the token endpoint and the
key set. The browser is the only party that visits the authorisation endpoint. Failures raise
:class:`SignInFailed` with a message that holds no secret, token or provider text.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import quote_plus, urlencode, urlsplit

from . import connectors
from .id_tokens import Identity, InvalidToken, verify_id_token
from .oidc_settings import OidcSettings

log = logging.getLogger('insight.auth')

DISCOVERY_PATH: Final = '/.well-known/openid-configuration'
MAX_DOCUMENT_BYTES: Final = 256 * 1024
#: How long discovery and the key set are kept before they are fetched again.
CACHE_SECONDS: Final = 3600.0
#: An unknown key ID fetches the key set again at most this often (the provider rotated its keys).
KEY_REFRESH_SECONDS: Final = 300.0
#: After discovery or the key set could not be fetched, sign-ins fail at once for this long instead of
#: sending the provider a request for every visitor who tries (only the token exchange carries their input).
RETRY_SECONDS: Final = 10.0
#: How long a sign-in that went to the provider may take to come back.
FLOW_SECONDS: Final = 600.0
MAX_CODE_LENGTH: Final = 4096


class SignInFailed(Exception):
    """The sign-in did not work. The message is safe to log; people see a generic one."""


@dataclass(frozen=True, slots=True)
class Provider:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    #: ``client_secret_basic`` (preferred) or ``client_secret_post``.
    client_auth: str


@dataclass(frozen=True, slots=True)
class Flow:
    """One sign-in in progress, kept in the signed session cookie until it comes back (once)."""

    state: str
    nonce: str
    verifier: str
    started_at: float

    def as_cookie(self) -> dict[str, Any]:
        return {'state': self.state, 'nonce': self.nonce, 'verifier': self.verifier, 'at': self.started_at}

    @classmethod
    def from_cookie(cls, value: object) -> Flow | None:
        if not isinstance(value, dict):
            return None
        state, nonce, verifier, at = (value.get(k) for k in ('state', 'nonce', 'verifier', 'at'))
        if not (isinstance(state, str) and isinstance(nonce, str) and isinstance(verifier, str)):
            return None
        if isinstance(at, bool) or not isinstance(at, int | float):
            return None
        return cls(state, nonce, verifier, float(at))

    @classmethod
    def new(cls, now: float) -> Flow:
        # A 64-byte verifier is 86 characters, inside RFC 7636's 43 to 128.
        return cls(secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64), now)

    @property
    def challenge(self) -> str:
        """PKCE S256: the verifier's SHA-256, base64url without padding."""
        digest = hashlib.sha256(self.verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    def expired(self, now: float) -> bool:
        return not 0 <= now - self.started_at <= FLOW_SECONDS


def _endpoint(value: object, name: str) -> str:
    """An ``https://`` endpoint on port 443 with no user name, password or fragment."""
    if not isinstance(value, str):
        raise SignInFailed(f'The discovery document has no {name}')
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        port = -1
    if (
        parts.scheme != 'https'
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or port not in (None, 443)
    ):
        raise SignInFailed(f'The discovery document names an unsafe {name}')
    return value


def _provider(document: dict[str, Any], settings: OidcSettings) -> Provider:
    if document.get('issuer') != settings.issuer:
        raise SignInFailed('The discovery document names another issuer')
    for field, wanted in (('response_types_supported', 'code'), ('code_challenge_methods_supported', 'S256')):
        offered = document.get(field)
        if offered is not None and (not isinstance(offered, list) or wanted not in offered):
            raise SignInFailed(f'The provider does not offer {wanted} ({field})')
    methods = document.get('token_endpoint_auth_methods_supported')
    if isinstance(methods, list) and 'client_secret_basic' not in methods and 'client_secret_post' in methods:
        client_auth = 'client_secret_post'
    else:
        client_auth = 'client_secret_basic'
    return Provider(
        authorization_endpoint=_endpoint(document.get('authorization_endpoint'), 'authorization endpoint'),
        token_endpoint=_endpoint(document.get('token_endpoint'), 'token endpoint'),
        jwks_uri=_endpoint(document.get('jwks_uri'), 'key set'),
        client_auth=client_auth,
    )


class OidcClient:
    """Discovery, the key set and the code exchange for one provider; caches what it fetched."""

    def __init__(self, settings: OidcSettings) -> None:
        self.settings = settings
        self._tls = settings.tls_context()
        self._provider: tuple[float, Provider] | None = None
        self._keys: tuple[float, list[object]] | None = None
        #: When discovery or the key set last failed.
        self._failed_at: float | None = None
        self._lock = asyncio.Lock()

    async def _fetch_setup(self, url: str, now: float) -> Any:
        """Discovery or the key set (call with the lock); a failure pauses them for ``RETRY_SECONDS``."""
        if self._failed_at is not None and 0 <= now - self._failed_at < RETRY_SECONDS:
            raise SignInFailed('The identity provider failed moments ago; not asked again yet')
        try:
            return await self._get_json(url)
        except SignInFailed:
            self._failed_at = now
            raise

    async def _get_json(
        self, url: str, *, body: bytes | None = None, headers: dict[str, str] | None = None
    ) -> Any:
        host = urlsplit(url).hostname or ''
        try:
            raw = await connectors.download(
                url,
                body=body,
                headers={'Accept': 'application/json', **(headers or {})},
                max_bytes=MAX_DOCUMENT_BYTES,
                allowed_hosts=frozenset({host}),
                allow_private=self.settings.private_network,
                tls=self._tls,
            )
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise SignInFailed(f'{host} did not answer with JSON') from None
        except Exception as exc:  # Network, TLS, status, size and egress refusals: none may leak details.
            log.warning('Identity provider request to %s failed: %s', host, type(exc).__name__)
            raise SignInFailed(f'{host} could not be reached') from None

    async def provider(self, now: float) -> Provider:
        async with self._lock:
            if self._provider is None or now - self._provider[0] > CACHE_SECONDS:
                document = await self._fetch_setup(self.settings.issuer.rstrip('/') + DISCOVERY_PATH, now)
                try:
                    if not isinstance(document, dict):
                        raise SignInFailed('The discovery document is not a JSON object')
                    self._provider = (now, _provider(document, self.settings))
                except SignInFailed:
                    self._failed_at = now
                    raise
            return self._provider[1]

    async def _key_set(self, now: float, *, refresh: bool) -> list[object]:
        provider = await self.provider(now)
        async with self._lock:
            cached = self._keys
            stale = cached is None or now - cached[0] > CACHE_SECONDS
            if stale or (refresh and cached is not None and now - cached[0] > KEY_REFRESH_SECONDS):
                document = await self._fetch_setup(provider.jwks_uri, now)
                keys = document.get('keys') if isinstance(document, dict) else None
                if not isinstance(keys, list):
                    self._failed_at = now
                    raise SignInFailed('The key set has no keys')
                self._keys = cached = (now, keys)
            if cached is None:
                raise SignInFailed('The key set has no keys')
            return cached[1]

    async def authorization_url(self, flow: Flow, now: float) -> str:
        """Where to send the browser to sign in."""
        provider = await self.provider(now)
        query = urlencode(
            {
                'response_type': 'code',
                'client_id': self.settings.client_id,
                'redirect_uri': self.settings.redirect_uri,
                'scope': self.settings.scopes,
                'state': flow.state,
                'nonce': flow.nonce,
                'code_challenge': flow.challenge,
                'code_challenge_method': 'S256',
            }
        )
        separator = '&' if urlsplit(provider.authorization_endpoint).query else '?'
        return f'{provider.authorization_endpoint}{separator}{query}'

    async def finish(self, code: str, flow: Flow, now: float) -> Identity:
        """Exchange the code (with the PKCE verifier) and check the ID token; raises :class:`SignInFailed`."""
        if not code or len(code) > MAX_CODE_LENGTH:
            raise SignInFailed('The provider sent no usable code')
        provider = await self.provider(now)
        form = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.settings.redirect_uri,
            'code_verifier': flow.verifier,
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if provider.client_auth == 'client_secret_post':
            form |= {'client_id': self.settings.client_id, 'client_secret': self.settings.client_secret}
        else:  # RFC 6749 2.3.1: both parts form-encoded before base64.
            client_id, secret = (
                quote_plus(v, safe='') for v in (self.settings.client_id, self.settings.client_secret)
            )
            pair = f'{client_id}:{secret}'
            headers['Authorization'] = 'Basic ' + base64.b64encode(pair.encode()).decode('ascii')
        answer = await self._get_json(provider.token_endpoint, body=urlencode(form).encode(), headers=headers)
        token = answer.get('id_token') if isinstance(answer, dict) else None
        if not isinstance(token, str):
            raise SignInFailed('The provider sent no ID token')
        for refresh in (False, True):  # Once more with a fresh key set, in case the provider rotated keys.
            keys = await self._key_set(now, refresh=refresh)
            try:
                return verify_id_token(
                    token,
                    keys=keys,
                    issuer=self.settings.issuer,
                    client_id=self.settings.client_id,
                    nonce=flow.nonce,
                    now=now,
                    groups_claim=self.settings.groups_claim,
                )
            except InvalidToken as exc:
                if refresh or str(exc) != 'no single matching signing key':
                    raise SignInFailed(f'The ID token was refused: {exc}') from None
        raise SignInFailed('The ID token was refused')  # pragma: no cover - the loop always returns or raises
