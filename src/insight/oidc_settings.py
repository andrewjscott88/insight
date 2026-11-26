"""Sign-in through an OpenID Connect provider: the host's settings (ADR 0046, TIP 3.4b).

Nothing here talks to the network. ``insight.oidc`` runs the sign-in with these settings.
"""

from __future__ import annotations

import os
import re
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final, Self
from urllib.parse import urlsplit

from .permissions import Role

DEFAULT_SCOPES: Final = 'openid email profile'
DEFAULT_GROUPS_CLAIM: Final = 'groups'
#: Where the provider sends the browser back to, under ``INSIGHT_PUBLIC_URL``.
CALLBACK_PATH: Final = '/login/sso/callback'
_CLAIM_NAME: Final = re.compile(r'[A-Za-z0-9_.:/-]{1,100}')
_SWITCHES: Final = {'': False, 'off': False, 'on': True}


def _switch(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, '').strip().lower()
    if value not in _SWITCHES:
        raise RuntimeError(f'{name} must be "on" or "off"; got {env.get(name)!r}')
    return _SWITCHES[value]


def _https_url(name: str, value: str) -> str:
    """An ``https://`` URL on the default port, with no user name, password, query or fragment."""
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
        or parts.query
        or parts.fragment
        or port not in (None, 443)
    ):
        raise RuntimeError(f'{name} must be an https:// address on port 443 with no query; got {value!r}')
    return value


def _groups(env: Mapping[str, str], name: str) -> frozenset[str]:
    return frozenset(group.strip() for group in env.get(name, '').split(',') if group.strip())


def _check_ca_file(path: str) -> None:
    """Refuse a CA file that cannot be read, or that holds no certificate authority (a server certificate)."""
    try:
        authorities = ssl.create_default_context(cafile=path).get_ca_certs()
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError(f'INSIGHT_OIDC_CA_FILE: {path} could not be read as PEM certificates') from exc
    if not authorities:
        raise RuntimeError(f'INSIGHT_OIDC_CA_FILE: {path} holds no certificate authority certificate')


@dataclass(frozen=True, slots=True)
class OidcSettings:
    """``INSIGHT_OIDC_*``: one provider, the confidential client Insight is registered as, and which
    provider groups give which role (none: new people wait for an admin's approval)."""

    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    #: The callback URL registered at the provider: ``INSIGHT_PUBLIC_URL`` + ``/login/sso/callback``.
    redirect_uri: str
    scopes: str = DEFAULT_SCOPES
    groups_claim: str = DEFAULT_GROUPS_CLAIM
    admin_groups: frozenset[str] = frozenset()
    analyst_groups: frozenset[str] = frozenset()
    viewer_groups: frozenset[str] = frozenset()
    #: A self-hosted provider on a private network (loopback, link-local and metadata addresses stay blocked).
    private_network: bool = False
    #: ``INSIGHT_OIDC_CA_FILE``: PEM certificate authorities that sign the provider's certificate (an internal
    #: CA). They replace the public ones for requests to the provider; nothing else trusts them.
    ca_file: str | None = None
    #: Turn the operator's password sign-in off (``INSIGHT_SSO_ONLY``); the CLI stays the break-glass.
    sso_only: bool = False

    @property
    def issuer_host(self) -> str:
        return urlsplit(self.issuer).hostname or ''

    def tls_context(self) -> ssl.SSLContext | None:
        """The TLS context for requests to the provider: ``None`` means the public certificate authorities."""
        return None if self.ca_file is None else ssl.create_default_context(cafile=self.ca_file)

    @property
    def groups_mapped(self) -> bool:
        """Whether provider groups set roles (then every sign-in sets the role again)."""
        return bool(self.admin_groups or self.analyst_groups or self.viewer_groups)

    def role_for(self, groups: Iterable[str]) -> Role | None:
        """The highest role the person's provider groups give, or ``None``."""
        member = set(groups)
        if member & self.admin_groups:
            return 'admin'
        if member & self.analyst_groups:
            return 'analyst'
        if member & self.viewer_groups:
            return 'viewer'
        return None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Self | None:
        """``None`` when no provider is set. Raises ``RuntimeError`` for an invalid or half-set provider, so a
        typo never leaves sign-in in an unexpected state."""
        env = os.environ if environ is None else environ
        issuer = env.get('INSIGHT_OIDC_ISSUER', '').strip()
        if not issuer:
            stray = sorted(
                name
                for name, value in env.items()
                if (name.startswith('INSIGHT_OIDC_') or name == 'INSIGHT_SSO_ONLY')
                and value.strip()
                and value.strip().lower() != 'off'
            )
            if stray:
                raise RuntimeError(f'{", ".join(stray)} needs INSIGHT_OIDC_ISSUER')
            return None
        _https_url('INSIGHT_OIDC_ISSUER', issuer)
        client_id = env.get('INSIGHT_OIDC_CLIENT_ID', '').strip()
        client_secret = env.get('INSIGHT_OIDC_CLIENT_SECRET', '').strip()
        if not client_id or not client_secret:
            raise RuntimeError(
                'INSIGHT_OIDC_ISSUER needs INSIGHT_OIDC_CLIENT_ID and INSIGHT_OIDC_CLIENT_SECRET'
            )
        public_url = env.get('INSIGHT_PUBLIC_URL', '').strip().rstrip('/')
        if not public_url.startswith('https://'):
            raise RuntimeError(
                'INSIGHT_OIDC_ISSUER needs INSIGHT_PUBLIC_URL, the https:// address people open Insight at: '
                'the provider sends them back to it'
            )
        scopes = ' '.join(env.get('INSIGHT_OIDC_SCOPES', '').split()) or DEFAULT_SCOPES
        if 'openid' not in scopes.split():
            raise RuntimeError(f'INSIGHT_OIDC_SCOPES must include openid; got {scopes!r}')
        groups_claim = env.get('INSIGHT_OIDC_GROUPS_CLAIM', '').strip() or DEFAULT_GROUPS_CLAIM
        if not _CLAIM_NAME.fullmatch(groups_claim):
            raise RuntimeError(f'INSIGHT_OIDC_GROUPS_CLAIM is not a claim name: {groups_claim!r}')
        ca_file = env.get('INSIGHT_OIDC_CA_FILE', '').strip() or None
        if ca_file is not None:
            _check_ca_file(ca_file)
        return cls(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=public_url + CALLBACK_PATH,
            scopes=scopes,
            groups_claim=groups_claim,
            admin_groups=_groups(env, 'INSIGHT_OIDC_ADMIN_GROUPS'),
            analyst_groups=_groups(env, 'INSIGHT_OIDC_ANALYST_GROUPS'),
            viewer_groups=_groups(env, 'INSIGHT_OIDC_VIEWER_GROUPS'),
            private_network=_switch(env, 'INSIGHT_OIDC_PRIVATE_NETWORK'),
            ca_file=ca_file,
            sso_only=_switch(env, 'INSIGHT_SSO_ONLY'),
        )
