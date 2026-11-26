"""A fake OpenID Connect provider for tests (ADR 0046): signing keys, a key set, ID tokens and an HTTP handler
for discovery, the token endpoint and the key set. Nothing leaves the process."""

from __future__ import annotations

import base64
import ipaddress
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from insight import connectors, egress

ISSUER = 'https://idp.example.org/realms/insight'
CLIENT_ID = 'insight-workspace'
CLIENT_SECRET = 'fixture-client-secret'
PUBLIC_URL = 'https://insight.example.org'


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def number(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, 'big'))


@dataclass
class Key:
    alg: str
    kid: str
    private: Any

    @classmethod
    def make(cls, alg: str = 'RS256', kid: str = 'key-1', bits: int = 2048) -> Key:
        if alg == 'ES256':
            return cls(alg, kid, ec.generate_private_key(ec.SECP256R1()))
        return cls(alg, kid, rsa.generate_private_key(public_exponent=65537, key_size=bits))

    def jwk(self, **extra: Any) -> dict[str, Any]:
        public = self.private.public_key().public_numbers()
        if self.alg == 'ES256':
            body = {
                'kty': 'EC',
                'crv': 'P-256',
                'x': b64(public.x.to_bytes(32, 'big')),
                'y': b64(public.y.to_bytes(32, 'big')),
            }
        else:
            body = {'kty': 'RSA', 'n': number(public.n), 'e': number(public.e)}
        return {**body, 'kid': self.kid, 'use': 'sig', 'alg': self.alg, **extra}

    def sign(self, data: bytes) -> bytes:
        if self.alg == 'ES256':
            r, s = utils.decode_dss_signature(self.private.sign(data, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        if self.alg == 'PS256':
            pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            return bytes(self.private.sign(data, pss, hashes.SHA256()))
        return bytes(self.private.sign(data, padding.PKCS1v15(), hashes.SHA256()))


def claims(nonce: str, **changes: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        'iss': ISSUER,
        'aud': CLIENT_ID,
        'sub': 'subject-1',
        'iat': now,
        'exp': now + 300,
        'nonce': nonce,
        'email': 'ann@example.org',
        'email_verified': True,
        'name': 'Ann Analyst',
        'groups': ['insight-analysts'],
    }
    base.update(changes)
    return {k: v for k, v in base.items() if v is not None}


def token(
    key: Key, body: Mapping[str, Any], *, header: Mapping[str, Any] | None = None, alg: str | None = None
) -> str:
    head = {'alg': key.alg if alg is None else alg, 'kid': key.kid, 'typ': 'JWT', **(header or {})}
    signing = f'{b64(json.dumps(head).encode())}.{b64(json.dumps(body).encode())}'
    return f'{signing}.{b64(key.sign(signing.encode()))}'


@dataclass
class FakeProvider:
    """Discovery, token endpoint and key set at ``idp.example.org``; records the requests it saw."""

    key: Key = field(default_factory=Key.make)
    nonce: str = ''
    groups: list[str] = field(default_factory=lambda: ['insight-analysts'])
    subject: str = 'subject-1'
    discovery: dict[str, Any] = field(default_factory=dict)
    token_status: int = 200
    requests: list[httpx.Request] = field(default_factory=list)
    on_token: Callable[[FakeProvider], str] | None = None

    def __post_init__(self) -> None:
        self.discovery = {
            'issuer': ISSUER,
            'authorization_endpoint': f'{ISSUER}/protocol/openid-connect/auth',
            'token_endpoint': f'{ISSUER}/protocol/openid-connect/token',
            'jwks_uri': f'{ISSUER}/protocol/openid-connect/certs',
            'response_types_supported': ['code'],
            'code_challenge_methods_supported': ['S256'],
            'id_token_signing_alg_values_supported': ['RS256'],
            **self.discovery,
        }

    def id_token(self) -> str:
        if self.on_token is not None:
            return self.on_token(self)
        return token(self.key, claims(self.nonce, sub=self.subject, groups=self.groups))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        assert request.method == ('POST' if path.endswith('/token') else 'GET')
        if path.endswith('/.well-known/openid-configuration'):
            return httpx.Response(200, json=self.discovery)
        if path.endswith('/certs'):
            return httpx.Response(200, json={'keys': [self.key.jwk()]})
        if path.endswith('/token'):
            form = parse_qs(request.content.decode())
            assert form['grant_type'] == ['authorization_code']
            return httpx.Response(self.token_status, json={'id_token': self.id_token(), 'access_token': 'x'})
        return httpx.Response(404)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Route ``connectors.download`` to this provider (DNS answers with a public test address)."""
        real = connectors.download

        async def resolved(host: str, port: int) -> list[egress.IPAddress]:
            return [ipaddress.ip_address('93.184.216.34')]

        async def download(*args: Any, **kwargs: Any) -> bytes:
            return await real(*args, **kwargs, transport=httpx.MockTransport(self.handle))

        monkeypatch.setattr(egress, 'resolve', resolved)
        monkeypatch.setattr(connectors, 'download', download)


def oidc_env(**changes: str) -> dict[str, str]:
    return {
        'INSIGHT_OIDC_ISSUER': ISSUER,
        'INSIGHT_OIDC_CLIENT_ID': CLIENT_ID,
        'INSIGHT_OIDC_CLIENT_SECRET': CLIENT_SECRET,
        'INSIGHT_PUBLIC_URL': PUBLIC_URL,
        **changes,
    }
