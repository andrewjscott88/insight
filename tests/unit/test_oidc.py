"""The identity provider's settings and the sign-in client (ADR 0046), against an in-process fake provider."""

from __future__ import annotations

import base64
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from tests.oidc_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    PUBLIC_URL,
    FakeProvider,
    Key,
    claims,
    oidc_env,
    token,
)

from insight.config import Settings
from insight.oidc import FLOW_SECONDS, RETRY_SECONDS, Flow, OidcClient, SignInFailed
from insight.oidc_settings import OidcSettings

GOOD = {'INSIGHT_PASSWORD': 'p' * 12, 'INSIGHT_SESSION_SECRET': 's' * 32}


def settings(**changes: str) -> OidcSettings:
    found = OidcSettings.from_env(oidc_env(**changes))
    assert found is not None
    return found


# --------------------------------------------------------------------------- settings


def test_no_issuer_means_password_sign_in_only() -> None:
    assert OidcSettings.from_env({}) is None
    assert OidcSettings.from_env({'INSIGHT_SSO_ONLY': 'off'}) is None


@pytest.mark.parametrize('name', ['INSIGHT_OIDC_CLIENT_ID', 'INSIGHT_SSO_ONLY', 'INSIGHT_OIDC_ADMIN_GROUPS'])
def test_half_a_provider_fails_closed(name: str) -> None:
    with pytest.raises(RuntimeError, match='needs INSIGHT_OIDC_ISSUER'):
        OidcSettings.from_env({name: 'on' if name == 'INSIGHT_SSO_ONLY' else 'x'})


@pytest.mark.parametrize(
    ('changes', 'message'),
    [
        ({'INSIGHT_OIDC_ISSUER': 'http://idp.example.org/realms/insight'}, 'https://'),
        ({'INSIGHT_OIDC_ISSUER': 'https://idp.example.org:8443/realms/insight'}, 'port 443'),
        ({'INSIGHT_OIDC_ISSUER': 'https://user:pw@idp.example.org/'}, 'https://'),
        ({'INSIGHT_OIDC_ISSUER': 'https://idp.example.org/?realm=x'}, 'no query'),
        ({'INSIGHT_OIDC_CLIENT_SECRET': ''}, 'CLIENT_SECRET'),
        ({'INSIGHT_PUBLIC_URL': ''}, 'INSIGHT_PUBLIC_URL'),
        ({'INSIGHT_PUBLIC_URL': 'http://insight.example.org'}, 'INSIGHT_PUBLIC_URL'),
        ({'INSIGHT_OIDC_SCOPES': 'email profile'}, 'openid'),
        ({'INSIGHT_OIDC_GROUPS_CLAIM': 'two words'}, 'claim name'),
        ({'INSIGHT_SSO_ONLY': 'yes'}, 'INSIGHT_SSO_ONLY'),
        ({'INSIGHT_OIDC_PRIVATE_NETWORK': '1'}, 'INSIGHT_OIDC_PRIVATE_NETWORK'),
    ],
)
def test_invalid_provider_settings_fail_closed(changes: dict[str, str], message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        OidcSettings.from_env(oidc_env(**changes))


def test_provider_settings_and_the_role_from_groups() -> None:
    found = settings(
        INSIGHT_OIDC_ADMIN_GROUPS='/insight-admins, ops',
        INSIGHT_OIDC_ANALYST_GROUPS='insight-analysts',
        INSIGHT_OIDC_VIEWER_GROUPS='staff',
        INSIGHT_PUBLIC_URL=PUBLIC_URL + '/',
    )
    assert found.redirect_uri == f'{PUBLIC_URL}/login/sso/callback'
    assert (found.scopes, found.groups_claim, found.issuer_host) == (
        'openid email profile',
        'groups',
        'idp.example.org',
    )
    assert found.groups_mapped
    assert found.role_for(['staff', 'ops']) == 'admin'
    assert found.role_for(['insight-analysts', 'staff']) == 'analyst'
    assert found.role_for(['staff']) == 'viewer'
    assert found.role_for(['Staff', 'other']) is None, 'group names match exactly'
    assert not settings().groups_mapped
    assert CLIENT_SECRET not in repr(found)


def test_the_provider_cannot_be_combined_with_open_access() -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_DEV_NO_AUTH'):
        Settings.from_env({**GOOD, **oidc_env(), 'INSIGHT_DEV_NO_AUTH': 'on'})
    assert Settings.from_env({**GOOD, **oidc_env(INSIGHT_SSO_ONLY='on')}).oidc.sso_only  # type: ignore[union-attr]


# --------------------------------------------------------------------------- the flow


def test_a_flow_has_pkce_and_survives_the_cookie() -> None:
    flow = Flow.new(1000.0)
    assert 43 <= len(flow.verifier) <= 128
    assert len(flow.challenge) == 43
    assert '=' not in flow.challenge
    assert Flow.from_cookie(flow.as_cookie()) == flow
    assert not flow.expired(1000.0 + FLOW_SECONDS)
    assert flow.expired(1000.0 + FLOW_SECONDS + 1)
    assert flow.expired(999.0)
    for broken in (None, 'x', {}, {**flow.as_cookie(), 'at': 'soon'}, {**flow.as_cookie(), 'state': 3}):
        assert Flow.from_cookie(broken) is None


async def test_the_authorisation_request(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider()
    provider.install(monkeypatch)
    client = OidcClient(settings())
    flow = Flow.new(time.time())
    target = urlsplit(await client.authorization_url(flow, time.time()))
    query = {k: v[0] for k, v in parse_qs(target.query).items()}
    assert f'{target.scheme}://{target.netloc}{target.path}' == provider.discovery['authorization_endpoint']
    assert query == {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': f'{PUBLIC_URL}/login/sso/callback',
        'scope': 'openid email profile',
        'state': flow.state,
        'nonce': flow.nonce,
        'code_challenge': flow.challenge,
        'code_challenge_method': 'S256',
    }
    await client.authorization_url(Flow.new(time.time()), time.time())
    assert len(provider.requests) == 1, 'discovery is cached'


async def test_the_code_exchange_sends_the_verifier_and_checks_the_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = FakeProvider()
    provider.install(monkeypatch)
    client = OidcClient(settings())
    flow = Flow.new(time.time())
    provider.nonce = flow.nonce
    identity = await client.finish('the-code', flow, time.time())
    assert (identity.subject, identity.groups) == ('subject-1', ('insight-analysts',))
    exchange = next(r for r in provider.requests if r.url.path.endswith('/token'))
    form = {k: v[0] for k, v in parse_qs(exchange.content.decode()).items()}
    assert form == {
        'grant_type': 'authorization_code',
        'code': 'the-code',
        'redirect_uri': f'{PUBLIC_URL}/login/sso/callback',
        'code_verifier': flow.verifier,
    }
    basic = base64.b64decode(exchange.headers['Authorization'].removeprefix('Basic ')).decode()
    assert basic == f'{CLIENT_ID}:{CLIENT_SECRET}'


async def test_basic_auth_form_encodes_both_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider()
    provider.install(monkeypatch)
    flow = Flow.new(time.time())
    provider.nonce = flow.nonce
    await OidcClient(settings(INSIGHT_OIDC_CLIENT_SECRET='a b:c%')).finish('code', flow, time.time())
    exchange = next(r for r in provider.requests if r.url.path.endswith('/token'))
    basic = base64.b64decode(exchange.headers['Authorization'].removeprefix('Basic ')).decode()
    assert basic == f'{CLIENT_ID}:a+b%3Ac%25', 'RFC 6749 2.3.1: application/x-www-form-urlencoded first'


async def test_client_secret_post_when_the_provider_only_offers_it(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider(discovery={'token_endpoint_auth_methods_supported': ['client_secret_post']})
    provider.install(monkeypatch)
    flow = Flow.new(time.time())
    provider.nonce = flow.nonce
    await OidcClient(settings()).finish('the-code', flow, time.time())
    exchange = next(r for r in provider.requests if r.url.path.endswith('/token'))
    assert 'Authorization' not in exchange.headers
    assert parse_qs(exchange.content.decode())['client_secret'] == [CLIENT_SECRET]


async def test_a_rotated_key_is_fetched_again_once(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider()
    provider.install(monkeypatch)
    client = OidcClient(settings())
    flow = Flow.new(time.time())
    provider.nonce = flow.nonce
    await client.finish('code', flow, time.time())
    provider.key = Key.make('RS256', kid='key-2')  # The provider rotates; the cached set has only key-1.
    later = time.time() + 400
    flow = Flow.new(later)
    provider.nonce = flow.nonce
    assert (await client.finish('code', flow, later)).subject == 'subject-1'
    assert sum(r.url.path.endswith('/certs') for r in provider.requests) == 2


@pytest.mark.parametrize(
    'discovery',
    [
        {'issuer': 'https://idp.example.org/realms/other'},
        {'token_endpoint': 'http://idp.example.org/token'},
        {'jwks_uri': 'https://idp.example.org:8443/certs'},
        {'authorization_endpoint': None},
        {'code_challenge_methods_supported': ['plain']},
        {'response_types_supported': ['token']},
    ],
)
async def test_an_unsafe_discovery_document_is_refused(
    monkeypatch: pytest.MonkeyPatch, discovery: dict[str, object]
) -> None:
    provider = FakeProvider(discovery=discovery)
    provider.install(monkeypatch)
    with pytest.raises(SignInFailed):
        await OidcClient(settings()).authorization_url(Flow.new(time.time()), time.time())


async def test_a_failing_provider_is_not_asked_again_for_a_moment(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider(discovery={'issuer': 'https://elsewhere.example.org'})
    provider.install(monkeypatch)
    client = OidcClient(settings())
    now = time.time()
    with pytest.raises(SignInFailed, match='another issuer'):
        await client.authorization_url(Flow.new(now), now)
    provider.discovery['issuer'] = ISSUER
    with pytest.raises(SignInFailed, match='moments ago'):
        await client.authorization_url(Flow.new(now + 1), now + 1)
    assert len(provider.requests) == 1, 'nothing was sent during the pause'
    later = now + RETRY_SECONDS + 1
    assert (await client.authorization_url(Flow.new(later), later)).startswith(ISSUER)
    provider.key = Key.make('RS256', kid='key-2')
    provider.discovery['jwks_uri'] = f'{ISSUER}/missing/certs'  # Cached discovery keeps the old address.
    flow = Flow.new(later)
    provider.nonce = flow.nonce
    assert (await client.finish('code', flow, later)).subject == 'subject-1'


async def test_failures_never_carry_secrets_or_provider_text(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider(token_status=400)
    provider.install(monkeypatch)
    flow = Flow.new(time.time())
    with pytest.raises(SignInFailed) as failed:
        await OidcClient(settings()).finish('code', flow, time.time())
    assert CLIENT_SECRET not in str(failed.value)
    assert 'idp.example.org could not be reached' in str(failed.value)


async def test_a_token_for_another_nonce_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeProvider()
    provider.on_token = lambda p: token(p.key, claims('someone-elses-nonce'))
    provider.install(monkeypatch)
    with pytest.raises(SignInFailed, match='wrong nonce'):
        await OidcClient(settings()).finish('code', Flow.new(time.time()), time.time())


async def test_the_provider_must_be_on_a_public_address_unless_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ipaddress

    from insight import egress

    async def private(host: str, port: int) -> list[egress.IPAddress]:
        return [ipaddress.ip_address('10.0.0.5')]

    provider = FakeProvider()
    provider.install(monkeypatch)
    monkeypatch.setattr(egress, 'resolve', private)
    with pytest.raises(SignInFailed):
        await OidcClient(settings()).authorization_url(Flow.new(time.time()), time.time())
    target = await OidcClient(settings(INSIGHT_OIDC_PRIVATE_NETWORK='on')).authorization_url(
        Flow.new(time.time()), time.time()
    )
    assert target.startswith(ISSUER)


# ------------------------------------------------------------------------- an internal certificate authority


def pem_certificate(directory: Path, *, authority: bool) -> Path:
    """A self-signed certificate: a certificate authority, or (``authority=False``) a server certificate."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Insight test CA')])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=authority, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = directory / ('ca.pem' if authority else 'server.pem')
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path


def test_an_internal_ca_file_is_checked_at_start_up(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match='could not be read'):
        settings(INSIGHT_OIDC_CA_FILE=str(tmp_path / 'missing.pem'))
    (tmp_path / 'junk.pem').write_text('not a certificate')
    with pytest.raises(RuntimeError, match='could not be read'):
        settings(INSIGHT_OIDC_CA_FILE=str(tmp_path / 'junk.pem'))
    with pytest.raises(RuntimeError, match='no certificate authority'):
        settings(INSIGHT_OIDC_CA_FILE=str(pem_certificate(tmp_path, authority=False)))
    with pytest.raises(RuntimeError, match='needs INSIGHT_OIDC_ISSUER'):
        OidcSettings.from_env({'INSIGHT_OIDC_CA_FILE': str(tmp_path / 'ca.pem')})
    assert settings().ca_file is None, 'without the setting: the public authorities'


async def test_requests_to_the_provider_trust_only_the_internal_ca(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from insight import connectors

    ca = pem_certificate(tmp_path, authority=True)
    found = settings(INSIGHT_OIDC_CA_FILE=str(ca))
    assert found.ca_file == str(ca)
    provider = FakeProvider()
    provider.install(monkeypatch)
    wrapped = connectors.download
    files: list[object] = []

    async def recording(*args: object, **kwargs: object) -> bytes:
        files.append(kwargs.get('ca_file'))
        return await wrapped(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(connectors, 'download', recording)
    flow = Flow.new(time.time())
    provider.nonce = flow.nonce
    await OidcClient(found).finish('code', flow, time.time())
    assert files == [str(ca)] * 3, 'discovery, the token exchange and the key set'
