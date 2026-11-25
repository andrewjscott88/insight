"""Offline HTTP contract for operator-supplied TAXII collections; no URL from a response is followed."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from insight import connectors, egress, stix_import, taxii_client
from insight.taxii import TAXII_MEDIA_TYPE

ROOT = 'https://taxii.example.org/root'
COLLECTION = 'synthetic-collection'
ENDPOINT = ROOT + '/collections/' + COLLECTION + '/objects/'
ENV_NAME = 'INSIGHT_SOURCE_SYNTHETIC'
PREVIOUS = '2026-01-01T00:00:01.123456788Z'
FIRST = '2026-01-01T00:00:01.123456789Z'
LAST = '2026-01-01T02:00:01.123456789123+02:00'
FIXTURES = Path(__file__).parents[1] / 'fixtures'
PAGE1 = (FIXTURES / 'taxii-collection-page-1.json').read_bytes()
PAGE2 = (FIXTURES / 'taxii-collection-page-2.json').read_bytes()
SECRET = 'PRIVATE-RESPONSE-CONTENT'


def _setup(
    monkeypatch: pytest.MonkeyPatch, responses: list[tuple[bytes, str, str]]
) -> list[tuple[str, dict[str, str], Mapping[str, str]]]:
    calls: list[tuple[str, dict[str, str], Mapping[str, str]]] = []

    async def fake(
        url: str,
        params: dict[str, str],
        *,
        response_headers: connectors.DownloadHeaders,
        headers: Mapping[str, str],
        **kwargs: Any,
    ) -> bytes:
        assert kwargs['allowed_hosts'] == frozenset({'taxii.example.org'})
        assert kwargs['allow_private'] is False
        calls.append((url, dict(params), headers))
        payload, response_headers.content_type, response_headers.date_added_last = responses[len(calls) - 1]
        return payload

    monkeypatch.setattr(connectors, 'download', fake)
    return calls


async def test_cross_page_bundle_preserves_precision_order_and_opaque_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _setup(monkeypatch, [(PAGE1, TAXII_MEDIA_TYPE, FIRST), (PAGE2, 'application/taxii+json', LAST)])
    batch = await taxii_client.fetch_collection(ROOT + '/', COLLECTION, added_after=PREVIOUS)
    assert batch.watermark == LAST
    assert batch.object_count == 2
    assert batch.bundle
    assert stix_import.parse_stix(batch.bundle, 'RED').reports[0].item.title == 'Synthetic collection report'
    assert [call[0] for call in calls] == [ENDPOINT, ENDPOINT]
    assert [call[1] for call in calls] == [
        {'added_after': PREVIOUS},
        {'added_after': PREVIOUS, 'next': 'page-2+token=='},
    ]
    assert all(call[2] == {'Accept': TAXII_MEDIA_TYPE} for call in calls)
    records = json.loads(PAGE2)['objects'] + json.loads(PAGE1)['objects']
    joined = json.dumps({'objects': records}).encode()
    _setup(monkeypatch, [(joined, 'Application/TAXII+JSON; charset="utf-8"; version="2.1"', LAST)])
    single = await taxii_client.fetch_collection(ROOT, COLLECTION)
    assert single.bundle == batch.bundle


@pytest.mark.parametrize('empty', [b'{}', b'{"objects":[]}', b'{"more":false,"objects":[]}'])
async def test_empty_page_keeps_previous_cursor(monkeypatch: pytest.MonkeyPatch, empty: bytes) -> None:
    _setup(monkeypatch, [(empty, TAXII_MEDIA_TYPE, '')])
    assert await taxii_client.fetch_collection(
        ROOT, COLLECTION, added_after=PREVIOUS
    ) == taxii_client.CollectionBatch(None, PREVIOUS, 0)


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        ('sample.token+/=', 'Bearer sample.token+/='),
        (
            'sample-user:sample password:more',
            'Basic ' + base64.b64encode(b'sample-user:sample password:more').decode(),
        ),
    ],
)
async def test_credentials_only_in_header(monkeypatch: pytest.MonkeyPatch, raw: str, expected: str) -> None:
    monkeypatch.setenv(ENV_NAME, raw)
    calls = _setup(monkeypatch, [(b'{}', TAXII_MEDIA_TYPE, '')])
    assert taxii_client.credentials_configured(ENV_NAME)
    await taxii_client.fetch_collection(ROOT, COLLECTION, credential_env=ENV_NAME)
    assert calls == [(ENDPOINT, {}, {'Accept': TAXII_MEDIA_TYPE, 'Authorization': expected})]


@pytest.mark.parametrize(
    ('name', 'value'),
    [
        ('OUTSIDE_PREFIX', 'secret'),
        ('INSIGHT_SOURCE_', 'secret'),
        ('INSIGHT_SOURCE_lower', 'secret'),
        ('INSIGHT_SOURCE_' + 'A' * 41, 'secret'),
        (ENV_NAME, ''),
        (ENV_NAME, 'whitespace token'),
        (ENV_NAME, 'token\nleak'),
        (ENV_NAME, 'é'),
        (ENV_NAME, ':password'),
        (ENV_NAME, 'user:'),
        (ENV_NAME, 'x' * 2049),
        (ENV_NAME, None),
    ],
)
async def test_bad_configuration_never_requests_anything(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str | None
) -> None:
    monkeypatch.delenv(name, raising=False)
    if value is not None:
        monkeypatch.setenv(name, value)
    calls = _setup(monkeypatch, [])
    assert not taxii_client.credentials_configured(name)
    with pytest.raises(taxii_client.TaxiiNotConfigured, match='not configured'):
        await taxii_client.fetch_collection(ROOT, COLLECTION, credential_env=name)
    assert calls == []
    assert taxii_client.credentials_configured(None)
    assert taxii_client.credentials_configured('')


async def test_open_access_never_sends_a_host_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: in temporary open access any visitor can repoint a source, so its credential stays home."""
    monkeypatch.setenv(ENV_NAME, 'sample.token')
    assert taxii_client.credentials_configured(ENV_NAME)
    monkeypatch.setenv('INSIGHT_DEV_NO_AUTH', 'on')
    calls = _setup(monkeypatch, [])
    assert not taxii_client.credentials_configured(ENV_NAME)
    with pytest.raises(taxii_client.TaxiiNotConfigured, match='temporary open access'):
        await taxii_client.fetch_collection(ROOT, COLLECTION, credential_env=ENV_NAME)
    assert calls == []
    calls = _setup(monkeypatch, [(b'{}', TAXII_MEDIA_TYPE, '')])
    await taxii_client.fetch_collection(ROOT, COLLECTION)  # a collection without a credential still works
    assert calls == [(ENDPOINT, {}, {'Accept': TAXII_MEDIA_TYPE})]


@pytest.mark.parametrize(
    ('root', 'collection'),
    [
        ('http://taxii.example.org', COLLECTION),
        ('https://u:p@taxii.example.org', COLLECTION),
        (ROOT + '?token=T', COLLECTION),
        (ROOT + '#fragment', COLLECTION),
        ('https://taxii.example.org:8443', COLLECTION),
        (ROOT, '../other'),
        (ROOT, 'bad%2Fpath'),
        (ROOT, 'https://other.example'),
        (ROOT, 'x?key=secret'),
    ],
)
async def test_bad_endpoint_never_requests_anything(
    monkeypatch: pytest.MonkeyPatch, root: str, collection: str
) -> None:
    calls = _setup(monkeypatch, [])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(root, collection)
    assert calls == []


@pytest.mark.parametrize(
    'media',
    [
        '',
        'application/json',
        'application/taxii+json;version=2.0',
        'application/taxii+json;version=2.1;version=2.0',
        'application/taxii+json;garbage',
        'application/taxii+json;charset=latin-1',
        'application/taxii+json; version="2.1',
    ],
)
async def test_requires_taxii_media_and_valid_parameters(monkeypatch: pytest.MonkeyPatch, media: str) -> None:
    _setup(monkeypatch, [(PAGE2, media, LAST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)


@pytest.mark.parametrize(
    'raw',
    [
        b'[]',
        b'{"error":"private"}',
        b'{"more":"true"}',
        b'{"more":false,"next":"unused"}',
        b'{"more":true,"next":"opaque","objects":[]}',
        b'{"more":true,"objects":[]}',
        b'{"objects":{}}',
        b'{"objects":[null]}',
        b'{"objects":[{"type":"indicator","id":"id","spec_version":"2.0"}]}',
        b'{"objects":[],"objects":[]}',
        b'{"nested":[}',
        b'\xff',
        PAGE1.replace(b'page-2+token==', b'https://elsewhere.example/path'),
        PAGE1.replace(b'page-2+token==', b'/continue'),
        PAGE1.replace(b'page-2+token==', b'x' * 1025),
    ],
)
async def test_invalid_unbounded_or_unrelated_envelopes_fail_closed(
    monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    _setup(monkeypatch, [(raw, TAXII_MEDIA_TYPE, FIRST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)


@pytest.mark.parametrize(
    'value',
    [
        '',
        '2026-02-30T12:00:00Z',
        'today',
        '2026-01-01T01:00:00',
        '2026-01-01T00:00:01+00:75',
        '2026-01-01T00:00:01.12345678799Z',
        PREVIOUS,
    ],
)
async def test_cursor_is_required_and_must_advance_beyond_resume(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    _setup(monkeypatch, [(PAGE2, TAXII_MEDIA_TYPE, value)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION, added_after=PREVIOUS)


async def test_a_page_may_share_exact_timestamp_but_may_not_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    _setup(monkeypatch, [(PAGE1, TAXII_MEDIA_TYPE, FIRST), (PAGE2, TAXII_MEDIA_TYPE, FIRST)])
    assert (await taxii_client.fetch_collection(ROOT, COLLECTION, added_after=PREVIOUS)).watermark == FIRST
    _setup(monkeypatch, [(PAGE1, TAXII_MEDIA_TYPE, LAST), (PAGE2, TAXII_MEDIA_TYPE, FIRST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION, added_after=PREVIOUS)
    calls = _setup(monkeypatch, [])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION, added_after='not-a-date')
    assert calls == []


async def test_duplicate_ids_or_repeated_cursors_refuse_partial_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for response in (
        PAGE1,
        PAGE1.replace(b'"more": true,', b'"more": false,').replace(
            b'"next": "page-2+token=="', b'"x_unused": true'
        ),
    ):
        calls = _setup(monkeypatch, [(PAGE1, TAXII_MEDIA_TYPE, FIRST), (response, TAXII_MEDIA_TYPE, LAST)])
        with pytest.raises(taxii_client.TaxiiClientError):
            await taxii_client.fetch_collection(ROOT, COLLECTION)
        assert len(calls) == 2


async def test_endless_more_aggregate_limits_and_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(taxii_client, 'MAX_PAGES', 2)
    calls = _setup(
        monkeypatch,
        [(PAGE1, TAXII_MEDIA_TYPE, FIRST), (PAGE1.replace(b'page-2+', b'page-3+'), TAXII_MEDIA_TYPE, LAST)],
    )
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)
    assert len(calls) == 2
    monkeypatch.setattr(taxii_client, 'MAX_OBJECTS', 1)
    _setup(monkeypatch, [(PAGE1, TAXII_MEDIA_TYPE, FIRST), (PAGE2, TAXII_MEDIA_TYPE, LAST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)
    monkeypatch.setattr(taxii_client, 'MAX_BYTES', len(PAGE1) + 2)
    _setup(monkeypatch, [(PAGE1, TAXII_MEDIA_TYPE, FIRST), (PAGE2, TAXII_MEDIA_TYPE, LAST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)

    async def wait(*args: Any, **kwargs: Any) -> bytes:
        await asyncio.Event().wait()
        raise AssertionError('unreachable')

    monkeypatch.setattr(taxii_client, 'DEADLINE', 0)
    monkeypatch.setattr(connectors, 'download', wait)
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)


async def test_guarded_transport_disallows_redirect_and_keeps_credentials_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[httpx.Request] = []
    real = connectors.download
    monkeypatch.setenv(ENV_NAME, SECRET)

    async def resolved(host: str, port: int) -> list[egress.IPAddress]:
        assert (host, port) == ('taxii.example.org', 443)
        return [ipaddress.ip_address('93.184.216.34')]

    def redirect(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(302, headers={'Location': 'https://other.example.org/' + SECRET})

    async def fake(*args: Any, **kwargs: Any) -> bytes:
        return await real(*args, **kwargs, transport=httpx.MockTransport(redirect))

    monkeypatch.setattr(egress, 'resolve', resolved)
    monkeypatch.setattr(connectors, 'download', fake)
    with pytest.raises(taxii_client.TaxiiClientError) as caught:
        await taxii_client.fetch_collection(ROOT, COLLECTION, credential_env=ENV_NAME)
    assert SECRET not in str(caught.value)
    assert [r.url.host for r in sent] == ['93.184.216.34']
    assert sent[0].headers['host'] == 'taxii.example.org'
    assert sent[0].extensions['sni_hostname'] == 'taxii.example.org'
    assert sent[0].headers['authorization'] == 'Bearer ' + SECRET


@pytest.mark.parametrize(
    'headers',
    [
        [('Content-Type', TAXII_MEDIA_TYPE), ('Content-Type', TAXII_MEDIA_TYPE)],
        [('X-TAXII-Date-Added-Last', 'x' * 129)],
        [('Content-Type', 'x' * 257)],
        [('X-TAXII-Date-Added-Last', FIRST), ('X-TAXII-Date-Added-Last', LAST)],
    ],
)
def test_response_header_capture_rejects_ambiguous_or_oversize_values(headers: list[tuple[str, str]]) -> None:
    with pytest.raises(ValueError, match='headers'):
        connectors.DownloadHeaders().read(httpx.Response(200, headers=headers))


@pytest.mark.parametrize('collection', ['_leading', '~alias', '.hidden', 'a' * 250])
async def test_collection_ids_use_the_same_path_segment_policy_as_settings(
    monkeypatch: pytest.MonkeyPatch, collection: str
) -> None:
    calls = _setup(monkeypatch, [(b'{}', TAXII_MEDIA_TYPE, '')])
    await taxii_client.fetch_collection(ROOT, collection)
    assert calls[0][0] == ROOT + '/collections/' + collection + '/objects/'


async def test_real_downloader_captures_only_bounded_headers_on_a_pinned_private_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = connectors.download
    sent: list[httpx.Request] = []

    async def resolve(host: str, port: int) -> list[egress.IPAddress]:
        assert (host, port) == ('taxii.example.org', 443)
        return [ipaddress.ip_address('192.168.30.5')]

    def page(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(
            200,
            headers={
                'Content-Type': TAXII_MEDIA_TYPE,
                'X-TAXII-Date-Added-Last': LAST,
                'X-Private-Header': SECRET,
            },
            content=PAGE2,
        )

    async def through_downloader(*args: Any, **kwargs: Any) -> bytes:
        return await real(*args, **kwargs, transport=httpx.MockTransport(page))

    monkeypatch.setattr(connectors, 'download', through_downloader)
    monkeypatch.setattr(egress, 'resolve', resolve)
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)
    assert sent == []
    result = await taxii_client.fetch_collection(ROOT, COLLECTION, allow_private=True)
    assert result.watermark == LAST
    assert result.bundle
    assert SECRET.encode() not in result.bundle
    assert [r.url.host for r in sent] == ['192.168.30.5']
    assert sent[0].headers['host'] == 'taxii.example.org'


async def test_rejects_advance_without_objects_and_oversized_reconstructed_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, [(b'{}', TAXII_MEDIA_TYPE, LAST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)
    small = json.dumps({'objects': json.loads(PAGE2)['objects']}, separators=(',', ':')).encode()
    monkeypatch.setattr(taxii_client, 'MAX_BYTES', len(small))
    _setup(monkeypatch, [(small, TAXII_MEDIA_TYPE, LAST)])
    with pytest.raises(taxii_client.TaxiiClientError):
        await taxii_client.fetch_collection(ROOT, COLLECTION)
