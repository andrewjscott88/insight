"""Pure MCP schemas, result bounds and per-request protocol metadata."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from pydantic import ValidationError

from insight.mcp import MAX_RESULT_BYTES, MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION, tool_result
from insight.mcp_transport import (
    CAPABILITIES_FIELD,
    INFO_FIELD,
    VERSION_FIELD,
    MetadataError,
    validate_metadata,
)
from insight.schemas import (
    McpIdInput,
    McpInput,
    McpLandscapeInput,
    McpMessage,
    McpRequirementsInput,
    McpSearchInput,
)


@pytest.mark.parametrize(
    ('schema', 'args'),
    [
        (McpSearchInput, {'q': 'x', 'limit': 0}),
        (McpSearchInput, {'q': 'x', 'limit': 51}),
        (McpSearchInput, {'q': 'x' * 201}),
        (McpSearchInput, {'q': 'x', 'limit': True}),
        (McpIdInput, {'id': ''}),
        (McpIdInput, {'id': 'x' * 65}),
        (McpRequirementsInput, {'kind': 'unknown'}),
        (McpLandscapeInput, {'days': 31}),
        (McpLandscapeInput, {'days': 0}),
        (McpLandscapeInput, {'max_tlp': 'RED'}),
    ],
)
def test_arguments_are_strict_and_bounded(schema: type[McpInput], args: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        schema.model_validate(args)


def test_result_caps_are_explicit_and_keep_text_identical() -> None:
    result = tool_result({'items': ['x'] * 51, 'description': 'x' * 2001})
    data = result['structuredContent']
    assert data['truncated']
    assert data['sharing_tlp'] == 'RED'
    assert tool_result({}, sharing_tlp='GREEN')['structuredContent']['sharing_tlp'] == 'GREEN'
    assert len(data['items']) == 50
    assert len(data['description']) == 2000
    assert json.loads(result['content'][0]['text']) == data
    over = tool_result({'items': ['😀' * 2000] * 50})
    assert over['isError']
    assert over['structuredContent']['truncated']
    assert len(json.dumps(over).encode()) < MAX_RESULT_BYTES * 2 + 1000
    nested: Any = 'value'
    for _ in range(14):
        nested = {'nested': nested}
    assert tool_result({'nested': nested})['structuredContent']['truncated']


def modern_request(method: str = 'tools/list') -> tuple[McpMessage, dict[str, str]]:
    meta = {VERSION_FIELD: MODERN_PROTOCOL_VERSION, CAPABILITIES_FIELD: {}}
    message = McpMessage(jsonrpc='2.0', id=1, method=method, params={'_meta': meta})
    return message, {'mcp-protocol-version': MODERN_PROTOCOL_VERSION, 'mcp-method': method}


def test_current_metadata_and_legacy_selection() -> None:
    message, headers = modern_request()
    assert validate_metadata(message, headers)
    legacy = McpMessage(jsonrpc='2.0', id=1, method='ping')
    assert not validate_metadata(legacy, {'mcp-protocol-version': PROTOCOL_VERSION})
    initialize = McpMessage(jsonrpc='2.0', id=1, method='initialize')
    assert not validate_metadata(initialize, {})
    with pytest.raises(MetadataError) as caught:
        validate_metadata(legacy, {})
    assert caught.value.code == -32020


@pytest.mark.parametrize('field', [VERSION_FIELD, CAPABILITIES_FIELD])
def test_required_current_metadata_cannot_be_omitted(field: str) -> None:
    message, headers = modern_request()
    del message.params['_meta'][field]
    with pytest.raises(MetadataError) as caught:
        validate_metadata(message, headers)
    assert caught.value.code == -32602


def test_current_metadata_types_and_name_rules() -> None:
    message, headers = modern_request()
    for meta in (
        None,
        {VERSION_FIELD: 123},
        {VERSION_FIELD: MODERN_PROTOCOL_VERSION},
        {VERSION_FIELD: MODERN_PROTOCOL_VERSION, CAPABILITIES_FIELD: []},
        {VERSION_FIELD: MODERN_PROTOCOL_VERSION, CAPABILITIES_FIELD: {}, 'bad key': True},
        {VERSION_FIELD: MODERN_PROTOCOL_VERSION, CAPABILITIES_FIELD: {}, INFO_FIELD: {'name': 1}},
    ):
        message.params['_meta'] = meta
        with pytest.raises(MetadataError) as caught:
            validate_metadata(message, headers)
        assert caught.value.code == -32602
    message.params['_meta'] = {
        VERSION_FIELD: MODERN_PROTOCOL_VERSION,
        CAPABILITIES_FIELD: {},
        INFO_FIELD: {'name': 'Test', 'version': '1'},
    }
    assert validate_metadata(message, headers)


@pytest.mark.parametrize(
    ('key', 'value'),
    [
        ('mcp-method', None),
        ('mcp-method', ''),
        ('mcp-method', 'tools/call'),
        ('mcp-method', ' tools/list'),
        ('mcp-method', 'tools/list\n'),
        ('mcp-method', '世界'),
        ('mcp-protocol-version', None),
        ('mcp-protocol-version', PROTOCOL_VERSION),
    ],
)
def test_mirrored_headers_cannot_disagree_or_be_absent(key: str, value: str | None) -> None:
    message, headers = modern_request()
    if value is None:
        del headers[key]
    else:
        headers[key] = value
    with pytest.raises(MetadataError) as caught:
        validate_metadata(message, headers)
    assert caught.value.code == -32020


def test_unsupported_current_version_lists_both_supported_eras() -> None:
    message, headers = modern_request()
    headers['mcp-protocol-version'] = message.params['_meta'][VERSION_FIELD] = '2099-01-01'
    with pytest.raises(MetadataError) as caught:
        validate_metadata(message, headers)
    assert caught.value.code == -32022
    assert caught.value.data == {
        'supported': [MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION],
        'requested': '2099-01-01',
    }


def test_named_header_decoding_is_strict_and_matches_the_body() -> None:
    message, headers = modern_request('tools/call')
    message.params['name'] = 'search_reports'
    for value in (None, 'other_tool', '=?base64?%%%?=', '=?base64?/w==?='):
        if value is None:
            headers.pop('mcp-name', None)
        else:
            headers['mcp-name'] = value
        with pytest.raises(MetadataError) as caught:
            validate_metadata(message, headers)
        assert caught.value.code == -32020
    headers['mcp-name'] = 'search_reports'
    assert validate_metadata(message, headers)
    headers['mcp-name'] = '=?base64?' + base64.b64encode(b'search_reports').decode() + '?='
    assert validate_metadata(message, headers)
    # Header-safe tool names are recommended; the transport must still decode other valid names.
    message.params['name'] = '世界'
    headers['mcp-name'] = '=?base64?' + base64.b64encode('世界'.encode()).decode() + '?='
    assert validate_metadata(message, headers)
