"""Modern MCP request metadata and mirrored HTTP headers; no authentication or connection state.

2026-07-28 requires metadata on each request. Legacy 2025-11-25 remains supported explicitly. Neither
client names nor capabilities convey authorization: the HTTP route has already authenticated the API key.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Final

from .mcp import MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION, SUPPORTED_VERSIONS
from .schemas import McpMessage

META_PREFIX: Final = 'io.modelcontextprotocol/'
VERSION_FIELD: Final = META_PREFIX + 'protocolVersion'
CAPABILITIES_FIELD: Final = META_PREFIX + 'clientCapabilities'
INFO_FIELD: Final = META_PREFIX + 'clientInfo'
_META_KEY = re.compile(
    r'^(?:[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?'
    r'(?:\.[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*/)?'
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)?$'
)


class MetadataError(ValueError):
    """A protocol error classified by type. Its exception details stay inside the server."""

    code: int


class HeaderError(MetadataError):
    code = -32020


class InvalidMetadata(MetadataError):
    code = -32602


class UnsupportedVersion(MetadataError):
    code = -32022


def _header(value: str | None, *, encoded: bool = False) -> str:
    if (
        value is None
        or not value
        or value != value.strip()
        or any(ord(c) < 32 or ord(c) > 126 for c in value)
    ):
        raise HeaderError('Missing or malformed request header')
    if encoded and value.startswith('=?base64?') and value.endswith('?='):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode('utf-8')
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise HeaderError('Malformed encoded request header') from exc
    return value


def validate_metadata(message: McpMessage, headers: Mapping[str, str]) -> bool:
    """Return whether modern semantics apply, or a fixed protocol error without echoing client input."""
    version = headers.get('mcp-protocol-version')
    meta = message.params.get('_meta')
    modern_fields = isinstance(meta, dict) and any(key.startswith(META_PREFIX) for key in meta)
    modern = (version != PROTOCOL_VERSION and version is not None) or modern_fields
    if not modern:
        if message.method != 'initialize' and version is None:
            raise HeaderError('MCP-Protocol-Version is required')
        return False
    if not isinstance(meta, dict):
        raise InvalidMetadata('Required request metadata is missing')
    requested = meta.get(VERSION_FIELD)
    if not isinstance(requested, str) or not requested or len(requested) > 32:
        raise InvalidMetadata('Required protocol version is missing or malformed')
    if _header(version) != requested:
        raise HeaderError('Protocol version header does not match request metadata')
    if requested not in SUPPORTED_VERSIONS:
        raise UnsupportedVersion('Unsupported protocol version')
    if requested != MODERN_PROTOCOL_VERSION:
        raise InvalidMetadata('Per-request protocol metadata requires the modern version')
    if not all(isinstance(key, str) and len(key) <= 200 and _META_KEY.fullmatch(key) for key in meta):
        raise InvalidMetadata('Malformed metadata key')
    if not isinstance(meta.get(CAPABILITIES_FIELD), dict):
        raise InvalidMetadata('Client capabilities are required')
    info = meta.get(INFO_FIELD)
    if info is not None and (
        not isinstance(info, dict)
        or not all(
            isinstance(info.get(key), str) and 0 < len(info[key]) <= 200 for key in ('name', 'version')
        )
    ):
        raise InvalidMetadata('Malformed client information')
    if _header(headers.get('mcp-method')) != message.method:
        raise HeaderError('Method header does not match request body')
    if message.method in ('tools/call', 'resources/read', 'prompts/get'):
        field = 'uri' if message.method == 'resources/read' else 'name'
        if _header(headers.get('mcp-name'), encoded=True) != message.params.get(field):
            raise HeaderError('Name header does not match request body')
    return True
