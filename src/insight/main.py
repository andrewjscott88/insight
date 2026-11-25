"""Compatibility module: the web application now lives in ``insight.web`` (review finding B3).

``uvicorn insight.main:create_app --factory`` and ``from insight.main import create_app`` keep working;
new code should import from ``insight.web``.
"""

from __future__ import annotations

from .web.app import ROOT, create_app, theme_context
from .web.auth import (
    INVALID_KEY_HEADERS,
    LOGIN_MAX_FAILURES,
    LOGIN_WINDOW_SECONDS,
    MFA_UNPAIRED,
    MFA_UNPAIRED_LOG,
    SESSION_TTL_SECONDS,
    AuthDependency,
    KeyVerifier,
    SessionCheck,
    acting,
    api_key_verifier,
    auth_dependency,
    caller_of,
    reader_limit,
    session_checker,
    session_lookup,
    start_session,
    workspace_lookup,
)
from .web.boundary import (
    HSTS,
    MAX_BODY_BYTES,
    SAFE_METHODS,
    SECURITY_HEADERS,
    SESSION_ONLY_ROUTES,
    SESSION_ONLY_WRITE_PREFIXES,
    UNLIMITED_READER_PREFIXES,
    BoundaryMiddleware,
    rate_limit_policy,
    tokens_match,
)
from .web.callers import PUBLIC_CALLER, SESSION_CALLER, Caller
from .web.routes.documents import get_document_or_404
from .web.routes.exports import IOC_EXPORT_PARAMETERS, ioc_export_query
from .web.routes.sources import ENRICHMENT_INTERVAL_SECONDS

__all__ = [
    'ENRICHMENT_INTERVAL_SECONDS',
    'HSTS',
    'INVALID_KEY_HEADERS',
    'IOC_EXPORT_PARAMETERS',
    'LOGIN_MAX_FAILURES',
    'LOGIN_WINDOW_SECONDS',
    'MAX_BODY_BYTES',
    'MFA_UNPAIRED',
    'MFA_UNPAIRED_LOG',
    'PUBLIC_CALLER',
    'ROOT',
    'SAFE_METHODS',
    'SECURITY_HEADERS',
    'SESSION_CALLER',
    'SESSION_ONLY_ROUTES',
    'SESSION_ONLY_WRITE_PREFIXES',
    'SESSION_TTL_SECONDS',
    'UNLIMITED_READER_PREFIXES',
    'AuthDependency',
    'BoundaryMiddleware',
    'Caller',
    'KeyVerifier',
    'SessionCheck',
    'acting',
    'api_key_verifier',
    'auth_dependency',
    'caller_of',
    'create_app',
    'get_document_or_404',
    'ioc_export_query',
    'rate_limit_policy',
    'reader_limit',
    'session_checker',
    'session_lookup',
    'start_session',
    'theme_context',
    'tokens_match',
    'workspace_lookup',
]
