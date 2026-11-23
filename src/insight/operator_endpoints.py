"""Endpoint identifiers shared by operator-source forms and outbound TAXII requests."""

import re


def valid_collection_id(value: str) -> bool:
    """Accept one unescaped URL path segment, excluding the relative dot segments."""
    return value not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9._~-]{1,250}', value) is not None
