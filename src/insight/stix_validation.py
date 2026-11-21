"""Validate STIX 2.1 bundles with the OASIS validator and its packaged schemas."""

from __future__ import annotations

from typing import Any

from stix2validator import ValidationOptions, validate_parsed_json


def validate_stix_bundle(bundle: dict[str, Any]) -> None:
    """Reject invalid output before it can be downloaded or audited as a successful export."""
    result = validate_parsed_json(bundle, ValidationOptions(version='2.1', silent=True))
    if not result.is_valid:
        raise ValueError('STIX 2.1 validation failed.')
