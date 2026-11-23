"""Exporting intelligence products (TIP 4.4, ADR 0036): Markdown, or a validated STIX 2.1 bundle, of the draft
or of a published version. Every export is audited as ``case.export``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..schemas import ProductExportFormat
from ..stix_validation import validate_stix_bundle
from .audit import audit
from .product_views import product_view


@dataclass(frozen=True, slots=True)
class ProductExport:
    filename: str
    media_type: str
    content: str
    bundle: dict[str, Any] | None = None


def export_product(
    db: Session,
    case_id: str,
    fmt: ProductExportFormat,
    *,
    max_tlp: str | None = None,
    version: int | None = None,
) -> ProductExport:
    """``LookupError`` for a hidden product or version; ``ValueError`` for a STIX export with nothing in
    it."""
    # The renderers use the Markdown helpers of ``briefing``, which imports this package: import them here.
    from ..product_markdown import to_markdown
    from ..product_stix import to_stix

    product = product_view(db, case_id, max_tlp=max_tlp, version=version)
    bundle = None
    if fmt == 'stix':
        bundle = to_stix(product)
        validate_stix_bundle(bundle)
        content, media_type, extension = json.dumps(bundle), 'application/stix+json;version=2.1', 'json'
    else:
        content, media_type, extension = to_markdown(product), 'text/markdown; charset=utf-8', 'md'
    label = f'v{product["version"]}' if product['version'] else 'draft'
    detail = {'format': fmt, 'version': product['version'], 'tlp': product['tlp'], 'max_tlp': max_tlp}
    audit(db, 'case.export', product['id'], json.dumps(detail, sort_keys=True))
    return ProductExport(f'insight-product-{product["id"]}-{label}.{extension}', media_type, content, bundle)
