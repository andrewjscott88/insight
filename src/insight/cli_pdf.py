"""Import a local PDF advisory through the report service."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy.exc import IntegrityError

from . import services
from .cli import _current_database
from .config import parse_max_tlp
from .pdf_import import MAX_PDF_BYTES
from .schemas import TLP_LEVELS


def run_pdf(argv: Sequence[str]) -> str:
    parser = argparse.ArgumentParser(prog='insight import-pdf', description='Import text from a local PDF.')
    parser.add_argument('file', type=Path, help='PDF file, up to 2 megabytes')
    parser.add_argument('--title', help='report title (default: file name without its extension)')
    parser.add_argument('--source-name', default='Local PDF', help='publisher or source (default: Local PDF)')
    parser.add_argument('--source-url', default='', help='source web address (optional)')
    parser.add_argument('--tlp', type=str.upper, choices=TLP_LEVELS, default='AMBER', help='handling label')
    args = parser.parse_args(argv)
    with args.file.open('rb') as source:
        data = source.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        raise ValueError('Choose a PDF of 2 megabytes or less.')
    ceiling = parse_max_tlp(os.getenv('INSIGHT_MAX_TLP', ''))
    # Parse before opening the database: the sandboxed parse can take up to 10 s.
    report = services.prepare_pdf_report(
        data,
        title=args.file.stem if args.title is None else args.title,
        source_name=args.source_name,
        source_url=args.source_url,
        tlp=args.tlp,
        max_tlp=ceiling,
    )
    try:
        with _current_database() as sessions, sessions.begin() as db:
            services.set_actor(db, 'cli')
            result = services.store_pdf_report(db, report, max_tlp=ceiling)
    except IntegrityError as exc:
        raise ValueError('Concurrent import; retry once') from exc
    action = 'Imported' if result['created'] else 'Already imported'
    return f'{action} PDF as report {result["document_id"]}. SHA-256 {result["file_sha256"]}'
