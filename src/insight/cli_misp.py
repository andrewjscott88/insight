"""Host CLI entry points for exchanging a single MISP event."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from . import services
from .cli import _current_database
from .config import parse_max_tlp
from .misp_export import export_misp_event
from .misp_import import MAX_MISP_BYTES, import_misp_event, parse_misp_event
from .misp_remote import exchange
from .models import SessionFactory
from .schemas import TLP, TLP_LEVELS


def _parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f'insight {command}')
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument('file', type=Path, nargs='?', help='one MISP event JSON file')
    parser.add_argument('--allow-red', action='store_true', help='permit RED when INSIGHT_MAX_TLP=RED')
    parser.add_argument(
        '--max-tlp', choices=TLP_LEVELS, type=str.upper, help='limit the event handling label'
    )
    if command == 'misp-export':
        destination.add_argument(
            '--push', action='store_true', help='create an unpublished event on INSIGHT_MISP_URL'
        )
        parser.add_argument(
            '--document', action='append', default=[], metavar='ID', help='select a report (repeatable)'
        )
        parser.add_argument(
            '--include-unreviewed',
            action='store_true',
            help='also approve unreviewed observations for this export',
        )
        parser.add_argument('--include-personal-data', action='store_true', help='include e-mail indicators')
        parser.add_argument(
            '--include-evidence',
            action='store_true',
            help='include a permitted, defanged excerpt per indicator',
        )
    else:
        destination.add_argument(
            '--fetch', metavar='UUID', help='fetch this event UUID from INSIGHT_MISP_URL'
        )
    return parser


def _ceiling(requested: str | None, allow_red: bool) -> TLP:
    try:
        site = parse_max_tlp(os.environ.get('INSIGHT_MAX_TLP', ''))
        wanted = parse_max_tlp(requested) if requested else site
    except RuntimeError:
        raise ValueError('Invalid INSIGHT_MAX_TLP') from None
    if allow_red and site != 'RED':
        raise ValueError('--allow-red requires INSIGHT_MAX_TLP=RED')
    limit = min(site, wanted, key=TLP_LEVELS.index)
    return 'AMBER+STRICT' if limit == 'RED' and not allow_red else limit


def _export(sessions: SessionFactory, args: argparse.Namespace, ceiling: TLP) -> str:
    created: Path | None = None
    try:
        with sessions.begin() as db:
            services.set_actor(db, 'cli')
            result = export_misp_event(
                db,
                max_tlp=ceiling,
                allow_red=args.allow_red,
                document_ids=args.document,
                include_unreviewed=args.include_unreviewed,
                include_evidence=args.include_evidence,
                include_personal_data=args.include_personal_data,
            )
            event = result['Event']
            payload = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
            parse_misp_event(payload)  # The same byte, body and indicator limits apply in both directions.
            if args.file:
                fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created = args.file
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(payload)
        if args.push:
            try:
                asyncio.run(exchange(event_uuid=event['uuid'], body=payload))
            except ValueError as exc:
                raise ValueError(f'{exc} (event {event["uuid"]})') from None
            with sessions.begin() as db:
                services.set_actor(db, 'cli')
                services.audit(db, 'misp.push', event['uuid'])
    except BaseException:
        if created is not None:
            created.unlink(missing_ok=True)
        raise
    outcome = 'Created unpublished MISP event' if args.push else 'Wrote MISP event'
    label = event['Tag'][0]['name'].upper()
    return f'{outcome} {event["uuid"]} ({len(event["Attribute"])} attributes, {label}).'


def _import(sessions: SessionFactory, args: argparse.Namespace, ceiling: TLP) -> str:
    if args.fetch:
        payload = asyncio.run(exchange(event_uuid=args.fetch))
    else:
        with args.file.open('rb') as stream:
            payload = stream.read(MAX_MISP_BYTES + 1)
    # A concurrent copy may win the fingerprint/current-revision constraint. Re-read committed state
    # in a fresh transaction, without fetching the remote event a second time.
    for attempt in range(2):
        try:
            with sessions.begin() as db:
                services.set_actor(db, 'cli')
                doc, created = import_misp_event(
                    db, payload, max_tlp=ceiling, allow_red=args.allow_red, expected_uuid=args.fetch
                )
                action = 'Imported' if created else 'Already imported'
                return f'{action} MISP event {doc.external_id} as report {doc.id} (TLP:{doc.tlp}).'
        except IntegrityError:
            if attempt:
                raise
    raise AssertionError('unreachable')  # pragma: no cover


def run_misp(command: str, argv: Sequence[str]) -> str:
    args = _parser(command).parse_args(argv)
    try:
        with _current_database() as sessions:
            ceiling = _ceiling(args.max_tlp, args.allow_red)
            return (
                _export(sessions, args, ceiling)
                if command == 'misp-export'
                else _import(sessions, args, ceiling)
            )
    except SQLAlchemyError:
        # Database driver errors may contain full indicator values and report parameters.
        raise ValueError('The database could not complete the MISP exchange') from None
