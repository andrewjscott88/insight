"""Command-line entry point: ``init``, ``serve``, ``migrate``, ``backup`` and ``export-iocs``."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import __version__

#: How IOC export fields are named on the command line, for error messages that match what the user typed.
EXPORT_OPTIONS = {
    'q': '--query',
    'status': '--status',
    'tlp': '--tlp',
    'include_superseded': '--include-superseded',
    'kinds': '--kind',
    'review_statuses': '--review-status',
    'max_tlp': '--max-tlp',
    'document_ids': '--document',
    'include_evidence': '--no-evidence',
    'defang': '--defang',
}
EXPORT_EXAMPLES = """\
export-iocs examples:
  insight export-iocs iocs.json                      all indicators except rejected mentions
  insight export-iocs share.json --max-tlp GREEN --review-status accepted --defang --no-evidence
  insight export-iocs hashes.json --kind md5 --kind sha1 --kind sha256 --kind sha512
  insight export-iocs report.json --document DOCUMENT_ID
  In Docker, write under /data, e.g. /data/iocs.json. Guide: docs/IOC_EXPORT.md
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='insight',
        description='Insight local intelligence workspace',
        epilog=EXPORT_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument(
        'command',
        choices=['init', 'serve', 'migrate', 'backup', 'export-iocs'],
        nargs='?',
        default='serve',
        help=(
            'init: create .env | serve: run (default) | migrate: upgrade the database | backup DEST | '
            'export-iocs DEST: write a JSON IOC export'
        ),
    )
    parser.add_argument('destination', nargs='?', help='backup/export-iocs: file to write (must not exist)')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=8080, type=int)
    export = parser.add_argument_group(
        'export-iocs options',
        'Values are case-insensitive. The file is created owner-only (0600) and never overwritten.',
    )
    export.add_argument(
        '--kind',
        action='append',
        metavar='KIND',
        help='indicator type: cve url domain ip md5 sha1 sha256 sha512 (repeatable; default: all)',
    )
    export.add_argument(
        '--review-status',
        action='append',
        metavar='REVIEW',
        help='review state of each mention: unreviewed accepted rejected '
        '(repeatable; default: unreviewed and accepted)',
    )
    export.add_argument(
        '--max-tlp',
        metavar='LABEL',
        help='include only reports at or below this label: CLEAR GREEN AMBER AMBER+STRICT RED '
        '(default: no limit)',
    )
    export.add_argument(
        '--defang', action='store_true', help='write hxxps://example[.]com style values, titles and evidence'
    )
    export.add_argument(
        '--no-evidence',
        action='store_true',
        help='leave out the report text around each indicator (recommended when sharing)',
    )
    export.add_argument(
        '--document',
        action='append',
        metavar='ID',
        help='only this report (repeatable; a report ID from the workspace or GET /api/documents)',
    )
    export.add_argument(
        '--query', default='', metavar='TEXT', help='only reports matching this inbox search text'
    )
    export.add_argument(
        '--status', metavar='TRIAGE', help='only reports with this triage status: new reviewing reviewed'
    )
    export.add_argument(
        '--tlp', metavar='LABEL', help='only reports with exactly this label (for a ceiling use --max-tlp)'
    )
    export.add_argument(
        '--include-superseded', action='store_true', help='also include superseded revisions of synced items'
    )
    return parser


def init_env(path: Path) -> bool:
    """Create ``path`` with fresh credentials (mode 0600). Returns ``False`` if it already exists."""
    try:
        # Exclusive creation: never overwrite credentials.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        file.write(
            f'INSIGHT_PASSWORD={secrets.token_urlsafe(18)}\n'
            f'INSIGHT_SESSION_SECRET={secrets.token_urlsafe(48)}\n'
        )
    return True


def configure_logging(level: int = logging.INFO) -> None:
    """Send Insight's own log records (sign-ins, migrations, TLP raises) to stderr.

    Uvicorn only configures its own loggers; without this, INFO records from ``insight.*`` were dropped and
    only warnings reached the console through Python's last-resort handler.
    """
    logger = logging.getLogger('insight')
    if not any(getattr(h, 'insight_handler', False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)-8s %(name)s: %(message)s'))
        handler.insight_handler = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def load_env_file() -> None:
    from dotenv import load_dotenv  # Only needed for server-side commands.

    # Explicit path: a bare load_dotenv() searches upward from *this module's* directory, which for a
    # regular (non-editable) install is site-packages, so ./.env would silently be ignored.
    # Existing environment variables take precedence over the file (override=False).
    load_dotenv(Path.cwd() / '.env', override=False)


def migrate() -> str:
    """Apply pending migrations to the configured database; returns a status line."""
    from .config import database_url_from_env  # Deferred: keep `insight --version`/`init` lightweight.
    from .migrations import current_revision, head_revision, upgrade
    from .models import database

    load_env_file()
    configure_logging()
    engine, _ = database(database_url_from_env(), migrate=False)
    try:
        before = current_revision(engine)
        database_url = engine.url.render_as_string(hide_password=True)
        upgrade(engine)
        after = current_revision(engine)
    finally:
        engine.dispose()
    if before == after:
        return f'{database_url}: already at revision {after} (head {head_revision()}).'
    return f'{database_url}: upgraded {before or "unversioned"} -> {after}.'


def backup(destination: Path) -> str:
    """Consistent online copy of the SQLite database (safe while the server is running)."""
    import sqlite3  # Deferred imports keep `insight --version`/`init` lightweight.

    from sqlalchemy import make_url

    from .config import database_url_from_env

    load_env_file()
    url = make_url(database_url_from_env())
    if url.get_backend_name() != 'sqlite' or not url.database or url.database == ':memory:':
        raise ValueError('insight backup supports SQLite files only; use pg_dump for PostgreSQL.')
    source_path = Path(url.database)
    if not source_path.is_file():
        raise ValueError(f'No database at {source_path}')
    # Exclusive create: never overwrite an existing backup.
    os.close(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    source = sqlite3.connect(f'file:{source_path}?mode=ro', uri=True)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
        status = target.execute('PRAGMA integrity_check').fetchone()[0]
    finally:
        source.close()
        target.close()
    if status != 'ok':
        raise ValueError(f'Backup integrity check failed: {status}')
    return f'Backed up {source_path} to {destination} (integrity ok).'


def export_iocs(destination: Path, filters: Mapping[str, Any]) -> str:
    """Write a cross-report IOC export (``insight-ioc-v1``) to ``destination``; never overwrites.

    The file is created with mode 0600 because it carries TLP-labelled data. Read-only apart from the
    ``ioc.export`` audit event; the schema must already be current (``insight migrate``).
    """
    import json  # Deferred imports keep `insight --version`/`init` lightweight.

    from pydantic import ValidationError
    from sqlalchemy import make_url

    from . import services
    from .config import database_url_from_env
    from .migrations import current_revision, head_revision
    from .models import database
    from .schemas import IocExportQuery, validation_message

    try:
        query = IocExportQuery.model_validate(dict(filters))
    except ValidationError as exc:
        raise ValueError(validation_message(exc, EXPORT_OPTIONS)) from exc
    load_env_file()
    database_url = database_url_from_env()
    url = make_url(database_url)
    if url.get_backend_name() == 'sqlite' and (
        not url.database or url.database == ':memory:' or not Path(url.database).is_file()
    ):
        raise ValueError(f'No database at {url.database or "(in-memory)"}')
    engine, sessions = database(database_url, migrate=False)
    try:
        if current_revision(engine) != head_revision():
            raise ValueError('The database schema is not current; run `insight migrate` first.')
        try:  # Exclusive create: never overwrite an existing file.
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ValueError(
                f'{destination} already exists; exports never overwrite, choose a new name'
            ) from exc
        except OSError as exc:
            raise ValueError(
                f'cannot create {destination}: {exc.strerror or exc}. Choose a writable directory '
                '(in Docker: /data).'
            ) from exc
        written = False
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as file, sessions.begin() as db:
                result = services.export_iocs(db, query)
                json.dump(result, file, ensure_ascii=False, indent=2)
                file.write('\n')
                file.flush()  # Surface write errors before the audit event is committed.
            written = True
        except OSError as exc:
            raise ValueError(f'could not write {destination}: {exc.strerror or exc}') from exc
        finally:
            if not written:
                destination.unlink(missing_ok=True)
    finally:
        engine.dispose()
    return export_summary(result, destination)


def _plural(count: int, noun: str) -> str:
    return f'{count} {noun}' if count == 1 else f'{count} {noun}s'


def export_summary(result: Mapping[str, Any], destination: Path) -> str:
    """The line ``insight export-iocs`` prints: what was written and at which label to handle it."""
    counts = result['counts']
    defanged = ', defanged' if result['defanged'] else ''
    line = (
        f'Exported {_plural(counts["iocs"], "IOC")} ({_plural(counts["mentions"], "mention")}) from '
        f'{_plural(counts["documents"], "report")} to {destination} (TLP:{result["tlp"]}{defanged}). '
        'Handle the file according to that label.'
    )
    if not counts['iocs']:
        line += (
            ' Nothing matched the filters (rejected mentions and superseded revisions are left out by'
            ' default; --review-status accepted needs accepted mentions).'
        )
    return line


def serve(host: str, port: int) -> None:
    load_env_file()
    configure_logging()
    import uvicorn

    uvicorn.run(
        'insight.main:create_app',
        factory=True,
        host=host,
        port=port,
        workers=1,
        proxy_headers=False,
        log_level='info',
    )


def export_filters(args: argparse.Namespace) -> dict[str, Any]:
    """``IocExportQuery`` fields from the command line; TLP labels and kinds are case-insensitive here."""
    filters: dict[str, Any] = {
        'q': args.query,
        'status': args.status.lower() if args.status else None,
        'tlp': args.tlp.upper() if args.tlp else None,
        'max_tlp': args.max_tlp.upper() if args.max_tlp else None,
        'include_superseded': args.include_superseded,
        'defang': args.defang,
        'include_evidence': not args.no_evidence,
    }
    if args.kind:
        filters['kinds'] = [kind.lower() for kind in args.kind]
    if args.review_status:
        filters['review_statuses'] = [status.lower() for status in args.review_status]
    if args.document:
        filters['document_ids'] = args.document
    return filters


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == 'init':
        if not init_env(Path('.env')):
            print('.env already exists; refusing to overwrite existing credentials.', file=sys.stderr)
            return 1
        print('Created .env. Read INSIGHT_PASSWORD there to sign in. Keep this file private.')
        return 0
    if args.command == 'migrate':
        print(migrate())
        return 0
    if args.command == 'backup':
        if not args.destination:
            print('usage: insight backup DEST', file=sys.stderr)
            return 2
        try:
            print(backup(Path(args.destination)))
        except (ValueError, FileExistsError) as exc:
            print(f'Backup failed: {exc}', file=sys.stderr)
            return 1
        return 0
    if args.command == 'export-iocs':
        if not args.destination:
            print('usage: insight export-iocs DEST [options]; see `insight --help`', file=sys.stderr)
            return 2
        try:
            print(export_iocs(Path(args.destination), export_filters(args)))
        except (ValueError, FileExistsError) as exc:
            print(f'Export failed: {exc}', file=sys.stderr)
            return 1
        return 0
    serve(args.host, args.port)
    return 0


if __name__ == '__main__':
    sys.exit(main())
