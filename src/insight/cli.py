"""Command line: ``init``, ``serve``, ``migrate``, ``backup``, ``export-iocs``, ``api-key``, ``mfa`` and more.

The threat guide commands (TIP 2.10) live in :mod:`insight.cli_threats`.
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__

if TYPE_CHECKING:
    from .models import SessionFactory

API_KEY_ACTIONS = ('create', 'rotate', 'revoke', 'status')
MFA_ACTIONS = ('setup', 'reset', 'status')
#: ``insight schedule SOURCE --every ...``: how often a source syncs by itself, in minutes.
SCHEDULE_EVERY = {'off': 0, '1h': 60, '6h': 360, '24h': 1440}
#: Attempts to type the first code when enrolling an authenticator app.
MFA_ENROL_ATTEMPTS = 3

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
  insight export-stix bundle.json --max-tlp GREEN --review-status accepted
  In Docker, write under /data, e.g. /data/iocs.json. Guide: docs/IOC_EXPORT.md

api-key examples (one key at a time; the key is printed once, only its hash is stored):
  insight api-key create --name siem                 read-only key, expires in 90 days
  insight api-key create --name scripts --access read-write --expires-days 30
  insight api-key status                             key ID, access, expiry and last use (never the key)
  insight api-key rotate                             replace the key (the old one stops working at once)
  insight api-key revoke
  insight api-key create --name siem --max-tlp GREEN   a key that never sees AMBER or RED reports
  In Docker: docker compose exec insight insight api-key create --name siem. Guide: docs/API.md

mfa (sign-in second factor: a code from an authenticator app; off by default):
  insight mfa setup       pair an app: shows a secret for it, then asks for one code to confirm
  insight mfa status      whether MFA is on (INSIGHT_MFA) and whether an app is paired
  insight mfa reset       forget the paired app (e.g. a lost phone; needs shell access to the host)
  MFA is switched on and off with INSIGHT_MFA=on|off in .env. With Docker: make mfa-enable / make mfa-disable
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
        choices=[
            'init',
            'serve',
            'migrate',
            'backup',
            'export-iocs',
            'export-stix',
            'api-key',
            'mfa',
            'schedule',
            'notify',
            'import-stix',
            'import-pdf',
            'delete-report',
            'attack-backfill',
            'threat-library-sync',
            'industries',
            'threat-profile',
            'threat-guide',
            'rule-add',
            'misp-export',
            'misp-import',
        ],
        nargs='?',
        default='serve',
        help=(
            'init: create .env | serve: run (default) | migrate: upgrade the database | backup DEST | '
            'export-iocs DEST: write a JSON IOC export | export-stix DEST: write a STIX 2.1 bundle | '
            'api-key ACTION: manage the API key | '
            'mfa ACTION: pair the sign-in authenticator app | '
            'schedule [SOURCE|all --every off|1h|6h|24h]: show or set scheduled syncs | '
            'notify [list|add|enable|disable|remove]: manage alert destinations | '
            'import-stix FILE: import a STIX 2.1 JSON bundle | '
            'import-pdf FILE: add a local PDF advisory (see import-pdf --help) | '
            'delete-report ID --reason TEXT: delete one report for legal or retention reasons | '
            'attack-backfill: tag the ATT&CK techniques written in reports stored before 0.7.0 | '
            'threat-library-sync: fetch the full pinned threat library | industries | '
            'threat-profile INDUSTRY: the top ten groups | threat-guide REF DEST: write a threat guide | '
            'rule-add FILE: store a YARA or Sigma rule | '
            'misp-export / misp-import: exchange a MISP event (see command --help)'
        ),
    )
    parser.add_argument(
        'destination',
        nargs='?',
        help='backup and export commands: new file to write | api-key: create, rotate, revoke or '
        'status | mfa: setup, reset or status | schedule: a source key, or all | delete-report: a report ID '
        '| threat-profile: an industry key | threat-guide: a group (G0016) or actor ID '
        '| rule-add: a rule file',
    )
    # Not ``target``: ``notify --target`` uses that name (dest), and a positional would overwrite it.
    parser.add_argument(
        'output', nargs='?', metavar='FILE', help='threat-guide: the file to write (must not exist)'
    )
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=8080, type=int)
    export = parser.add_argument_group(
        'export-iocs and export-stix options',
        'Values are case-insensitive. The file is created owner-only (0600) and never overwritten.',
    )
    export.add_argument(
        '--kind',
        action='append',
        metavar='KIND',
        help='indicator type: cve url domain ip cidr email md5 sha1 sha256 sha512 (repeatable; default: all)',
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
        '(default: no limit). With api-key create/rotate: the most restrictive label the key may read '
        'or write (default: no limit beyond INSIGHT_MAX_TLP; rotate keeps the current one)',
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
    parser.add_argument(
        '--every',
        choices=list(SCHEDULE_EVERY),
        help='schedule: how often the source syncs by itself while `insight serve` runs (off: when asked)',
    )
    parser.add_argument(
        '--at',
        metavar='HH:MM',
        help='schedule: the time of day (UTC) the syncs start from, e.g. 00:00 (default: within a minute)',
    )
    removal = parser.add_argument_group(
        'delete-report options',
        'Deletes the report, its observations and notes, and indicators no other report mentions (with their '
        'verdicts). Take a backup first: there is no undo.',
    )
    removal.add_argument(
        '--reason',
        metavar='TEXT',
        help='delete-report: why, e.g. a ticket number (required; kept in the audit log)',
    )
    removal.add_argument('--yes', action='store_true', help='delete-report: do not ask for confirmation')
    threats = parser.add_argument_group(
        'threat guide options',
        'threat-profile and threat-guide also take --max-tlp; rule-add takes --kind, --name and --tlp '
        "(the rule's own label, default AMBER).",
    )
    threats.add_argument(
        '--format',
        default='md',
        metavar='FORMAT',
        help='threat-guide: md json navigator sweep-csv sweep-json',
    )
    threats.add_argument(
        '--include-named',
        action='store_true',
        help='threat-guide: the sweep list also takes indicators from reports that only name the group '
        '(default: only reports linked to it)',
    )
    threats.add_argument(
        '--days', type=int, default=90, help='threat-profile: count reports from the last N days'
    )
    threats.add_argument(
        '--link',
        action='append',
        default=[],
        metavar='REF',
        help='rule-add: G0016, T1059.001, document:ID, cve:CVE-YYYY-NNNN or malware:NAME; repeatable',
    )
    threats.add_argument('--licence', default='', help="rule-add: the rule's licence, e.g. DRL-1.1")
    threats.add_argument(
        '--source-url', default='', metavar='URL', help='rule-add: where the rule came from (https)'
    )
    notify = parser.add_argument_group('notify options')
    notify.add_argument('--style', choices=['chat', 'json', 'email'], help='notify add: destination type')
    notify.add_argument(
        '--secret-out', type=Path, metavar='FILE', help='notify add: new private JSON signing key file'
    )
    notify.add_argument('--target', metavar='ID', help='notify enable/disable/remove: ID from notify list')
    keys = parser.add_argument_group('api-key and destination options')
    keys.add_argument(
        '--name',
        metavar='NAME',
        help='api-key create/rotate or notify add: a label for this key or destination',
    )
    keys.add_argument(
        '--access',
        choices=['read', 'read-write'],
        help='create/rotate: read = GET requests only (default on create) | read-write = also writes',
    )
    keys.add_argument(
        '--expires-days', type=int, default=90, metavar='DAYS', help='create/rotate: 1-365 (default: 90)'
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


def export_iocs(destination: Path, filters: Mapping[str, Any], *, stix: bool = False) -> str:
    """Write an audited, owner-only IOC export or STIX bundle, refusing to overwrite existing files."""
    import json  # Deferred imports keep `insight --version`/`init` lightweight.

    from pydantic import ValidationError

    from . import services
    from .config import parse_max_tlp
    from .schemas import IocExportQuery, validation_message

    try:
        query = IocExportQuery.model_validate(dict(filters))
    except ValidationError as exc:
        raise ValueError(validation_message(exc, EXPORT_OPTIONS)) from exc
    with _current_database() as sessions:
        if stix:
            instance_limit = parse_max_tlp(os.environ.get('INSIGHT_MAX_TLP', ''))
            query = query.model_copy(
                update={'max_tlp': services.stricter_limit(query.max_tlp, instance_limit)}
            )
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
                services.set_actor(db, 'cli')
                result = services.export_stix(db, query) if stix else services.export_iocs(db, query)
                json.dump(result, file, ensure_ascii=False, indent=2)
                file.write('\n')
                file.flush()  # Surface write errors before the audit event is committed.
            written = True
        except OSError as exc:
            raise ValueError(f'could not write {destination}: {exc.strerror or exc}') from exc
        finally:
            if not written:
                destination.unlink(missing_ok=True)
    if stix:
        return f'Exported {_plural(len(result.get("objects", [])), "STIX object")} to {destination}.'
    return export_summary(result, destination)


@contextmanager
def _current_database() -> Iterator[SessionFactory]:
    """The configured database, which must exist and be at the current schema (never migrated from here)."""
    from sqlalchemy import make_url

    from .config import database_url_from_env
    from .migrations import current_revision, head_revision
    from .models import database

    load_env_file()
    database_url = database_url_from_env()
    url = make_url(database_url)
    if url.get_backend_name() == 'sqlite' and (
        not url.database or url.database == ':memory:' or not Path(url.database).is_file()
    ):
        raise ValueError(
            f'No database at {url.database or "(in-memory)"}; run `insight migrate` or start Insight first'
        )
    engine, sessions = database(database_url, migrate=False)
    try:
        if current_revision(engine) != head_revision():
            raise ValueError('The database schema is not current; run `insight migrate` first.')
        yield sessions
    finally:
        engine.dispose()


def _describe_key(key: Any) -> str:
    access = 'read-only' if key.access == 'read' else 'read-write'
    visibility = f'TLP:{key.max_tlp} and below' if key.max_tlp else 'every label stored'
    return f'{key.key_id} "{key.name}" ({access}; sees {visibility}; expires {key.expires_at[:10]})'


def api_key(
    action: str, *, name: str | None, access: str | None, expires_days: int, max_tlp: str | None = None
) -> str:
    """Create, rotate, revoke or describe the API key. Returns what to print; raises ``ValueError``."""
    from . import services

    with _current_database() as sessions, sessions.begin() as db:
        services.set_actor(db, 'cli')
        if action == 'status':
            key = services.active_api_key(db)
            if key is None:
                return 'No active API key. Create one with `insight api-key create --name NAME`.'
            used = f'{key.last_used_at[:16]} (recorded every 5 minutes)' if key.last_used_at else 'never'
            return f'Active API key {_describe_key(key)}; created {key.created_at[:19]}, last used {used}.'
        if action == 'revoke':
            key = services.revoke_api_key(db)
            if key is None:
                return 'No active API key; nothing to revoke.'
            return f'Revoked API key {key.key_id}. Requests using it are refused from now on.'
        if action == 'create':
            key, token = services.create_api_key(
                db, name=name or '', access=access or 'read', expires_days=expires_days, max_tlp=max_tlp
            )
            verb = 'Created'
        else:
            key, token = services.rotate_api_key(
                db, name=name, access=access, expires_days=expires_days, max_tlp=max_tlp
            )
            verb = 'Rotated to'
    return (
        f'{verb} API key {_describe_key(key)}.\n'
        'Copy it now: it is shown only once and cannot be recovered (only a hash is stored).\n\n'
        f'{token}\n\n'
        'Send it as the header  Authorization: Bearer <key>'
    )


def _mfa_switch() -> bool:
    """``INSIGHT_MFA`` as the server reads it (``.env`` and the environment); ``ValueError`` if invalid."""
    from .config import parse_mfa

    try:
        return parse_mfa(os.environ.get('INSIGHT_MFA', ''))
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc


def schedule(source: str | None, every: str | None, at: str | None = None) -> str:
    """Show every source's schedule, after setting ``source`` (a key, or ``all``) to ``every`` if given.

    Raises ``ValueError`` for an unknown source or a missing ``--every``. Audited as ``schedule.update`` by
    ``cli``.
    """
    from datetime import UTC, datetime

    from . import services
    from .source_registry import SOURCES, in_use

    labels = {minutes: name for name, minutes in SCHEDULE_EVERY.items()}
    with _current_database() as sessions:
        if source is not None:
            if every is None:
                raise ValueError(f'say how often: --every {"|".join(SCHEDULE_EVERY)}')
            keys = list(SOURCES) if source == 'all' else [source]
            if any(key not in SOURCES for key in keys):
                raise ValueError(f'unknown source {source!r}; use all or one of: {", ".join(SOURCES)}')
            now = datetime.now(UTC)
            starts_at = services.time_of_day(at, now) if at else None
            with sessions.begin() as db:
                services.set_actor(db, 'cli')
                switches = services.source_switches(db)
                if source == 'all':  # every source in use; switched-off sources stay off
                    keys = [key for key in keys if in_use(SOURCES[key], switches)]
                elif SCHEDULE_EVERY[every] and not in_use(SOURCES[source], switches):
                    raise ValueError(f'{source} is switched off; switch it on in the Sources tab first')
                for key in keys:
                    services.set_schedule(db, key, SCHEDULE_EVERY[every], at=now, starts_at=starts_at)
        with sessions() as db:
            stored = services.list_schedules(db)
            lines = []
            for key in SOURCES:
                s = stored.get(key)
                if s is not None and s.enabled and s.next_run_at:
                    when = s.next_run_at[:16].replace('T', ' ')
                    lines.append(f'{key}: every {labels[s.interval_minutes]}; next sync {when} UTC')
                elif not in_use(SOURCES[key], services.source_switches(db)):
                    lines.append(f'{key}: switched off (Insight does not contact it)')
                else:
                    lines.append(f'{key}: off (syncs only when asked)')
    lines.append('Scheduled syncs run inside `insight serve` while INSIGHT_RUN_JOBS is on (the default).')
    return '\n'.join(lines)


def mfa(action: str, read_code: Callable[[str], str] | None = None) -> str:
    """Pair (interactively), reset or describe the sign-in authenticator app; raises ``ValueError``.

    Pairing is separate from the switch that requires a code at sign-in (``INSIGHT_MFA``, off by default; the
    Makefile's ``mfa-enable``/``mfa-disable`` set it). ``read_code`` asks for the code the app shows (default:
    ``input``, looked up per call).
    """
    from . import services, totp

    read = read_code or input
    with _current_database() as sessions:
        switch_on = _mfa_switch()
        with sessions() as db:
            paired = services.mfa_paired(db)
        if action == 'status':
            state = 'on' if switch_on else 'off'
            app = 'An authenticator app is paired' if paired else 'No authenticator app is paired'
            if switch_on and not paired:
                effect = 'sign-in is LOCKED until an app is paired (make mfa-enable, or insight mfa setup)'
            elif switch_on:
                effect = 'sign-in needs the password and a code from the app'
            else:
                effect = 'sign-in needs the password only (make mfa-enable turns MFA on)'
            return f'MFA is {state} (INSIGHT_MFA={state}). {app}: {effect}.'
        if action == 'reset':
            with sessions.begin() as db:
                services.set_actor(db, 'cli')
                removed = services.reset_mfa(db)
            if not removed:
                return 'No authenticator app was paired; nothing to reset.'
            if switch_on:
                return (
                    'Authenticator app forgotten. MFA is still on, so sign-in is locked until you pair a new '
                    'app (make mfa-enable, or insight mfa setup) or turn MFA off (make mfa-disable).'
                )
            return 'Authenticator app forgotten. MFA is off: sign-in needs the password only.'
        if paired:
            return (
                'An authenticator app is already paired; keeping it. To pair a different one: '
                'insight mfa reset, then insight mfa setup.'
            )
        secret = totp.generate_secret()
        grouped = ' '.join(secret[i : i + 4] for i in range(0, len(secret), 4))
        print(
            'Add Insight to your authenticator app (Google Authenticator, Microsoft Authenticator, '
            '1Password, Aegis, Bitwarden, ...):\n'
            f'  Secret key (enter manually, type "time-based"): {grouped}\n'
            f'  Or this URI (paste it, or turn it into a QR code locally): {totp.provisioning_uri(secret)}\n'
            'Keep the secret private: anyone who has it can generate codes.'
        )
        for _ in range(MFA_ENROL_ATTEMPTS):
            step = totp.matching_step(secret, read('Code shown by the app: '))
            if step is not None:
                with sessions.begin() as db:
                    services.set_actor(db, 'cli')
                    services.pair_mfa(db, secret, step)
                if switch_on:
                    return 'Authenticator app paired. MFA is on: sign-in asks for the password and a code.'
                return (
                    'Authenticator app paired. MFA is still off until INSIGHT_MFA=on '
                    '(make mfa-enable sets it and restarts Insight).'
                )
            print("That code does not match; check the phone's clock and try the next code.", file=sys.stderr)
    raise ValueError('no matching code; no authenticator app was paired (nothing was saved)')


def attack_backfill() -> str:
    """Tag the ATT&CK technique IDs written in reports stored before technique tagging existed (0.7.0).

    Safe to run again: reports that already have technique rows are left alone. Audited as
    ``technique.backfill`` by ``cli``.
    """
    from . import services

    with _current_database() as sessions, sessions.begin() as db:
        services.set_actor(db, 'cli')
        reports, added = services.backfill_techniques(db)
    return f'Read {_plural(reports, "report")} without technique tags; added {_plural(added, "tag")}.'


def delete_report(document_id: str, reason: str, confirm: Callable[[str], bool] | None = None) -> str:
    """Delete one report (``services.delete_document``), after ``confirm`` agrees to the summary it is shown.

    Raises ``ValueError`` for an unknown ID or a missing reason. Audited as ``document.delete`` by ``cli``.
    """
    from . import services

    if not reason.strip():
        raise ValueError('say why: --reason "ticket 1234: retention period ended"')
    with _current_database() as sessions:
        with sessions() as db:
            preview = services.deletion_preview(db, document_id)
        if preview is None:
            raise ValueError(f'no report with ID {document_id}')
        summary = (
            f'{preview.title}\n'
            f'  TLP:{preview.tlp} · {preview.source_name} · added {preview.created_at[:10]}\n'
            f'  {_plural(preview.observations, "observation")} and {_plural(preview.notes, "note")} '
            'are deleted with it'
        )
        if preview.revisions:
            summary += f'; {_plural(preview.revisions, "other revision")} of this item stay'
        if confirm is not None and not confirm(summary):
            return 'Cancelled; nothing was deleted.'
        try:
            with sessions.begin() as db:
                services.set_actor(db, 'cli')
                result = services.delete_document(db, document_id, reason)
        except LookupError as exc:
            raise ValueError(str(exc)) from exc
    lines = [
        f'Deleted report {document_id}: {_plural(result.observations, "observation")}, '
        f'{_plural(result.notes, "note")}, {_plural(result.entities, "indicator")} no other report mentions '
        f'and {_plural(result.verdicts, "verdict")} on them. Audited as document.delete.',
    ]
    if result.now_current:
        lines.append(f'Revision {result.now_current} of the same item is current again.')
    if preview.source_key:
        lines.append(
            f'It came from the {preview.source_key} source: if the publisher still lists the item and the '
            'feed changes, the next sync adds it again.'
        )
    lines.append('Backups taken before now still contain the report; apply your retention policy to them.')
    return '\n'.join(lines)


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
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['import-pdf']:
        from .cli_pdf import run_pdf

        try:
            print(run_pdf(argv[1:]))
        except (ValueError, OSError, RuntimeError) as exc:
            print(f'PDF import failed: {exc}', file=sys.stderr)
            return 1
        return 0
    if argv[:1] in (['misp-export'], ['misp-import']):
        from .cli_misp import run_misp

        try:
            print(run_misp(argv[0], argv[1:]))
        except (ValueError, OSError) as exc:
            print(f'MISP exchange failed: {exc}', file=sys.stderr)
            return 1
        return 0
    args = build_parser().parse_args(argv)
    if args.command in ('misp-export', 'misp-import', 'import-pdf'):
        print(f'usage: insight {args.command} [OPTIONS]; place options after the command', file=sys.stderr)
        return 2
    if args.command == 'init':
        if not init_env(Path('.env')):
            print('.env already exists; refusing to overwrite existing credentials.', file=sys.stderr)
            return 1
        print('Created .env. Read INSIGHT_PASSWORD there to sign in. Keep this file private.')
        return 0
    if args.command == 'migrate':
        print(migrate())
        return 0
    if args.command == 'import-stix':
        from sqlalchemy.exc import IntegrityError

        from . import services
        from .config import parse_max_tlp
        from .stix_import import MAX_BUNDLE_BYTES

        if not args.destination:
            print('usage: insight import-stix FILE', file=sys.stderr)
            return 2
        try:
            with Path(args.destination).open('rb') as source:
                data = source.read(MAX_BUNDLE_BYTES + 1)
            with _current_database() as sessions, sessions.begin() as db:
                services.set_actor(db, 'cli')
                result = services.import_stix(
                    db, data, max_tlp=parse_max_tlp(os.getenv('INSIGHT_MAX_TLP', ''))
                )
            print(
                f'Imported {result["reports"]} report(s), {result["created"]} new revision(s). '
                f'SHA-256 {result["bundle_sha256"]}'
            )
        except IntegrityError:
            print('Concurrent import; retry once', file=sys.stderr)
            return 1
        except (OSError, ValueError, RuntimeError) as exc:
            print(f'Import failed: {exc}', file=sys.stderr)
            return 1
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
    if args.command in ('export-iocs', 'export-stix'):
        if not args.destination:
            print(f'usage: insight {args.command} DEST [options]; see `insight --help`', file=sys.stderr)
            return 2
        try:
            print(
                export_iocs(Path(args.destination), export_filters(args), stix=args.command == 'export-stix')
            )
        except (ValueError, FileExistsError, RuntimeError) as exc:
            print(f'Export failed: {exc}', file=sys.stderr)
            return 1
        return 0
    if args.command == 'api-key':
        if args.destination not in API_KEY_ACTIONS:
            print(f'usage: insight api-key {{{",".join(API_KEY_ACTIONS)}}} [options]', file=sys.stderr)
            return 2
        if args.destination == 'create' and not args.name:
            print('usage: insight api-key create --name NAME [--access read|read-write]', file=sys.stderr)
            return 2
        try:
            print(
                api_key(
                    args.destination,
                    name=args.name,
                    access=args.access,
                    expires_days=args.expires_days,
                    max_tlp=args.max_tlp.upper() if args.max_tlp else None,
                )
            )
        except ValueError as exc:
            print(f'API key: {exc}', file=sys.stderr)
            return 1
        return 0
    if args.command == 'mfa':
        if args.destination not in MFA_ACTIONS:
            print(f'usage: insight mfa {{{",".join(MFA_ACTIONS)}}}', file=sys.stderr)
            return 2
        try:
            print(mfa(args.destination))
        except ValueError as exc:
            print(f'MFA: {exc}', file=sys.stderr)
            return 1
        except (EOFError, KeyboardInterrupt):
            print('\nCancelled; no authenticator app was paired (nothing was saved).', file=sys.stderr)
            return 1
        return 0
    if args.command == 'notify':
        from .cli_notify import manage_destination

        try:
            with _current_database() as sessions:
                print(
                    manage_destination(
                        sessions,
                        args.destination or 'list',
                        name=args.name,
                        style=args.style,
                        target_id=args.target,
                        max_tlp=args.max_tlp,
                        secret_out=args.secret_out,
                    )
                )
        except (EOFError, KeyboardInterrupt):
            print('Cancelled.', file=sys.stderr)
            return 1
        except FileExistsError:
            print('Alert destination: the key file already exists. Choose a new file.', file=sys.stderr)
            return 1
        except (OSError, ValueError) as exc:
            print(f'Alert destination: {exc}', file=sys.stderr)
            return 1
        return 0
    if args.command == 'schedule':
        try:
            print(schedule(args.destination, args.every, args.at))
        except ValueError as exc:
            print(f'Schedule: {exc}', file=sys.stderr)
            return 1
        return 0
    if args.command == 'attack-backfill':
        print(attack_backfill())
        return 0
    if args.command == 'delete-report':
        if not args.destination or not args.reason:
            print('usage: insight delete-report ID --reason TEXT [--yes]', file=sys.stderr)
            return 2
        try:
            print(delete_report(args.destination, args.reason, None if args.yes else _ask_to_delete))
        except ValueError as exc:
            print(f'Delete report: {exc}', file=sys.stderr)
            return 1
        except (EOFError, KeyboardInterrupt):
            print('\nCancelled; nothing was deleted.', file=sys.stderr)
            return 1
        return 0
    if args.command in THREAT_COMMANDS:
        return _threat_command(args)
    serve(args.host, args.port)
    return 0


THREAT_COMMANDS = ('threat-library-sync', 'industries', 'threat-profile', 'threat-guide', 'rule-add')


def _threat_command(args: argparse.Namespace) -> int:
    from . import cli_threats

    max_tlp = args.max_tlp.upper() if args.max_tlp else None
    usage = {
        'threat-profile': 'insight threat-profile INDUSTRY [--max-tlp LABEL] [--days N]',
        'threat-guide': (
            'insight threat-guide REF DEST [--format md|json|navigator|sweep-csv|sweep-json] '
            '[--include-named]'
        ),
        'rule-add': 'insight rule-add FILE --kind yara|sigma [--name N] [--link REF] [--tlp LABEL]',
    }
    if args.command in usage and (
        not args.destination or (args.command == 'threat-guide' and not args.output)
    ):
        print(f'usage: {usage[args.command]}', file=sys.stderr)
        return 2
    try:
        if args.command == 'threat-library-sync':
            print(cli_threats.threat_library_sync())
        elif args.command == 'industries':
            print(cli_threats.industries(max_tlp))
        elif args.command == 'threat-profile':
            print(cli_threats.threat_profile(args.destination, max_tlp, args.days))
        elif args.command == 'threat-guide':
            print(
                cli_threats.threat_guide(
                    args.destination, Path(args.output), args.format, max_tlp, args.include_named
                )
            )
        else:
            kind = (args.kind or [''])[0].lower()
            tlp = args.tlp.upper() if args.tlp else 'AMBER'
            print(
                cli_threats.rule_add(
                    Path(args.destination),
                    kind,
                    args.name or '',
                    args.link,
                    tlp,
                    args.licence,
                    args.source_url,
                )
            )
    except ValueError as exc:
        print(f'{args.command}: {exc}', file=sys.stderr)
        return 1
    return 0


def _ask_to_delete(summary: str) -> bool:
    print(f'This deletes, with no undo:\n  {summary}')
    return input('Type delete to go ahead: ').strip().lower() == 'delete'


if __name__ == '__main__':
    sys.exit(main())
