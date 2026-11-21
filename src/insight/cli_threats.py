"""Command line for industry threat profiles and actor threat guides (TIP 2.10, ADR 0025).

``threat-library-sync``, ``industries``, ``threat-profile INDUSTRY``, ``threat-guide REF DEST`` and
``rule-add FILE``. Reads act as an unlimited reader unless ``--max-tlp`` is given; files are created
owner-only (0600) and never overwritten; every export and change is audited as ``cli``.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

GUIDE_FORMATS: Final = ('md', 'json', 'navigator', 'sweep-csv', 'sweep-json')


def threat_library_sync() -> str:
    """Fetch the pinned ATT&CK and MISP galaxy releases and write the full threat library."""
    from .threat_library import reload, synced_path
    from .threat_library_sync import PINNED, sync_library

    target = synced_path()
    try:
        library = asyncio.run(sync_library(target))
    except (OSError, ValueError) as exc:
        raise ValueError(f'{exc}. The bundled threat library is still used.') from exc
    loaded = reload()
    claims = sum(len(c['industries']) for g in library['groups'] for c in g['industries'])
    pinned = ', '.join(f'{p.name} {p.version}' for p in PINNED.values())
    return (
        f'Wrote the full threat library to {target} from {pinned} (SHA-256 checked): '
        f'{len(library["groups"])} groups, {claims} industry claims. Insight now uses it ({loaded.edition} '
        'edition); restart a running server to load it there.'
    )


def industries(max_tlp: str | None = None) -> str:
    from . import services
    from .cli import _current_database
    from .industries import INDUSTRIES
    from .threat_library import library

    with _current_database() as sessions, sessions() as db:
        counts = services.industry_counts(db, max_tlp=max_tlp)
    lib = library()
    lines = [f'Threat library: {lib.edition} edition, ATT&CK {lib.attack_version}.']
    lines += [f'  {i.key:<20} {counts[i.key]:>4} groups  {i.name}' for i in INDUSTRIES]
    lines.append('Show the top ten for one: insight threat-profile KEY')
    return '\n'.join(lines)


def threat_profile(industry: str, max_tlp: str | None = None, days: int = 90) -> str:
    from . import services
    from .cli import _current_database

    with _current_database() as sessions, sessions() as db:
        try:
            profile = services.industry_profile(
                db, industry, max_tlp=max_tlp, now=datetime.now(UTC), days=days
            )
        except LookupError as exc:
            raise ValueError(f'{exc}; see `insight industries`') from exc
    lines = [
        f'TLP:{profile.tlp} - groups that cited sources name for {profile.industry.name} '
        f'({profile.candidates} in all; top {len(profile.entries)}):'
    ]
    for rank, entry in enumerate(profile.entries, start=1):
        lines.append(f'{rank:>2}. {entry.subject.ref} {entry.subject.name}')
        lines += [f'      - {reason}' for reason in entry.reasons]
    if profile.capped:
        lines.append(f'Only the newest {profile.scanned} reports were read for mentions.')
    return '\n'.join(lines)


def _create(destination: Path) -> int:
    try:
        return os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(f'{destination} already exists; exports never overwrite, choose a new name') from exc
    except OSError as exc:
        raise ValueError(f'cannot create {destination}: {exc.strerror or exc}') from exc


def threat_guide(
    ref: str, destination: Path, fmt: str = 'md', max_tlp: str | None = None, include_named: bool = False
) -> str:
    """Write a group's threat guide (or its Navigator layer or sweep list) to ``destination``. Audited.

    The sweep list takes indicators only from reports linked to the group unless ``include_named``.
    """
    from . import services
    from .cli import _current_database
    from .threat_guide import compose, guide_json, navigator_layer, sweep_csv, sweep_json
    from .threat_guide_markdown import to_markdown
    from .threat_library import library

    if fmt not in GUIDE_FORMATS:
        raise ValueError(f'--format must be one of {", ".join(GUIDE_FORMATS)}')
    with _current_database() as sessions:
        with sessions.begin() as db:
            services.set_actor(db, 'cli')
            try:
                data = services.guide_data(
                    db, ref, max_tlp=max_tlp, now=datetime.now(UTC), linked_only=not include_named
                )
            except LookupError as exc:
                raise ValueError(f'{exc}: {ref}') from exc
            detail = {
                'what': f'cli.{fmt}',
                'tlp': data.tlp,
                'max_tlp': max_tlp,
                'linked_only': not include_named,
            }
            services.audit(db, 'actor.guide', data.subject.ref, json.dumps(detail, sort_keys=True))
        guide = compose(data, library())
    writers = {
        'md': lambda: to_markdown(guide),
        'json': lambda: json.dumps(guide_json(guide), indent=2, ensure_ascii=False),
        'navigator': lambda: json.dumps(navigator_layer(guide), indent=2),
        'sweep-csv': lambda: sweep_csv(guide),
        'sweep-json': lambda: json.dumps(sweep_json(guide), indent=2, ensure_ascii=False),
    }
    text = writers[fmt]()
    with os.fdopen(_create(destination), 'w', encoding='utf-8') as out:
        out.write(text if text.endswith('\n') else text + '\n')
    return (
        f'Wrote the {fmt} threat guide for {guide.name} to {destination} (TLP:{guide.tlp}); share no wider.'
    )


def rule_add(
    path: Path, kind: str, name: str, links: list[str], tlp: str, licence: str, source_url: str
) -> str:
    """Store a YARA or Sigma rule from a file and link it to groups (``G0016``) or techniques (``T1059``)."""
    from pydantic import ValidationError

    from . import services
    from .cli import _current_database
    from .config import parse_max_tlp
    from .schemas import RuleInput, RuleLinkInput, validation_message

    try:
        body = path.read_text(encoding='utf-8')
    except OSError as exc:
        raise ValueError(f'cannot read {path}: {exc.strerror or exc}') from exc
    try:
        payload = RuleInput.model_validate(
            {
                'kind': kind,
                'name': name or path.stem,
                'body': body,
                'tlp': tlp,
                'licence': licence,
                'source_url': source_url,
            }
        )
        targets = [
            RuleLinkInput(target_kind='technique' if t.upper().startswith('T') else 'group', target_id=t)
            for t in links
        ]
    except ValidationError as exc:
        raise ValueError(validation_message(exc)) from exc
    with _current_database() as sessions, sessions.begin() as db:
        services.set_actor(db, 'cli')
        try:
            rule = services.add_rule(
                db, payload, max_tlp=parse_max_tlp(os.environ.get('INSIGHT_MAX_TLP', ''))
            )
        except services.TlpNotPermitted as exc:
            raise ValueError(str(exc)) from exc
        for target in targets:
            try:
                services.link_rule(db, rule.id, target)
            except LookupError as exc:
                raise ValueError(f'{target.target_id}: {exc}') from exc
        rule_id = rule.id
    return (
        f'Stored {kind} rule {rule_id} ({payload.name}), linked to {len(targets)} target(s). It is never run.'
    )
