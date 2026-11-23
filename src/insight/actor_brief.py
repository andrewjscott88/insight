"""Plain-English actor context from explicit catalog facts, never inferred activity."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .focused_brief import BriefSection, BriefSource
from .industries import BY_KEY
from .threat_library import Group, Library, technique_name

# These explain documented techniques. Their order is editorial, not a claim about frequency.
_METHODS = (
    (
        'T1190',
        'Break into systems exposed to the internet',
        'Watch for unusual requests to public servers, followed by new commands or files.',
    ),
    (
        'T1078',
        'Use real accounts to blend in with normal users',
        'Watch for sign-ins from new places or devices, especially on administrator accounts.',
    ),
    (
        'T1059',
        'Run commands with built-in system tools',
        'Look for unusual command use by accounts or services that rarely run commands.',
    ),
    (
        'T1003',
        'Steal password data from computers',
        'Watch for unusual access to password stores or security processes.',
    ),
    (
        'T1505.003',
        'Leave hidden access on a web server for later use',
        'Check for new web-server files and web services starting unexpected programs.',
    ),
    (
        'T1021',
        'Move between computers through remote access',
        'Watch for a new chain of remote sign-ins from one machine to others.',
    ),
    (
        'T1090',
        'Route traffic through other systems to hide its source',
        'Review new forwarding services and unexpected connections through network devices.',
    ),
    (
        'T1070',
        'Remove traces of activity',
        'Watch for missing logs or unexpected clearing of account and network history.',
    ),
    (
        'T1566',
        'Trick people into opening a file or following a link',
        'Compare unusual messages with the files, links and sign-ins that follow them.',
    ),
    (
        'T1486',
        'Lock files so people cannot use them',
        'Watch for rapid file changes and unusual attempts to disable backups.',
    ),
)


@dataclass(frozen=True, slots=True)
class ActorBrief:
    summary: tuple[str, ...]
    sections: tuple[BriefSection, ...]
    sources: tuple[BriefSource, ...]


def _text(value: str, cap: int = 400) -> str:
    value = re.sub(r'\(Citation:[^)]*\)', '', value)
    value = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', value)
    value = ' '.join(value.split()).strip('. ')
    return value if len(value) <= cap else value[: cap - 1].rstrip() + '…'


def actor_profile(
    name: str,
    description: str,
    aliases: tuple[str, ...],
    group: Group | None,
    lib: Library,
    *,
    added: tuple[tuple[str, str], ...] = (),
    removed: frozenset[str] = frozenset(),
) -> ActorBrief:
    """Compose bounded background; callers have already filtered analyst decisions and their labels."""
    sections: list[BriefSection] = []
    sources: list[BriefSource] = []
    description = group.description if group else description
    overview = tuple(_text(s) + '.' for s in description.split('. ')[:3] if _text(s))
    # The first catalog sentence is already the executive takeaway; details add context instead.
    who = list(overview[1:3])
    targets = (
        [
            f'{BY_KEY[key].name} ({claim.source_name})'
            for claim in group.claims
            for key in claim.industries
            if key not in removed and key in BY_KEY
        ]
        if group
        else []
    )
    targets += [f'{BY_KEY[key].name} (analyst mapping)' for key, _ in added if key in BY_KEY]
    targets = list(dict.fromkeys(targets))
    if targets:
        who.append(
            'Recorded targets: '
            + '; '.join(targets[:8])
            + ('. More are in the full profile.' if len(targets) > 8 else '.')
        )
    if group and group.regions:
        who.append('Recorded regions: ' + ', '.join(group.regions[:8]) + '.')
    if who:
        sections.append(BriefSection('Who they are and known targets', tuple(who[:5])))
    methods: list[tuple[str, str, str]] = []
    if group:
        for prefix, plain, watch in _METHODS:
            matches = [tid for tid in group.techniques if tid == prefix or tid.startswith(prefix + '.')]
            if matches:
                methods.append((matches[0], plain, watch))
        if not methods:
            methods = [(tid, technique_name(tid), '') for tid in group.techniques[:5]]
    if methods:
        sections.append(
            BriefSection(
                'How they operate',
                (
                    *tuple(f'{plain} ({tid}; MITRE ATT&CK).' for tid, plain, _ in methods[:5]),
                    'Selected documented methods, not a ranking. The full catalog profile has more.',
                ),
            )
        )
    watches = [(tid, watch) for tid, _, watch in methods if watch][:4]
    if watches:
        sections.append(
            BriefSection(
                'What to watch for',
                (
                    *tuple(f'{watch} ({tid})' for tid, watch in watches),
                    'These are checks to adapt to your systems, not evidence that this actor is present.',
                ),
            )
        )
    tools = [lib.software[sid] for sid in group.software if sid in lib.software] if group else []
    if tools:
        lines = tuple(f'{tool.name} ({tool.id}; {tool.type}).' for tool in tools[:4])
        lines += (
            f'Shows {min(4, len(tools))} of {len(tools)} catalog tools. '
            'A tool alone does not identify an actor.',
        )
        sections.append(BriefSection('Tools recorded by MITRE ATT&CK', lines))
    names = tuple(dict.fromkeys(aliases))
    identity = (
        ['Also tracked as: ' + ', '.join(_text(alias, 80) for alias in names[:6]) + '.'] if names else []
    )
    if len(names) > 6:
        identity.append('Shows six aliases; the full profile has more.')
    if group:
        identity.append(
            f'Catalog entry {group.id}; updated {_text(group.modified[:10]) or "date not recorded"}. '
            'This is a catalog update date, not the date of an attack.'
        )
        sources.append(BriefSource(f'MITRE ATT&CK: {group.name} ({group.id})', group.url))
        sources.extend(BriefSource(c.name, c.url) for c in group.references[:4])
        identity.append(f'Background uses the saved {lib.edition} library, ATT&CK {lib.attack_version}.')
    if identity:
        sections.append(BriefSection('Names and source context', tuple(identity)))
    sources.extend(BriefSource('Analyst target mapping', url) for _, url in added if url)
    sources = list(
        dict.fromkeys(
            BriefSource(_text(s.name, 180), s.url.strip())
            for s in sources
            if s.url.startswith(('https://', 'http://'))
        )
    )[:6]
    first = ('MITRE ATT&CK background: ' if group else 'Analyst background: ') + (
        overview[0] if overview else f'{_text(name)} is tracked in this workspace.'
    )
    summary = [first]
    if methods:
        summary.append(
            'Documented methods include: ' + '; '.join(plain.lower() for _, plain, _ in methods[:3]) + '.'
        )
    if watches:
        summary.append('What matters for defenders: ' + ' '.join(watch for _, watch in watches[:2]))
    elif targets:
        summary.append('Recorded targets include ' + '; '.join(targets[:3]) + '.')
    return ActorBrief(tuple(summary[:3]), tuple(sections[:6]), tuple(sources))
