"""The curated public sources Insight can sync, and what each publisher allows Insight to do with its text.

This module has no dependencies on the rest of Insight, so the services that export reports can apply each
source's reuse rule (``insight.connectors`` fetches the sources; ADR 0021).

- **In use.** A source is in use unless the operator switched it off. ``optional`` sources (the
  threat-research publishers and news) start switched off: Insight contacts them only after someone switches
  them on.
- **Reuse.** ``public`` sources (US government works) may be exported with their text. For ``metadata``
  sources Insight keeps the title, a short summary and the link, shows them in the workspace, and leaves the
  publisher's text out of every export: the report export, the IOC export's evidence and shared briefings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

#: CISA publishes its advisories as CSAF 2.0 files on GitHub (its RSS feeds refuse automated clients).
#: Folder OT holds the industrial control system advisories, IT the other vulnerability advisories; VA
#: repeats IT.
CSAF_BASE: Final = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/'
CSAF_INBOX_LIMIT: Final = 25
OTX_SUBSCRIBED_URL: Final = 'https://otx.alienvault.com/api/v1/pulses/subscribed'

Category = Literal['vulnerabilities', 'threat research', 'news', 'indicators']
Reuse = Literal['public', 'metadata']

#: The order categories are shown in, with their headings.
CATEGORIES: Final[dict[str, str]] = {
    'vulnerabilities': 'Weaknesses and advisories',
    'threat research': 'Threat research',
    'news': 'Security news',
    'indicators': 'Indicator feeds',
}

_RESEARCH: Final = (
    'Insight keeps the title, a short summary and the link. The publisher’s terms apply: its text is left '
    'out of exports.'
)


@dataclass(frozen=True, slots=True)
class Source:
    key: str
    name: str
    #: The feed for ``kev`` and ``rss`` sources. For ``csaf`` sources, the page people open to browse them.
    url: str
    kind: Literal['kev', 'rss', 'csaf', 'abusech', 'otx', 'taxii']
    note: str
    #: Fixed download URLs when ``url`` points to the publisher page people can open in the workspace.
    indexes: tuple[str, ...] = ()
    category: Category = 'vulnerabilities'
    #: Switched off until the operator switches it on.
    optional: bool = False
    #: ``public``: the publisher's text may be exported. ``metadata``: only titles, links and dates leave
    #: Insight.
    reuse: Reuse = 'metadata'

    @property
    def fetch_urls(self) -> tuple[str, ...]:
        """The URLs a sync requests first (advisory files named by a CSAF index sit beside it)."""
        return self.indexes or (self.url,)


SOURCES: Final[dict[str, Source]] = {
    s.key: s
    for s in (
        Source(
            'cisa-kev',
            'CISA Known Exploited Vulnerabilities',
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'kev',
            'Known exploitation evidence; due dates apply to covered federal agencies, '
            'not a universal deadline.',
            reuse='public',
        ),
        Source(
            'cisa-csaf',
            'CISA Security Advisories',
            'https://github.com/cisagov/CSAF',
            'csaf',
            f'The {CSAF_INBOX_LIMIT} newest advisories CISA has published about weaknesses in industrial '
            "control systems and other products, from CISA's machine-readable files (CSAF). Advisories about "
            'attacker groups are not included.',
            indexes=(CSAF_BASE + 'OT/white/changes.csv', CSAF_BASE + 'IT/white/changes.csv'),
            reuse='public',
        ),
        Source(
            'sans-isc',
            'SANS Internet Storm Center',
            'https://isc.sans.edu/rssfeed.xml',
            'rss',
            'Feed metadata only. Publisher terms still apply; free access is not a redistribution license.',
        ),
        Source(
            'ncsc',
            'UK NCSC Reports',
            'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml',
            'rss',
            'Feed metadata only. Check publisher attribution and reuse terms.',
        ),
        Source(
            'talos',
            'Cisco Talos',
            'https://blog.talosintelligence.com/rss/',
            'rss',
            'Research on attacker groups, malware and campaigns from Cisco’s threat team. ' + _RESEARCH,
            category='threat research',
            optional=True,
        ),
        Source(
            'microsoft-ti',
            'Microsoft Threat Intelligence',
            'https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/',
            'rss',
            'Microsoft’s reports on state-backed groups, crime gangs and the ways they attack. ' + _RESEARCH,
            category='threat research',
            optional=True,
        ),
        Source(
            'dfir-report',
            'The DFIR Report',
            'https://thedfirreport.com/feed/',
            'rss',
            'Step-by-step accounts of real intrusions, often ransomware, with the ATT&CK techniques used. '
            + _RESEARCH,
            category='threat research',
            optional=True,
        ),
        Source(
            'eset',
            'ESET WeLiveSecurity',
            'https://www.welivesecurity.com/en/rss/feed/',
            'rss',
            'Research on malware, spying groups and campaigns from ESET. ' + _RESEARCH,
            category='threat research',
            optional=True,
        ),
        Source(
            'securelist',
            'Kaspersky Securelist',
            'https://securelist.com/feed/',
            'rss',
            'Research on spying groups, malware and crime from Kaspersky’s research team. ' + _RESEARCH,
            category='threat research',
            optional=True,
        ),
        Source(
            'the-record',
            'The Record (Recorded Future News)',
            'https://therecord.media/feed',
            'rss',
            'News on attacks, breaches, ransomware and cyber policy, several times a day. ' + _RESEARCH,
            category='news',
            optional=True,
        ),
        Source(
            'urlhaus',
            'URLhaus',
            'https://urlhaus.abuse.ch/',
            'abusech',
            'Recent URLs reported for malware delivery. Requires your abuse.ch key. Insight reads the list '
            'and keeps the reported links as text.',
            indexes=('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/',),
            category='indicators',
            optional=True,
        ),
        Source(
            'threatfox',
            'ThreatFox',
            'https://threatfox.abuse.ch/',
            'abusech',
            'Recent network indicators and file hashes reported to ThreatFox. Requires your abuse.ch key.',
            indexes=('https://threatfox-api.abuse.ch/api/v1/',),
            category='indicators',
            optional=True,
        ),
        Source(
            'malwarebazaar',
            'MalwareBazaar',
            'https://bazaar.abuse.ch/',
            'abusech',
            'File hashes from recent reports about malware. Requires your abuse.ch key. Insight reads only '
            'the file details.',
            indexes=('https://mb-api.abuse.ch/api/v1/',),
            category='indicators',
            optional=True,
        ),
        Source(
            'alienvault-otx',
            'AlienVault Open Threat Exchange (OTX)',
            OTX_SUBSCRIBED_URL,
            'otx',
            'Import public pulses you subscribe to with your own OTX key. Insight reads only pulses marked '
            'CLEAR or WHITE. It keeps the title, link and indicators. Publisher terms apply.',
            category='threat research',
            optional=True,
        ),
    )
}

#: Keys of the sources whose text stays in Insight (titles, links and dates may leave it).
METADATA_ONLY: Final = frozenset(key for key, s in SOURCES.items() if s.reuse == 'metadata')
OPERATOR_PREFIX: Final = 'op-'


def is_operator_source(source_key: str | None) -> bool:
    """Operator source IDs keep their namespace after the source is deleted."""
    return source_key is not None and source_key.startswith(OPERATOR_PREFIX)


def metadata_only(source_key: str | None, operator_reuse: str | None = None) -> bool:
    """Whether to withhold publisher text. An operator source needs a current, explicit public rule."""
    if is_operator_source(source_key):
        return operator_reuse != 'public'
    return source_key in METADATA_ONLY or source_key == 'stix-import-metadata'


def in_use(source: Source, switches: dict[str, bool]) -> bool:
    """Whether Insight may contact ``source``: the operator's switch, or on unless the source is optional."""
    return switches.get(source.key, not source.optional)
