"""Threat themes for the threat landscape: kinds of threat, how Insight spots them, and what they mean.

A report counts towards a theme when its text contains one of the theme's words (a literal, case- and
accent-insensitive match, like a watch term) or when it is tagged with one of the theme's ATT&CK
techniques. Nothing is inferred: the words are listed here and shown in the workspace, so an analyst can see
why a report was counted. The words are chosen so that a match almost always means the report is about that
kind of threat: "denial of service" is left out because most vulnerability advisories name it as a possible
effect, and "0-day" because "30-day" contains it.

``what``, ``impact`` and ``check`` are general guidance written for analysts, not facts about the reports.
They are kept plain (``tests/unit/test_themes.py`` checks the reading level, like the interface text).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Theme:
    key: str
    name: str
    #: Matched as substrings of the report's folded text (``services.fold``): lowercase, no accents.
    words: tuple[str, ...]
    #: ATT&CK technique IDs; a sub-technique of one counts too (T1566 covers T1566.001).
    techniques: tuple[str, ...]
    what: str
    impact: str
    check: str

    def has_technique(self, technique_id: str) -> bool:
        return any(technique_id == t or technique_id.startswith(f'{t}.') for t in self.techniques)


THEMES: Final[tuple[Theme, ...]] = (
    Theme(
        'ransomware',
        'Ransomware',
        ('ransomware', 'ransom note', 'ransom demand', 'double extortion'),
        ('T1486',),
        'Criminals lock up files and ask for money to unlock them. Many steal the data first.',
        'It can stop a whole organisation from working for days. Gangs often get in through remote access '
        'or systems that are not patched.',
        'Check that backups work and are kept apart from the network. Fix weak spots in systems that face '
        'the internet first.',
    ),
    Theme(
        'phishing',
        'Phishing',
        ('phishing', 'smishing', 'vishing', 'business email compromise', 'business e-mail compromise'),
        ('T1566', 'T1598', 'T1534'),
        'Fake e-mails, texts or calls. They trick people into giving away a password or opening a bad file.',
        'It is the most common way attackers get in. One click can hand over an account.',
        'Warn staff about the lures in these reports. Look for the senders and links in your mail logs.',
    ),
    Theme(
        'data-theft',
        'Data theft and extortion',
        (
            'data theft',
            'stolen data',
            'data leak site',
            'leak site',
            'exfiltration',
            'exfiltrated',
            'data extortion',
            'data breach',
        ),
        ('T1041', 'T1048', 'T1567', 'T1537'),
        'Attackers copy data out, then threaten to publish it unless they are paid.',
        'Stolen data can lead to fines, lost trust and legal work, even when nothing is locked up.',
        'Look for large or odd uploads to the internet. Know where your most private data is kept.',
    ),
    Theme(
        'credentials',
        'Password and account theft',
        (
            'credential theft',
            'stolen credentials',
            'credential harvesting',
            'credential stuffing',
            'infostealer',
            'info stealer',
            'info-stealer',
            'password spray',
        ),
        ('T1003', 'T1110', 'T1555', 'T1539'),
        'Stealing passwords, keys or sign-in sessions, for example with malware that steals them or by '
        'guessing.',
        'With a working sign-in, attackers look like normal users, and many tools will not flag them.',
        'Make sure accounts need a second step to sign in. Reset passwords that may have leaked.',
    ),
    Theme(
        'supply-chain',
        'Supply-chain attacks',
        (
            'supply chain attack',
            'supply-chain attack',
            'supply chain compromise',
            'supply-chain compromise',
            'software supply chain',
            'malicious package',
            'typosquat',
        ),
        ('T1195',),
        'Attacks that come in through a supplier, a software update or a shared code package.',
        'One break-in at a supplier can reach many of its customers at once.',
        'Check whether you use the suppliers, products or code packages named in these reports.',
    ),
    Theme(
        'zero-day',
        'Zero-day exploits',
        ('zero-day', 'zero day', 'zeroday'),
        (),
        'Attacks on a weakness before the maker has a fix for it.',
        'A patch cannot help until the maker ships one, so other defences have to hold the line.',
        'Find out if you use the product. Follow the maker’s advice until a fix comes out, then patch fast.',
    ),
    Theme(
        'espionage',
        'Spying by state-backed groups',
        ('espionage', 'state-sponsored', 'state sponsored', 'state-backed', 'nation-state', 'nation state'),
        (),
        'Groups that work for a government and break in to steal secrets, then stay hidden for a long time.',
        'They are patient and skilled. They often go after government, defence, energy and tech firms.',
        'Hunt for the clues and techniques in these reports, even if no alarm has gone off.',
    ),
    Theme(
        'wipers',
        'Destructive attacks (wipers)',
        ('wiper', 'destructive malware', 'disk wipe'),
        ('T1485', 'T1561'),
        'Malware that deletes data or breaks computers on purpose. There is no ransom to pay to get it back.',
        'The only way back is to rebuild from backups, which can take weeks.',
        'Check that you can bring key systems back from backups, and how long it would take.',
    ),
    Theme(
        'ddos',
        'Denial of service (DDoS)',
        ('ddos', 'distributed denial-of-service', 'distributed denial of service'),
        ('T1498', 'T1499'),
        'Floods of traffic meant to knock a website or service offline.',
        'People cannot reach you while it lasts. Some groups use it to hide other attacks.',
        'Check that your internet provider, or a service you pay for, can soak up a flood.',
    ),
    Theme(
        'botnets',
        'Botnets',
        ('botnet',),
        ('T1583.005', 'T1584.005'),
        'Large groups of hacked devices, such as routers and cameras, that attackers run as one.',
        'They send spam, floods of traffic and attacks. Some of your own devices could be part of one.',
        'Look for the addresses from these reports in your logs. Update or replace old routers and cameras.',
    ),
    Theme(
        'hacktivism',
        'Hacktivism',
        ('hacktivis',),
        (),
        'Attacks by activists who want to make a point, such as defacing or flooding websites.',
        'They are often short and noisy, but they can hurt a good name. They tend to follow the news.',
        'Check whether events in the news could make your organisation a target.',
    ),
    Theme(
        'cryptomining',
        'Cryptomining',
        ('cryptomin', 'cryptojack', 'coinminer', 'coin miner'),
        ('T1496',),
        'Hijacking computers or cloud accounts to make crypto money.',
        'It runs up costs and slows systems down. It also shows that someone has a way in.',
        'Look for computers that are busy for no reason, and for cloud bills that jump.',
    ),
    Theme(
        'insider',
        'Insider threats',
        ('insider threat',),
        (),
        'Harm done by people inside the organisation, on purpose or by mistake.',
        'Insiders already have access, so defences at the edge of the network do not stop them.',
        'Check who can reach private data, and whether odd access would be noticed.',
    ),
)

THEMES_BY_KEY: Final = {theme.key: theme for theme in THEMES}
