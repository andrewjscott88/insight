"""Plain-language explanations of the words and abbreviations the workspace uses (WCAG 3.1.3, 3.1.4; COGA).

Threat-intelligence work is full of jargon. Every abbreviation shown in the interface must be explained here
(``tests/unit/test_plain_language.py`` checks it); each explanation is written to be read at about age 12-14.
"""

from __future__ import annotations

from typing import Final

from nicegui import ui

from .typography import heading

#: (term, explanation), in the order a new user meets them.
GLOSSARY: Final[tuple[tuple[str, str], ...]] = (
    (
        'Report, source',
        'A piece of writing about a threat, such as an advisory or a blog post. You add reports to '
        'Insight, or sync them from public sources.',
    ),
    (
        'Ingest',
        'To add a report to Insight. You paste its text and Insight keeps a copy.',
    ),
    (
        'Indicator',
        'A clue that can point to an attack, such as a web address, an IP address or a file fingerprint.',
    ),
    (
        'IOC (indicator of compromise)',
        'Another name for an indicator: a clue that an attack may have happened.',
    ),
    (
        'Observation',
        'One place in a report where Insight found an indicator. You check each one and accept or reject it.',
    ),
    (
        'Accepted, rejected, unreviewed',
        'Accepted means you checked that Insight copied the value correctly. It does not mean the '
        'value is harmful. Rejected means it was copied wrongly. Unreviewed means nobody has checked '
        'it.',
    ),
    (
        'Verdict: unknown, benign, suspicious, malicious',
        'What you decided an indicator means. Benign means harmless. Malicious means it is used in '
        'attacks. Unknown means nobody has decided yet. A verdict is not the same as accepting a value. A '
        'verdict can end on a date you choose.',
    ),
    (
        'Warning',
        'A sign that a value must never be blocked, whatever its verdict. Insight works it out from the '
        'value itself.',
    ),
    (
        'Private or reserved address',
        'An address that only works inside a network, or is kept for special uses. Blocking it could cut '
        'off your own computers.',
    ),
    (
        'Example address',
        'An address set aside for examples in books and guides, such as 192.0.2.1. No real computer uses it.',
    ),
    (
        'Reserved name',
        'A name that is not a real site on the internet, such as example.com or a name ending in .local.',
    ),
    (
        'Common vendor site',
        'The site of a big company, such as microsoft.com. Reports often name it, and blocking it would '
        'break things.',
    ),
    (
        'Blocklist',
        'A list of values for a firewall to block. A value goes on it only when you marked it malicious, '
        'accepted it in a report and it has no warning. Verdicts on addresses drop off after 30 days, and '
        'on domains after 90 days, unless you chose an end date.',
    ),
    (
        'New, reviewing, reviewed',
        'How far you have got with a whole report.',
    ),
    (
        'Evidence',
        'The words around an indicator in the report, so you can see why it was found.',
    ),
    (
        'Extraction',
        'How Insight finds indicators in text. It follows fixed rules, so it can miss things or make '
        'mistakes. Always check the evidence.',
    ),
    (
        'Entity',
        'One indicator value, such as one web address, that may appear in many reports.',
    ),
    (
        'Threat landscape',
        'The big picture: which kinds of threat your reports describe most, how that is changing, and what '
        'it could mean for you. Insight counts this from your reports.',
    ),
    (
        'Rising, new, as usual, quieter',
        'How a kind of threat compares with the 4 weeks (or 4 months) before. Rising means in more reports '
        'than usual and a bigger share of them. New means it was in none of them. Quieter means half as many '
        'or fewer.',
    ),
    (
        'Webhook',
        'A web address that a chat app or another tool gives you, so that Insight can post alerts to it. '
        'Keep it secret, like a password.',
    ),
    (
        'MITRE ATT&CK',
        'A free list of the ways attackers work, kept by the MITRE organisation. Analysts use it so that '
        'everyone names the same attack steps with the same words.',
    ),
    (
        'Technique, sub-technique, technique ID',
        'One way attackers work, such as phishing. Each one has a short code, its ID, such as T1566. A '
        'sub-technique is a more exact kind, such as T1566.001 for phishing with a file attached.',
    ),
    (
        'Tactic',
        'What an attacker wants from a step, such as getting in, staying hidden or stealing data. Each '
        'technique serves one or more tactics.',
    ),
    (
        'ATT&CK Navigator, layer',
        'A free web tool from MITRE that shows the ATT&CK techniques as a grid of colours. A layer is a '
        'file you open in it. Insight makes one from the techniques in your reports.',
    ),
    (
        'Watch term',
        'A word you care about, such as a product name. Reports that contain it are marked in the inbox.',
    ),
    (
        'TLP (Traffic Light Protocol)',
        'A label that says who may see a report. CLEAR: anyone. GREEN: your community. AMBER: your '
        'organisation and its clients. AMBER+STRICT: your organisation only. RED: only the people it '
        'was given to.',
    ),
    (
        'Superseded, revision',
        'When a publisher changes a report, Insight keeps the old version as a revision. The old '
        'version is then superseded by the new one.',
    ),
    (
        'Truncated',
        'Cut short. Insight saved only part of the text.',
    ),
    (
        'Sync',
        'To fetch new reports from a public source. This only happens when you press Sync now.',
    ),
    (
        'Enrichment, lookup',
        'Asking an outside service for more facts about a vulnerability. Insight asks you first.',
    ),
    (
        'Provenance',
        'Where a report came from and proof that it has not changed.',
    ),
    (
        'Defang',
        'To change a web address so it cannot be clicked by mistake, for example example[.]com.',
    ),
    (
        'CVE',
        'A number that names one known security weakness, such as CVE-2024-3400.',
    ),
    (
        'KEV (CISA Known Exploited Vulnerabilities)',
        'A list, kept by the US agency CISA, of weaknesses that attackers are using now.',
    ),
    (
        'CISA',
        'The US Cybersecurity and Infrastructure Security Agency.',
    ),
    (
        'AI',
        'Short for artificial intelligence: programs, such as chatbots, that write text on their own. '
        'Insight does not use them.',
    ),
    (
        'CSAF',
        'A way of writing security warnings so that computers can read them. CISA uses it for its warnings.',
    ),
    (
        'CVSS',
        'A score from 0 to 10 for how serious a weakness is. A score of 9 or more is critical.',
    ),
    (
        'UTC',
        'The time zone that clocks around the world are set from. It does not change in summer. Midnight UTC '
        'is 7 pm in New York in winter.',
    ),
    (
        'EPSS (FIRST)',
        'A score from the FIRST organisation: how likely a weakness is to be used in an attack soon.',
    ),
    (
        'NVD (NIST)',
        'The US National Vulnerability Database, run by NIST. It describes each CVE.',
    ),
    (
        'IP address',
        'A number that points to one computer on a network, a bit like a phone number.',
    ),
    (
        'Network range (CIDR)',
        'A short way to write a group of IP addresses. For example, 203.0.113.0/24 covers all '
        'addresses from 203.0.113.0 through 203.0.113.255.',
    ),
    (
        'Domain, URL',
        'A domain is a website name, such as example.com. A URL is a full web address.',
    ),
    (
        'MD5, SHA-1, SHA-256, SHA-512',
        'Codes that work like fingerprints (hashes). Each one matches one exact file or piece of text.',
    ),
    (
        'JSON',
        'A common file format that other tools can read.',
    ),
    (
        'STIX',
        'A standard format for sharing threat information. Insight does not use it yet.',
    ),
    (
        'VPN (virtual private network)',
        'A safe way to connect to a company network from outside.',
    ),
)


def open_glossary() -> None:
    """A dialog listing every term, with a heading and a name for assistive technology."""
    title = 'What the words mean'
    with (
        ui.dialog().props(f'aria-label="{title}"') as dialog,
        ui.card().classes('panel dialog-card w-[42rem] max-w-full p-6 gap-3'),
    ):
        heading(title, 2)
        ui.label('Words and abbreviations used in Insight, in plain language.').classes('muted prose')
        with ui.element('dl').classes('glossary w-full'):
            for term, explanation in GLOSSARY:
                ui.label(term).tag = 'dt'
                ui.label(explanation).tag = 'dd'
        ui.button('Close', on_click=dialog.close).props('flat')
    dialog.open()
