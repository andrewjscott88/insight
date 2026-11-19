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
        'CSAF',
        'A way of writing security warnings so that computers can read them. CISA uses it for its warnings.',
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
