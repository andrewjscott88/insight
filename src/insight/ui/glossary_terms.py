"""The glossary's terms and plain-language explanations (shown by ``glossary.open_glossary``)."""

from __future__ import annotations

from typing import Final

#: (term, explanation), in the order a new user meets them.
GLOSSARY: Final[tuple[tuple[str, str], ...]] = (
    (
        'Report, source',
        'A piece of writing about a threat, such as an advisory or a blog post. You add reports to '
        'Insight, or sync them from public sources.',
    ),
    (
        'Ingest',
        'To add a report to Insight. You can paste its text or import a file.',
    ),
    ('PDF', 'Portable Document Format. A file that keeps the layout of a page.'),
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
        'Personal data',
        'Details that can identify a person, such as an e-mail address. Check who may see them '
        'before you share a report.',
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
        'Reliability',
        'How far you trust a source, from A (completely reliable) to F (cannot be judged).',
    ),
    (
        'Credibility',
        'How believable one report is, from 1 (confirmed by other sources) to 6 (cannot be judged).',
    ),
    (
        'Confidence',
        'A score from 0 to 100 for how well your sources back up an indicator. Trusted sources that agree '
        'raise it. Old reports count for less.',
    ),
    (
        'PIR',
        'One of the main questions your team must keep answering, such as: are we a target? It stands for '
        'priority intelligence requirement.',
    ),
    (
        'RFI',
        'A request for information: a one-off question from a person or another tool. Answering it closes '
        'it.',
    ),
    (
        'API key',
        'A secret that lets a script, or a tool such as a SIEM, read from Insight. It only sees reports up '
        'to the TLP you set for it.',
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
        'TAXII',
        'A standard way for tools to fetch threat information from a server. Insight runs a TAXII feed.',
    ),
    (
        'STIX',
        'A standard format for sharing threat information. You can export a STIX file for other tools.',
    ),
    (
        'VPN (virtual private network)',
        'A safe way to connect to a company network from outside.',
    ),
    (
        'CSV',
        'A plain table file. Spreadsheets and most security tools can open it.',
    ),
    (
        'Threat group, actor',
        'A team of attackers that security researchers track under a name, such as APT29. Many groups have '
        'more than one name.',
    ),
    (
        'MISP galaxy',
        'A free, shared list of threat groups and the sectors they attack, kept by the MISP project.',
    ),
    (
        'Industry threats, top ten',
        'The groups that a cited source says attack an industry. Insight never guesses this. Groups named in '
        'your recent reports come first.',
    ),
    (
        'Threat guide',
        'One page about a group: who it attacks, how it works, your reports about it, and a hunt plan.',
    ),
    (
        'Hunt, hunt plan',
        'A planned search of your own logs for signs of a group. The plan lists ideas to check. The hunt '
        'record says what you checked and what you found.',
    ),
    (
        'YARA, Sigma',
        'Two common kinds of detection rule. YARA rules match files. Sigma rules search logs. Insight keeps '
        'them as text and never runs them.',
    ),
)
