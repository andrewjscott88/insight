"""The fixed list of industries for threat profiles (TIP 2.10, ADR 0024) and how catalog labels map to them.

Catalogs name sectors in their own words: MISP galaxy uses labels such as ``Healthcare`` or ``Telecoms``, and
MITRE ATT&CK writes them only in its prose ("has targeted banks, financial institutions ..."). This module is
the one place that says which of those words count as which industry, so the mapping is reviewable and the
same at build time (``scripts/update_actors.py``) and in the application.

Rules for the prose patterns (precision first, as in ADR 0007): a phrase counts only in a sentence that also
says the group *targeted* someone (``TARGETING``), after phrases that name a sponsor rather than a victim
(``on behalf of the ... government``) are removed. The sentence itself is kept as the evidence, so the analyst
can read exactly what the catalog says. Nothing here is a score and nothing is inferred from indicators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Industry:
    key: str
    name: str
    #: What it covers, in plain words, shown under the picker.
    covers: str
    #: MISP galaxy ``cfr-target-category`` / ``targeted-sector`` labels (case-folded) that mean this industry.
    labels: frozenset[str]
    #: Phrases in ATT&CK group descriptions that name a victim in this industry.
    phrases: re.Pattern[str]


def _phrases(*patterns: str) -> re.Pattern[str]:
    return re.compile(r'\b(?:' + '|'.join(patterns) + r')', re.IGNORECASE)


INDUSTRIES: Final[tuple[Industry, ...]] = (
    Industry(
        'government',
        'Government and diplomacy',
        'Ministries, agencies, local government, embassies and international bodies.',
        frozenset(
            {
                'government',
                'government, administration',
                'government administration',
                'government agencies and services',
                'government institutions',
                'intergovernmental',
                'diplomacy',
                'justice',
            }
        ),
        _phrases(
            r'government(?:s|al)?(?! ?-?sponsored)(?! of)',
            r'ministr(?:y|ies)',
            r'embass(?:y|ies)',
            r'diplomat(?:s|ic)?',
            r'public sector',
            r'municipal',
            r'state agencies',
            r'federal agencies',
            r'intergovernmental',
        ),
    ),
    Industry(
        'defense',
        'Defence, military and aerospace',
        'Armed forces, defence contractors, aerospace and space organisations.',
        frozenset(
            {
                'military',
                'defense',
                'defense industrial base',
                'defense contractor',
                'aerospace',
                'space',
            }
        ),
        _phrases(
            r'defen[cs]e (?:sector|industr|organi[sz]ation|contractor|compan|firm|entit|ministr|department)',
            r'defen[cs]e(?=,| and| sectors?\b| industr)',
            r'military(?! unit cover)',
            r'armed forces',
            r'aerospace',
            r'defen[cs]e industrial base',
        ),
    ),
    Industry(
        'finance',
        'Finance, banking and cryptocurrency',
        'Banks, payment and insurance firms, investment firms and cryptocurrency businesses.',
        frozenset(
            {
                'finance',
                'financial',
                'financial services',
                'bank',
                'payment',
                'investment',
                'cryptocurrency',
            }
        ),
        _phrases(
            r'financial (?:institution|sector|services|organi[sz]ation|compan|entit|industr|firm|vertical)',
            r'finance(?=,| and| sectors?\b| industr)',
            r'financial(?=,| and| sectors?\b)',
            r'banks?\b(?! ?trojan)',
            r'banking (?:sector|industr|institution)',
            r'cryptocurrency (?:exchange|compan|firm|industr|platform|trading|business|sector|related)',
            r'fintech',
            r'insurance',
            r'payment (?:processor|system|compan)',
            r'investment (?:firm|bank|compan)',
            r'credit unions?',
            r'stock exchanges?',
        ),
    ),
    Industry(
        'healthcare',
        'Healthcare and pharmaceuticals',
        'Hospitals, health services, medical research and drug makers.',
        frozenset(
            {
                'healthcare',
                'health',
                'medical',
                'pharmaceuticals',
                'pharmacy',
                'biomedical',
                'covid-19 research organizations',
            }
        ),
        _phrases(
            r'health ?care',
            r'hospitals?\b',
            r'medical',
            r'pharmaceutical',
            r'biotech',
            r'health (?:sector|organi)',
            r'public health',
        ),
    ),
    Industry(
        'energy',
        'Energy and utilities',
        'Oil and gas, electricity, nuclear power, water and other utilities.',
        frozenset({'energy', 'electric', 'gas', 'oil', 'petroleum'}),
        _phrases(
            r'energy',
            r'oil and (?:natural )?gas',
            r'petroleum',
            r'petrochemical',
            r'electric(?:al|ity)? ',
            r'utilit(?:y|ies)',
            r'power (?:grid|plant|generation|compan)',
            r'nuclear (?:power|energy|plant)',
            r'water (?:utilit|treatment|sector)',
        ),
    ),
    Industry(
        'telecommunications',
        'Telecommunications',
        'Phone, mobile and internet providers.',
        frozenset({'telecommunications', 'telecoms', 'telecomms'}),
        _phrases(
            r'telecommunications?',
            r'telecoms?\b',
            r'mobile (?:operator|network|carrier)',
            r'internet service providers?',
            r'\bISPs?\b',
        ),
    ),
    Industry(
        'technology',
        'Technology and IT services',
        'Software and hardware makers, IT and managed service providers, chip makers.',
        frozenset(
            {
                'high-tech',
                'high tech',
                'technology',
                'information technology',
                'electronics manufacturers',
                'semiconductor industry',
                'electronic',
            }
        ),
        _phrases(
            r'technology(?=,| and| sectors?\b| industr| compan| firms?\b| organi[sz]ation| provider'
            r'| related)',
            r'high[- ]tech',
            r'(?:IT|managed) service providers?',
            r'\bMSPs?\b',
            r'software (?:compan|vendor|develop)',
            r'semiconductor',
            r'information technology',
            r'IT (?:compan|sector|firm|industr)',
            r'tech compan',
            r'cloud (?:service )?providers?',
        ),
    ),
    Industry(
        'education',
        'Education and research',
        'Universities, schools, research institutes and scientists.',
        frozenset(
            {
                'education',
                'universities',
                'academia - university',
                'scientific research',
                'research - innovation',
            }
        ),
        _phrases(
            r'universit(?:y|ies)',
            r'academi[ac]',
            r'education(?:al)?',
            r'research (?:institut|cent|organi)',
            r'schools?\b',
            r'scientists?',
        ),
    ),
    Industry(
        'media',
        'Media and entertainment',
        'News outlets, journalists, broadcasters, entertainment and video game companies.',
        frozenset(
            {'media', 'media and entertainment', 'news - media', 'journalist', 'entertainment', 'gaming'}
        ),
        _phrases(
            r'media (?:outlet|organi[sz]ation|compan|sector|industr)',
            r'journalists?',
            r'news (?:organi|outlet|agenc|media)',
            r'broadcast',
            r'entertainment',
            r'video ?games?',
            r'gaming (?:compan|industr)',
        ),
    ),
    Industry(
        'civil_society',
        'Civil society, think tanks and politics',
        'Non-profit and human rights groups, think tanks, activists and political parties.',
        frozenset(
            {
                'civil society',
                'ngos',
                'think tanks',
                'activists',
                'dissidents',
                'non-profit organisation',
                'religious organization',
                'pro-democracy and human rights political organizations',
                'opposition',
                'political party',
            }
        ),
        _phrases(
            r'non-?governmental',
            r'\bNGOs?\b',
            r'think[- ]tanks?',
            r'dissidents?',
            r'activists?',
            r'human rights',
            r'political (?:organi[sz]ation|part|campaign|figure|group)',
            r'civil society',
            r'non-?profit',
            r'religious',
            r'opposition',
        ),
    ),
    Industry(
        'manufacturing',
        'Manufacturing, industry and engineering',
        'Factories, chemical and car makers, mining, construction and engineering firms.',
        frozenset(
            {
                'manufacturing',
                'critical manufacturing',
                'industrial',
                'chemical',
                'engineering',
                'automotive',
                'construction',
                'mining',
                'civil engineering',
            }
        ),
        _phrases(
            r'manufactur',
            r'industrial (?:sector|compan|control|organi)',
            r'chemical(?=,| and| compan| industr| sectors?\b| manufactur| plant)',
            r'chemistry',
            r'automotive',
            r'(?<!social )engineering(?=,| and| compan| firms?\b| sectors?\b| organi[sz]ation)',
            r'mining(?=,| and| compan| industr| sectors?\b)',
            r'construction',
            r'heavy industry',
        ),
    ),
    Industry(
        'transportation',
        'Transport and logistics',
        'Airlines, shipping, rail, ports and logistics firms.',
        frozenset({'transportation', 'transportation systems', 'rail', 'logistics', 'maritime', 'aviation'}),
        _phrases(
            r'transportation',
            r'aviation',
            r'logistics',
            r'shipping',
            r'maritime',
            r'airlines?',
            r'airports?',
            r'railways?',
            r'\bports?\b(?! ?\d)',
        ),
    ),
    Industry(
        'retail',
        'Retail, hospitality and gambling',
        'Shops, online stores, hotels, restaurants, travel, casinos and gambling firms.',
        frozenset(
            {
                'retail',
                'hospitality',
                'travel',
                'gambling companies',
                'gambling websites',
            }
        ),
        _phrases(
            r'retail',
            r'hospitality',
            r'hotels?',
            r'restaurants?',
            r'point[- ]of[- ]sale',
            r'e-?commerce',
            r'casinos?',
            r'gambling',
            r'online gambling',
            r'travel',
        ),
    ),
    Industry(
        'legal',
        'Legal and professional services',
        'Law firms, consultancies and other business services.',
        frozenset({'legal'}),
        _phrases(
            r'law firms?', r'legal (?:sector|services|firm)', r'consult(?:ing|ancy|ancies) (?:firm|compan)'
        ),
    ),
    Industry(
        'agriculture',
        'Food and agriculture',
        'Farming, food production and food suppliers.',
        frozenset({'food and agriculture'}),
        _phrases(r'agricultur', r'food (?:sector|industr|compan|production)'),
    ),
)

BY_KEY: Final[dict[str, Industry]] = {industry.key: industry for industry in INDUSTRIES}

#: A sentence must say the group went after someone before a sector phrase in it counts.
TARGETING: Final = re.compile(
    r'\b(?:target\w*|against|victim\w*|compromis\w*|intru\w*|attack\w*|breach\w*|focus\w*|'
    r'espionage|operations? (?:expanded|included|have included)|infiltrat\w*|struck|hit)\b',
    re.IGNORECASE,
)
#: Phrases that name who a group works for or resembles, not whom it attacks; removed before matching.
NOT_A_VICTIM: Final = re.compile(
    r'\b(?:on behalf of|sponsored by|backed by|tied to|linked to|attributed to|associated with|working for|'
    r'operat\w* (?:for|on behalf of)|serv\w* the|support\w* the|unit of|part of|employed by|affiliated with|'
    r'contracted by|indicted by|according to|conducted by|nexus to|within|subordinate|via)\b[^.;,]{0,80}|'
    r'\b(?:Military Unit Cover Designator|Unit \d+|'
    r'Ministry of (?:Intelligence|State Security|Public Security)|'
    r'Reconnaissance (?:General )?Bureau|Prohibition of Chemical Weapons)\b[^.;,]{0,40}',
    re.IGNORECASE,
)
#: The end of a sentence: its full stop and the ``(Citation: ...)`` markers that follow it.
_SENTENCE_END: Final = re.compile(r'[.!?](?:\s*\(Citation: [^)]*\))*(?=\s+[A-Z\[]|\s*$)')
_LINK: Final = re.compile(r'\[([^\]]+)\]\(https?://[^)]+\)')
_CITATION: Final = re.compile(r'\s*\(Citation: [^)]*\)')


def plain(text: str) -> str:
    """ATT&CK prose without Markdown links and citation markers, on one line."""
    return ' '.join(_CITATION.sub('', _LINK.sub(r'\1', text)).split())


def sentences(text: str) -> list[str]:
    """``text`` split into sentences, each still carrying its ``(Citation: ...)`` markers."""
    found, start = [], 0
    for end in _SENTENCE_END.finditer(text):
        found.append(text[start : end.end()].strip())
        start = end.end()
    found.append(text[start:].strip())
    return [s for s in found if s]


def industries_in(description: str) -> dict[str, str]:
    """``{industry key: the sentence naming it}`` for an ATT&CK group description (first sentence wins)."""
    found: dict[str, str] = {}
    for sentence in sentences(description):
        text = plain(sentence)
        if not TARGETING.search(text):
            continue
        victims = NOT_A_VICTIM.sub(' ', text)
        for industry in INDUSTRIES:
            if industry.key not in found and industry.phrases.search(victims):
                found[industry.key] = sentence.strip()
    return found


def industry_for_label(label: str) -> str | None:
    """The industry a catalog label (``Healthcare``, ``Telecoms``) means, or ``None`` if it is too vague."""
    folded = ' '.join(label.split()).casefold()
    return next((industry.key for industry in INDUSTRIES if folded in industry.labels), None)
