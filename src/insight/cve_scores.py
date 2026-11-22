"""Scores per CVE from the cached NVD, EPSS and VulnCheck KEV answers (review C2, TIP 3.3): parsing, wording.

Insight caches each provider's whole JSON answer (``enrichments``); this module reads the parts analysts use.
It never raises on an odd answer: a field it cannot read is simply missing. Wording states what each provider
says and what the number does *not* mean (EPSS is a probability estimate, not a sign that you are exposed).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Final

#: CVSS base scores in the lines ``connectors.parse_csaf`` writes for CISA advisories
#: (``tests/unit/test_brief.py`` checks the contract).
CSAF_SCORE_LINE: Final = re.compile(
    r'^- (CVE-\d{4}-\d{4,}), CVSS (?:2\.0|3(?:\.\d)?|4\.0) base score (\d{1,2}(?:\.\d+)?):', re.M
)
#: Newest CVSS version first: NVD lists several for some CVEs.
_METRICS: Final = ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')
_NO_CWE: Final = frozenset({'NVD-CWE-Other', 'NVD-CWE-noinfo'})
#: NVD's terms ask services that use its API to show this notice (https://nvd.nist.gov/developers).
NVD_NOTICE: Final = 'This product uses the NVD API but is not endorsed or certified by the NVD.'
#: VulnCheck's community terms ask for prominent attribution wherever VulnCheck KEV data is shown.
VULNCHECK_NOTICE: Final = 'Exploitation and exploit data from VulnCheck KEV, provided by VulnCheck.'
#: Exploit entries kept per CVE from VulnCheck (links to VulnCheck's own pages; never code or clone URLs).
MAX_VULNCHECK_EXPLOITS: Final = 10
#: Only links to VulnCheck's own exploit pages are kept and shown (never a repository or clone address).
_VULNCHECK_URL = re.compile(r'https://(?:[a-z0-9-]+\.)*vulncheck\.com/[^\s"<>\\]{0,300}')
EPSS_CAVEAT: Final = (
    'EPSS estimates how likely attackers are to try to use a weakness in the next 30 days. It says '
    'nothing about whether you use the product.'
)


@dataclass(frozen=True, slots=True)
class NvdScore:
    #: The CVSS base score (0-10), or ``None`` when NVD has not scored the CVE yet.
    score: float | None
    severity: str
    version: str
    vector: str
    #: NVD's status, such as ``Analyzed``, ``Awaiting Analysis`` or ``Rejected``.
    status: str
    published: str
    description: str
    cwes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EpssScore:
    #: The probability (0-1) of exploitation attempts in the next 30 days.
    probability: float
    #: The share of scored CVEs with a lower probability (0-1).
    percentile: float | None
    date: str


@dataclass(frozen=True, slots=True)
class VulnCheckExploit:
    xdb_id: str
    url: str
    exploit_type: str
    date_added: str


@dataclass(frozen=True, slots=True)
class VulnCheckEntry:
    """What VulnCheck KEV says about one CVE (TIP 3.3). ``listed`` is ``False`` when it was looked up and
    is not in the catalog."""

    listed: bool
    date_added: str = ''
    exploits: tuple[VulnCheckExploit, ...] = ()
    #: All exploit entries VulnCheck lists (``exploits`` keeps at most ``MAX_VULNCHECK_EXPLOITS``).
    exploit_count: int = 0
    #: How many public reports of exploitation VulnCheck cites.
    reported_count: int = 0
    #: VulnCheck's own honeypots ("canaries") saw exploitation attempts.
    canaries: bool = False
    ransomware: bool = False


@dataclass(frozen=True, slots=True)
class CveScores:
    cve: str
    nvd: NvdScore | None = None
    epss: EpssScore | None = None
    nvd_checked_at: str = ''
    epss_checked_at: str = ''
    vulncheck: VulnCheckEntry | None = None
    vulncheck_checked_at: str = ''

    @property
    def checked(self) -> bool:
        return bool(self.nvd_checked_at or self.epss_checked_at or self.vulncheck_checked_at)


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _dicts(value: Any) -> list[dict[str, Any]]:
    """The objects in a JSON list; anything else is treated as an empty list."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def parse_nvd(payload: Any) -> NvdScore | None:
    """NVD's answer for one CVE (``/rest/json/cves/2.0?cveId=``); ``None`` if NVD does not know it."""
    try:
        cve = payload['vulnerabilities'][0]['cve']
    except (KeyError, IndexError, TypeError):
        return None
    if not isinstance(cve, dict):
        return None
    score, severity, version, vector = None, '', '', ''
    metrics: dict[str, Any] = cve['metrics'] if isinstance(cve.get('metrics'), dict) else {}
    for key in _METRICS:
        entries = _dicts(metrics.get(key))
        if not entries:
            continue
        entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
        data: dict[str, Any] = entry['cvssData'] if isinstance(entry.get('cvssData'), dict) else {}
        score = _number(data.get('baseScore'))
        severity = str(data.get('baseSeverity') or entry.get('baseSeverity') or '').title()
        version, vector = str(data.get('version') or ''), str(data.get('vectorString') or '')
        break
    english = next(
        (str(d.get('value', '')) for d in _dicts(cve.get('descriptions')) if d.get('lang') == 'en'), ''
    )
    cwes = sorted(
        {
            str(d.get('value'))
            for w in _dicts(cve.get('weaknesses'))
            for d in _dicts(w.get('description'))
            if str(d.get('value', '')).startswith('CWE-')
        }
        - _NO_CWE
    )
    return NvdScore(
        score=score,
        severity=severity,
        version=version,
        vector=vector,
        status=str(cve.get('vulnStatus') or ''),
        published=str(cve.get('published') or '')[:10],
        description=' '.join(english.split())[:600],
        cwes=tuple(cwes),
    )


def parse_epss(payload: Any, cve: str) -> EpssScore | None:
    """FIRST's EPSS answer (``/data/v1/epss?cve=``); ``None`` when EPSS has no score for ``cve``."""
    rows = _dicts(payload.get('data') if isinstance(payload, dict) else None)
    row = next((r for r in rows if r.get('cve') == cve), rows[0] if len(rows) == 1 else None)
    probability = _number(row.get('epss')) if row else None
    if row is None or probability is None or not 0 <= probability <= 1:
        return None
    percentile = _number(row.get('percentile'))
    return EpssScore(
        probability=probability,
        percentile=percentile if percentile is not None and 0 <= percentile <= 1 else None,
        date=str(row.get('date') or ''),
    )


def _day(value: Any) -> str:
    text = str(value or '')[:10]
    return text if re.fullmatch(r'\d{4}-\d{2}-\d{2}', text) else ''


def _vulncheck_url(value: Any) -> str:
    url = str(value or '')
    return url if _VULNCHECK_URL.fullmatch(url) else ''


def _cves_of(row: dict[str, Any]) -> list[str]:
    value = row.get('cve')
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return [c.upper() for c in values if isinstance(c, str)]


def summarise_vulncheck(payload: Any, cve: str) -> dict[str, Any]:
    """The parts of a VulnCheck KEV answer (``/v3/index/vulncheck-kev?cve=``) Insight keeps, before caching.

    Metadata only: the entry's dates, counts and links to VulnCheck's exploit pages. Descriptions, clone URLs
    and anything else are dropped, so no exploit code or repository address is ever stored (ADR 0028).
    """
    rows = _dicts(payload.get('data') if isinstance(payload, dict) else None)
    row = next((r for r in rows if cve.upper() in _cves_of(r)), None)
    if row is None:
        return {'cve': cve, 'listed': False}
    exploits = _dicts(row.get('vulncheck_xdb'))
    kept = [
        {
            'xdb_id': str(item.get('xdb_id') or '')[:80],
            'url': _vulncheck_url(item.get('xdb_url')),
            'exploit_type': str(item.get('exploit_type') or '')[:40],
            'date_added': _day(item.get('date_added')),
        }
        for item in exploits[:MAX_VULNCHECK_EXPLOITS]
    ]
    return {
        'cve': cve,
        'listed': True,
        'date_added': _day(row.get('date_added')),
        'exploits': kept,
        'exploit_count': len(exploits),
        'reported_count': len(_dicts(row.get('vulncheck_reported_exploitation'))),
        'canaries': row.get('reported_exploited_by_vulncheck_canaries') is True,
        'ransomware': row.get('knownRansomwareCampaignUse') == 'Known',
    }


def parse_vulncheck(stored: Any) -> VulnCheckEntry | None:
    """A cached :func:`summarise_vulncheck` result; ``None`` if it cannot be read."""
    if not isinstance(stored, dict) or not isinstance(stored.get('listed'), bool):
        return None
    if not stored['listed']:
        return VulnCheckEntry(listed=False)

    def count(name: str) -> int:
        value = stored.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    exploits = tuple(
        VulnCheckExploit(
            str(e.get('xdb_id', ''))[:80],
            _vulncheck_url(e.get('url')),
            str(e.get('exploit_type', ''))[:40],
            _day(e.get('date_added')),
        )
        for e in _dicts(stored.get('exploits'))[:MAX_VULNCHECK_EXPLOITS]
    )
    return VulnCheckEntry(
        listed=True,
        date_added=_day(stored.get('date_added')),
        exploits=exploits,
        exploit_count=max(count('exploit_count'), len(exploits)),
        reported_count=count('reported_count'),
        canaries=stored.get('canaries') is True,
        ransomware=stored.get('ransomware') is True,
    )


def scores(cve: str, cached: list[tuple[str, str, str]]) -> CveScores:
    """``cached`` is ``(provider, payload JSON, fetched_at)`` rows for ``cve``."""
    nvd = epss = vulncheck = None
    nvd_at = epss_at = vulncheck_at = ''
    for provider, payload, fetched_at in cached:
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if provider == 'nvd':
            nvd, nvd_at = parse_nvd(data), fetched_at
        elif provider == 'epss':
            epss, epss_at = parse_epss(data, cve), fetched_at
        elif provider == 'vulncheck':
            vulncheck, vulncheck_at = parse_vulncheck(data), fetched_at
    return CveScores(cve, nvd, epss, nvd_at, epss_at, vulncheck, vulncheck_at)


# --------------------------------------------------------------------------- plain wording


def percent(probability: float) -> str:
    """``0.0423`` -> ``4.2%``; tiny values do not round to a misleading 0%."""
    value = probability * 100
    if value < 0.1:
        return 'under 0.1%'
    return f'{value:.1f}%' if value < 10 else f'{value:.0f}%'


def describe_nvd(nvd: NvdScore) -> str:
    """``CVSS 9.8 (Critical), NIST NVD`` or what NVD says instead."""
    if nvd.status == 'Rejected':
        return 'NIST NVD: rejected (withdrawn or a duplicate)'
    if nvd.score is None:
        return f'NIST NVD: not scored yet ({nvd.status.lower() or "no score"})'
    severity = f' ({nvd.severity})' if nvd.severity else ''
    return f'CVSS {nvd.score:.1f}{severity}, NIST NVD'


def describe_epss(epss: EpssScore) -> str:
    """``EPSS 4.2% chance of exploitation attempts within 30 days, higher than 91% of CVEs (FIRST)``."""
    # Rounded down and capped, so the 99.9th percentile never reads as "higher than 100%".
    share = min(99, math.floor(epss.percentile * 100)) if epss.percentile is not None else 0
    rank = f', higher than {share}% of CVEs' if share else ''
    return f'EPSS {percent(epss.probability)} chance of exploitation attempts within 30 days{rank} (FIRST)'


def describe_vulncheck(entry: VulnCheckEntry) -> str:
    """``VulnCheck KEV: exploited, listed 2025-06-07, 3 public exploits`` or ``Not in VulnCheck KEV``."""
    if not entry.listed:
        return 'Not in VulnCheck KEV'
    parts = ['VulnCheck KEV: exploited']
    if entry.date_added:
        parts.append(f'listed {entry.date_added}')
    if entry.exploit_count:
        parts.append(f'{entry.exploit_count} public exploit{"s" if entry.exploit_count != 1 else ""}')
    if entry.canaries:
        parts.append("seen by VulnCheck's sensors")
    return ', '.join(parts)


def summary(found: CveScores) -> str:
    """One line for the reader, such as ``CVSS 9.8 (Critical), NIST NVD · EPSS 97% chance ...``."""
    parts = []
    if found.nvd is not None:
        parts.append(describe_nvd(found.nvd))
    elif found.nvd_checked_at:
        parts.append('NIST NVD has no record of it yet')
    if found.epss is not None:
        parts.append(describe_epss(found.epss))
    elif found.epss_checked_at:
        parts.append('No EPSS score yet')
    if found.vulncheck is not None:
        parts.append(describe_vulncheck(found.vulncheck))
    return ' · '.join(parts)
