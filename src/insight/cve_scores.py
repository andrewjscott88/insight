"""Scores per CVE from the cached NVD and EPSS answers (review C2): parsing and plain wording.

Insight caches each provider's whole JSON answer (``enrichments``); this module reads the parts analysts use.
It never raises on an odd answer: a field it cannot read is simply missing. Wording states what each provider
says and what the number does *not* mean (EPSS is a probability estimate, not a sign that you are exposed).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Final

#: Newest CVSS version first: NVD lists several for some CVEs.
_METRICS: Final = ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')
_NO_CWE: Final = frozenset({'NVD-CWE-Other', 'NVD-CWE-noinfo'})
EPSS_CAVEAT: Final = (
    'EPSS estimates how likely attackers are to try to exploit a weakness in the next 30 days. It says '
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
class CveScores:
    cve: str
    nvd: NvdScore | None = None
    epss: EpssScore | None = None
    nvd_checked_at: str = ''
    epss_checked_at: str = ''

    @property
    def checked(self) -> bool:
        return bool(self.nvd_checked_at or self.epss_checked_at)


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


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
        entries = [e for e in metrics.get(key) or [] if isinstance(e, dict)]
        if not entries:
            continue
        entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
        data: dict[str, Any] = entry['cvssData'] if isinstance(entry.get('cvssData'), dict) else {}
        score = _number(data.get('baseScore'))
        severity = str(data.get('baseSeverity') or entry.get('baseSeverity') or '').title()
        version, vector = str(data.get('version') or ''), str(data.get('vectorString') or '')
        break
    descriptions = [d for d in cve.get('descriptions') or [] if isinstance(d, dict)]
    english = next((str(d.get('value', '')) for d in descriptions if d.get('lang') == 'en'), '')
    cwes = sorted(
        {
            str(d.get('value'))
            for w in cve.get('weaknesses') or []
            if isinstance(w, dict)
            for d in w.get('description') or []
            if isinstance(d, dict) and str(d.get('value', '')).startswith('CWE-')
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
    rows = payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return None
    rows = [r for r in rows if isinstance(r, dict)]
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


def scores(cve: str, cached: list[tuple[str, str, str]]) -> CveScores:
    """``cached`` is ``(provider, payload JSON, fetched_at)`` rows for ``cve``."""
    nvd = epss = None
    nvd_at = epss_at = ''
    for provider, payload, fetched_at in cached:
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if provider == 'nvd':
            nvd, nvd_at = parse_nvd(data), fetched_at
        elif provider == 'epss':
            epss, epss_at = parse_epss(data, cve), fetched_at
    return CveScores(cve, nvd, epss, nvd_at, epss_at)


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
        return 'NIST NVD: rejected, not a real weakness'
    if nvd.score is None:
        return f'NIST NVD: not scored yet ({nvd.status.lower() or "no score"})'
    severity = f' ({nvd.severity})' if nvd.severity else ''
    return f'CVSS {nvd.score:.1f}{severity}, NIST NVD'


def describe_epss(epss: EpssScore) -> str:
    """``EPSS 4.2% chance of exploitation attempts within 30 days, higher than 91% of CVEs (FIRST)``."""
    rank = f', higher than {epss.percentile * 100:.0f}% of CVEs' if epss.percentile is not None else ''
    return f'EPSS {percent(epss.probability)} chance of exploitation attempts within 30 days{rank} (FIRST)'


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
    return ' · '.join(parts)
