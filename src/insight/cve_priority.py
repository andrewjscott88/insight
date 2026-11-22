"""The prioritised CVE view (TIP 1.3): which CVEs in your reports to look at first, and why, in plain words.

Insight ranks by stated rules, not a hidden score, so an analyst can always see why a CVE is where it is:

1. **Used in ransomware campaigns**: on CISA's Known Exploited Vulnerabilities (KEV) list, and CISA knows of
   ransomware campaigns that use it.
2. **Known to be exploited**: on CISA's KEV list.
3. **Reported exploited**: VulnCheck KEV lists exploitation in the wild (TIP 3.3; only if looked up).
4. **Public exploit**: a report you can see, or VulnCheck, says exploit code is public (TIP 3.3).
5. **Likely to be attacked soon**: an EPSS score of 10% or more (FIRST's estimate for the next 30 days).
6. **Critical**: a CVSS base score of 9 or more (NIST NVD, or a CISA advisory).
7. **High**: a CVSS base score of 7 or more.
8. **No strong signal yet**: everything else, including CVEs not looked up yet.

Within a group: higher EPSS first, then higher CVSS, more reports, and the most recently seen. Nothing here
says whether the reader's organisation uses the product: every signal describes the weakness, not exposure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .brief import count_of
from .cve_scores import describe_epss, describe_nvd, describe_vulncheck
from .exploit_signals import LABELS
from .services import CveSignal

#: EPSS probability from which a CVE counts as likely to be attacked soon (as in the brief).
LIKELY: Final = 0.1
CRITICAL: Final = 9.0
HIGH: Final = 7.0
#: ``tier -> (short label, why it ranks there)``.
TIERS: Final[dict[int, tuple[str, str]]] = {
    1: ('Used in ransomware', 'CISA knows of ransomware campaigns that use it.'),
    2: ('Known exploited', "It is on CISA's list of weaknesses attackers have used."),
    3: ('Reported exploited', 'VulnCheck KEV lists reports of attackers using it.'),
    4: ('Public exploit', 'A report or VulnCheck says exploit code for it is public.'),
    5: ('Likely attacked soon', 'EPSS gives it a 10% or higher chance of attack attempts in 30 days.'),
    6: ('Critical', 'Its CVSS base score is 9 or more.'),
    7: ('High', 'Its CVSS base score is 7 or more.'),
    8: ('No strong signal', 'No KEV entry, public exploit, high EPSS score or high CVSS score is known yet.'),
}


@dataclass(frozen=True, slots=True)
class PrioritisedCve:
    signal: CveSignal
    tier: int
    #: The highest CVSS base score known (NIST NVD or a CISA advisory), and where it comes from.
    cvss: float | None
    cvss_source: str
    epss: float | None

    @property
    def label(self) -> str:
        return TIERS[self.tier][0]

    @property
    def reason(self) -> str:
        return TIERS[self.tier][1]


def _cvss(signal: CveSignal) -> tuple[float | None, str]:
    nvd = signal.scores.nvd
    nvd_score = nvd.score if nvd is not None and nvd.status != 'Rejected' else None
    if signal.csaf_score is not None and (nvd_score is None or signal.csaf_score > nvd_score):
        return signal.csaf_score, 'CISA advisory'
    return (nvd_score, 'NIST NVD') if nvd_score is not None else (None, '')


def prioritise(signal: CveSignal) -> PrioritisedCve:
    cvss, source = _cvss(signal)
    epss = signal.scores.epss.probability if signal.scores.epss is not None else None
    if signal.kev is not None and signal.kev.ransomware:
        tier = 1
    elif signal.kev is not None:
        tier = 2
    elif signal.exploit is not None and signal.exploit.reported_exploited:
        tier = 3
    elif signal.exploit is not None and signal.exploit.public_exploit:
        tier = 4
    elif epss is not None and epss >= LIKELY:
        tier = 5
    elif cvss is not None and cvss >= CRITICAL:
        tier = 6
    elif cvss is not None and cvss >= HIGH:
        tier = 7
    else:
        tier = 8
    return PrioritisedCve(signal, tier, cvss, source, epss)


def rank(signals: list[CveSignal]) -> list[PrioritisedCve]:
    """Most urgent first, by the rules in this module's docstring."""
    ranked = [prioritise(s) for s in signals]
    # Stable sorts, least important key first.
    ranked.sort(key=lambda p: p.signal.cve)
    ranked.sort(key=lambda p: p.signal.last_seen, reverse=True)
    ranked.sort(key=lambda p: p.signal.reports, reverse=True)
    ranked.sort(key=lambda p: p.cvss if p.cvss is not None else -1.0, reverse=True)
    ranked.sort(key=lambda p: p.epss if p.epss is not None else -1.0, reverse=True)
    ranked.sort(key=lambda p: p.tier)
    return ranked


def details(item: PrioritisedCve) -> list[str]:
    """The facts behind one row, one plain line each."""
    signal, lines = item.signal, []
    if kev := signal.kev:
        line = f"On CISA's known exploited list since {kev.date_added}"
        line += ', used in ransomware campaigns.' if kev.ransomware else '.'
        if kev.due_date:
            line += f' US federal agencies must fix it by {kev.due_date}.'
        lines.append(line)
    if signal.scores.nvd is not None:
        lines.append(describe_nvd(signal.scores.nvd))
    if signal.csaf_score is not None:
        lines.append(f'CVSS {signal.csaf_score:g} in a CISA advisory')
    if signal.scores.epss is not None:
        lines.append(describe_epss(signal.scores.epss))
    if (exploit := signal.exploit) is not None:
        for kind, count in sorted(exploit.reports.items()):
            lines.append(
                f'{count_of(count, "report")} mention{"s" if count == 1 else ""} {LABELS[kind]} near it'
            )
        if exploit.vulncheck is not None:
            lines.append(describe_vulncheck(exploit.vulncheck))
    if not (signal.scores.nvd_checked_at or signal.scores.epss_checked_at):
        lines.append('Not looked up at NIST NVD or FIRST EPSS yet.')
    seen = f'{count_of(signal.reports, "report")} from {count_of(signal.sources, "source")}'
    lines.append(f'{seen} · last seen {signal.last_seen[:10]}')
    return lines
