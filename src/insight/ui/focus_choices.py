"""Shared starting points for focused intelligence briefs and threat hunt guides."""

from __future__ import annotations

from typing import Final

FOCUS_KINDS: Final = {
    'industry': 'Sector / Industry',
    'theme': 'Threat type',
    'actor': 'Threat actor',
    'cve': 'Software flaw (CVE)',
    'document': 'Report or advisory',
    'exploit': 'Exploit activity',
    'software': 'Malware or tool',
    'indicator': 'Indicator',
    'campaign': 'Campaign',
}
