"""The prioritised CVE tab (TIP 1.3): the CVEs in your reports, most urgent first, and why.

The order comes from ``insight.cve_priority``: stated rules (ransomware, known exploited, likely to be
attacked, critical, high), never a hidden score. Each row says what is known and opens its newest report or
the indicator in the entity explorer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

from nicegui import ui

from .. import services
from ..brief import DEMO
from ..cve_priority import TIERS, PrioritisedCve, details, rank
from ..cve_scores import VULNCHECK_NOTICE
from .typography import heading
from .workspace import Workspace

#: Period choices, in days.
PERIODS: Final[dict[int, str]] = {
    7: 'Last 7 days',
    30: 'Last 30 days',
    90: 'Last 90 days',
    365: 'Last 12 months',
}
#: Rows shown before "Show all".
FIRST_ROWS: Final = 25


def build_cves(ws: Workspace) -> None:
    def open_report(item: PrioritisedCve) -> None:
        if ws.authorized():
            ws.show_inbox()
            ws.open_document(item.signal.report_id)

    def show_indicator(item: PrioritisedCve) -> None:
        if ws.authorized():
            ws.show_entity(item.signal.cve)

    def row(item: PrioritisedCve) -> None:
        with ui.column().classes('panel w-full p-3 sm:p-4 gap-1 min-w-0').mark(f'cve-{item.signal.cve}'):
            with ui.row().classes('w-full items-center gap-2'):
                ui.label(item.signal.cve).classes('font-mono font-semibold break-value')
                ui.badge(item.label).props('outline')
            ui.label(item.reason).classes('prose')
            for line in details(item):
                ui.label(line).classes('muted text-sm prose break-value')
            if item.signal.exploit is not None and item.signal.exploit.vulncheck is not None:
                ui.label(VULNCHECK_NOTICE).classes('muted text-sm prose')
            with ui.row().classes('gap-x-4 gap-y-0'):
                ui.button(
                    f'Open the newest report: {item.signal.report_title}',
                    on_click=lambda i=item: open_report(i),
                ).props('flat dense no-caps align=left').classes('break-value text-left')
                ui.button('Show in the entity explorer', on_click=lambda i=item: show_indicator(i)).props(
                    'flat dense no-caps'
                )

    @ui.refreshable
    def listing() -> None:
        if not ws.authorized():
            return
        days = ws.state.cve_days
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with ws.read() as db:
            found = services.cve_signals(db, since=since, ignore=DEMO, max_tlp=ws.reader_limit)
        ranked = rank(found.signals)
        if not ranked:
            ui.label('No report from this time mentions a CVE yet.').classes('muted p-2')
            return
        counts = {tier: sum(1 for item in ranked if item.tier == tier) for tier in TIERS}
        ui.label(' · '.join(f'{TIERS[tier][0]}: {count}' for tier, count in counts.items() if count)).classes(
            'muted text-sm prose'
        )
        if found.truncated:
            ui.label(
                'Only the newest reports were read. Choose a shorter period to see all of them.'
            ).classes('text-warn text-sm prose')
        for item in ranked[:FIRST_ROWS]:
            row(item)
        if rest := ranked[FIRST_ROWS:]:
            with (
                ui.expansion(f'Show all {len(ranked)} CVEs').classes('w-full'),
                ui.column().classes('w-full gap-2'),
            ):
                for item in rest:
                    row(item)

    def choose(days: int) -> None:
        ws.state.cve_days = days
        listing.refresh()

    ws.on_refresh(listing.refresh)
    heading('Prioritised CVEs', 2)
    ui.label(
        'The weaknesses your reports mention, most urgent first. First come those CISA knows are used in '
        'ransomware, then others CISA knows attackers use, then those likely to be attacked soon (EPSS), '
        'then the most severe (CVSS). None of this shows whether you use the product.'
    ).classes('muted prose')
    ui.label(
        'How severe a CVE is and how likely an attack is come from automatic lookups. '
        'Turn them on in Settings.'
    ).classes('muted text-sm prose')
    ui.select(
        PERIODS, value=ws.state.cve_days, label='Reports added in', on_change=lambda e: choose(e.value)
    ).props('outlined').classes('w-60').mark('cve-period')
    with ui.column().classes('w-full gap-2'):
        listing()
