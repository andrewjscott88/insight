"""Operator switches and per-lookup consent for infrastructure context."""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import passive_dns, pivot_data, pivots, services
from ..connectors import ProviderError
from .messages import problem_area, tell
from .typography import heading
from .workspace import Workspace


def _render_result(result: dict[str, Any]) -> None:
    if not result['found']:
        ui.label('This provider has no matching record.')
        return
    if result.get('truncated'):
        ui.label('This is a limited set of records, not a full history.').classes('muted prose')
    for record in result.get('records', []):
        with ui.expansion(record['name']).classes('w-full min-w-0').style('overflow-wrap:anywhere'):
            ui.label(f'Record type: {record["type"]}').classes('w-full min-w-0').style(
                'overflow-wrap:anywhere'
            )
            ui.label(f'Answer: {record["answer"]}').classes('w-full min-w-0').style('overflow-wrap:anywhere')
            ui.label(f'First seen: {record["first_seen"]}').classes('w-full min-w-0').style(
                'overflow-wrap:anywhere'
            )
            ui.label(f'Last seen: {record["last_seen"]}').classes('w-full min-w-0').style(
                'overflow-wrap:anywhere'
            )
            count = record['count'] if record['count'] is not None else 'Not supplied'
            ui.label(f'Count: {count}').classes('w-full min-w-0').style('overflow-wrap:anywhere')


def build_pivot_switches(ws: Workspace) -> None:
    heading('Infrastructure lookups', 3, 'subsection-title mt-4')
    ui.label(
        'Each provider starts off. Turning one on does not send any data. '
        'You must approve each new lookup. Cached answers are reused for 24 hours.'
    ).classes('muted prose')

    def change(provider: str, enabled: bool) -> None:
        if not ws.authorized():
            return
        try:
            with ws.write() as db:
                services.set_pivot_switch(db, provider, enabled)
        except ValueError as exc:
            tell(str(exc), 'warning')
            return
        tell(f'{pivot_data.PROVIDERS[provider]} is {"on" if enabled else "off"}.', 'success')
        ws.refresh_all()

    with ws.read() as db:
        switches = services.pivot_switches(db)
    for provider, name in pivot_data.PROVIDERS.items():
        switch = ui.switch(
            f'Use {name}', value=switches[provider], on_change=lambda e, p=provider: change(p, bool(e.value))
        ).mark(f'pivot-switch-{provider}')
        if not passive_dns.configured():
            switch.disable()
    if not passive_dns.configured():
        ui.label('Set the CIRCL passive DNS credentials on the server first.').classes('muted prose')
    ui.label(
        'CIRCL shows past DNS records. Insight asks it to use stored records only. '
        'A record does not prove ownership or harm. Check the provider’s terms before use.'
    ).classes('muted prose')


def open_pivots(ws: Workspace, value: str) -> None:
    if not ws.authorized():
        return
    with ws.read() as db:
        try:
            cached = services.cached_pivots(db, value, max_tlp=None)
        except LookupError:
            return
        enabled = services.pivot_switches(db)
    kind, _ = pivot_data.subject(value)
    with (
        ui.dialog().props('aria-label="Infrastructure pivots"') as dialog,
        ui.card().classes('panel dialog-card gap-3'),
    ):
        heading(f'Infrastructure around {value}', 2).classes('w-full min-w-0').style('overflow-wrap:anywhere')
        ui.label(
            'These results describe infrastructure. They do not prove harm. '
            'Insight does not add them as indicators.'
        ).classes('muted prose')
        output = ui.column().classes('w-full break-value')

        def render() -> None:
            output.clear()
            with output:
                if not cached:
                    ui.label('No fresh cached results.')
                for result in cached:
                    heading(pivot_data.PROVIDERS[result['provider']], 3)
                    ui.label(f'Fetched: {result["fetched_at"]}').classes('muted text-sm')
                    _render_result(result)

        render()
        for provider, name in pivot_data.PROVIDERS.items():
            if not enabled[provider] or kind not in pivot_data.PROVIDER_KINDS[provider]:
                continue
            with ui.column().classes('w-full gap-2'):
                consent = (
                    ui.checkbox(f'I approve sending {value} to {name}.')
                    .classes('w-full min-w-0')
                    .style('overflow-wrap:anywhere')
                )
                ui.label(
                    'The value leaves Insight. This provider can see your interest in it. '
                    'A fresh cached answer needs no new request.'
                ).classes('muted prose')
                problem = problem_area()

                async def fetch(
                    p: str = provider, checkbox: ui.checkbox = consent, error: ui.label = problem
                ) -> None:
                    if not ws.authorized() or not checkbox.value:
                        return
                    checkbox.set_value(False)
                    error.set_text('')
                    try:
                        result = await pivots.lookup(
                            ws.sessions, p, value, approved=True, actor='operator', max_tlp=None
                        )
                    except (ProviderError, ValueError, LookupError, pivots.RateLimited) as exc:
                        if ws.authorized():
                            error.set_text(str(exc))
                        return
                    if ws.authorized():
                        cached[:] = [r for r in cached if r['provider'] != p] + [result]
                        render()

                ui.button(f'Look up at {name}', on_click=fetch).bind_enabled_from(consent, 'value')
        ui.button('Close', on_click=dialog.close).props('flat')
    dialog.open()
