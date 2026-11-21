"""YARA and Sigma rules in a threat guide (TIP 2.7 minimum, TIP 2.10; ADR 0024).

Insight keeps the text of a rule, where it came from and its licence, and links it to a group or technique.
It never runs a rule. Rule text is shown as plain text.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import TLP_LEVELS, RuleInput, RuleLinkInput
from ..threat_guide import ThreatGuide
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .workspace import Workspace

KINDS: Final = {'sigma': 'Sigma (log searches)', 'yara': 'YARA (file patterns)'}


def render_rules(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    rules = guide.data.rules
    heading(f'Detection rules ({len(rules)})', 4)
    ui.label(
        'Rules you saved for this group or its techniques. Insight keeps them as text and never runs them.'
    ).classes('muted prose')
    for linked in rules:
        rule = linked.rule
        with ui.expansion(f'{rule.name} · {KINDS.get(rule.kind, rule.kind)}').classes('w-full break-value'):
            tlp_badge(rule.tlp)
            ui.label(
                f'Licence: {rule.licence or "not given"} · fingerprint {rule.content_hash[:16]}'
            ).classes('muted text-sm break-value')
            if rule.source_url:
                new_tab_link('Where the rule came from', rule.source_url)
            ui.label('Linked to: ' + ', '.join(f'{kind} {target}' for kind, target in linked.links)).classes(
                'text-sm break-value'
            )
            ui.label(rule.body).classes('source-body font-mono text-sm w-full')
    ui.button(
        'Add a rule', icon='add', on_click=lambda: open_rule_dialog(ws, guide.data.subject.ref, refresh)
    ).props('outline no-caps')


def open_rule_dialog(ws: Workspace, group_ref: str, on_saved: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with (
        ui.dialog().props('aria-label="Add a rule"') as dialog,
        ui.card().classes('panel dialog-card w-[42rem] max-w-full p-6 gap-3'),
    ):
        heading('Add a rule', 2)
        ui.label(
            'Paste a rule. It will be linked to this group. You can also link it to a technique.'
        ).classes('muted prose')
        kind = ui.select(KINDS, value='sigma', label='Kind of rule').props('outlined')
        name = ui.input('Name').props('outlined maxlength=200')
        body = ui.textarea('Rule text').props('outlined maxlength=100000').classes('w-full font-mono')
        technique = ui.input('Technique ID (optional), such as T1059.001').props('outlined maxlength=16')
        licence = ui.input('Licence (optional)').props('outlined maxlength=120')
        source = ui.input('Web address it came from (optional)').props('outlined maxlength=2000')
        label = ui.select([t for t in TLP_LEVELS if services.tlp_permitted(t, limit)], label='TLP')
        label.props('outlined').set_value(services.stricter_limit('AMBER', limit))
        problem = problem_area()

        def save() -> None:
            if not ws.authorized():
                return
            try:
                payload = RuleInput.model_validate(
                    {
                        'kind': kind.value,
                        'name': name.value or 'Unnamed rule',
                        'body': body.value or '',
                        'licence': licence.value or '',
                        'source_url': source.value or '',
                        'tlp': label.value,
                    }
                )
                with ws.write() as db:
                    rule = services.add_rule(db, payload, max_tlp=limit)
                    services.link_rule(db, rule.id, RuleLinkInput(target_kind='group', target_id=group_ref))
                    if (technique.value or '').strip():
                        services.link_rule(
                            db,
                            rule.id,
                            RuleLinkInput(target_kind='technique', target_id=technique.value.strip()),
                        )
            except ValidationError:
                problem.set_text('Paste the rule text. A web address must start with https.')
                return
            except (LookupError, ValueError) as exc:
                problem.set_text(str(exc))
                return
            dialog.close()
            on_saved()
            tell('Rule saved and linked.', 'success')

        with ui.row():
            ui.button('Save', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()
