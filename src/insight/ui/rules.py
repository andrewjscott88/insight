"""YARA, Sigma, Suricata and Snort rules in a threat guide (TIP 2.7, 2.10 and 4.3; ADR 0025).

Insight keeps the text of a rule, where it came from and its licence, and links it to a group or technique.
It never runs a rule. Rule text is shown as plain text.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import TLP_LEVELS, RuleInput, RuleLinkInput
from ..services.rules import LinkedRule
from ..threat_guide import ThreatGuide
from .messages import problem_area, tell
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .verdicts import suggested_tlp
from .workspace import Workspace

KINDS: Final = {
    'sigma': 'Sigma (log searches)',
    'yara': 'YARA (file patterns)',
    'suricata': 'Suricata (network traffic)',
    'snort': 'Snort (network traffic)',
}


def render_rules(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    rules = guide.data.rules
    heading(f'Detection rules ({len(rules)})', 4)
    ui.label('Rules linked to this group, its techniques or its reports.').classes('muted prose')
    _show_rules(rules)
    ui.button(
        'Add a rule',
        icon='add',
        on_click=lambda: open_rule_dialog(
            ws, RuleLinkInput(target_kind='group', target_id=guide.data.subject.ref), refresh
        ),
    ).props('outline no-caps')


def _show_rules(rules: Sequence[LinkedRule]) -> None:
    for linked in rules:
        rule = linked.rule
        with ui.expansion(f'{rule.name} · {KINDS.get(rule.kind, rule.kind)}').classes('w-full break-value'):
            tlp_badge(linked.tlp)
            ui.label(
                f'Licence: {rule.licence or "not given"} · fingerprint {rule.content_hash[:16]}'
            ).classes('muted text-sm break-value')
            if rule.source_url:
                new_tab_link('Where the rule came from', rule.source_url)
            ui.label('Linked to: ' + ', '.join(f'{kind} {target}' for kind, target in linked.links)).classes(
                'text-sm break-value'
            )
            ui.label(rule.body).classes('source-body font-mono text-sm w-full')
            new_tab_link('Download rule and manifest', f'/api/rules/{rule.id}/export')


def render_report_rules(ws: Workspace, report_id: str, report_tlp: str, refresh: Callable[[], Any]) -> None:
    target = RuleLinkInput(target_kind='document', target_id=report_id)
    limit = ws.app.state.settings.max_tlp
    try:
        with ws.read() as db:
            rules = services.list_rules(db, target=target, max_tlp=limit)
    except LookupError:
        return
    with ui.expansion(f'Detection rules ({len(rules)})').classes('w-full'):
        _show_rules(rules)
        ui.button(
            'Add a rule to this report', on_click=lambda: open_rule_dialog(ws, target, refresh, report_tlp)
        ).props('outline no-caps')

        def choose_existing() -> None:
            if not ws.authorized():
                return
            with ws.read() as db:
                choices = {entry.rule.id: entry.rule.name for entry in services.list_rules(db, max_tlp=limit)}
            with ui.dialog() as dialog, ui.card().classes('panel dialog-card'):
                heading('Link a saved rule', 2)
                saved = (
                    ui.select(choices, label='Saved rule', with_input=True)
                    .classes('w-full')
                    .mark('saved-rule')
                )
                problem = problem_area()

                def attach() -> None:
                    if not ws.authorized():
                        return
                    if not saved.value:
                        problem.set_text('Choose a saved rule.')
                        return
                    try:
                        with ws.write() as db:
                            services.link_rule(db, saved.value, target, max_tlp=limit)
                    except (LookupError, ValueError) as exc:
                        problem.set_text(str(exc))
                        return
                    dialog.close()
                    refresh()
                    tell('Rule linked to this report.', 'success')

                ui.button('Link rule', on_click=attach).mark('attach-saved-rule')
                ui.button('Cancel', on_click=dialog.close).props('flat')
            dialog.open()

        ui.button('Link a saved rule', on_click=choose_existing).props('flat no-caps').mark(
            'choose-saved-rule'
        )


def open_rule_dialog(
    ws: Workspace, target: RuleLinkInput, on_saved: Callable[[], Any], source_tlp: str | None = None
) -> None:
    if not ws.authorized():
        return
    limit = ws.app.state.settings.max_tlp
    with (
        ui.dialog().props('aria-label="Add a rule"') as dialog,
        ui.card().classes('panel dialog-card w-[42rem] max-w-full p-6 gap-3'),
    ):
        heading('Add a rule', 2)
        ui.label(
            f'Paste a rule to attach to this {"report" if target.target_kind == "document" else "group"}.'
        ).classes('muted prose')
        kind = ui.select(KINDS, value='sigma', label='Kind of rule').props('outlined')
        name = ui.input('Name').props('outlined maxlength=200')
        body = ui.textarea('Rule text').props('outlined maxlength=100000').classes('w-full font-mono')
        technique = ui.input('Technique ID (optional), such as T1059.001').props('outlined maxlength=16')
        cve = ui.input('CVE (optional)').props('outlined maxlength=36')
        family = ui.input('Malware family (optional)').props('outlined maxlength=36')
        licence = ui.input('Licence (optional)').props('outlined maxlength=120')
        source = ui.input('Web address it came from (optional)').props('outlined maxlength=2000')
        permitted = [t for t in TLP_LEVELS if services.tlp_permitted(t, limit)]
        label = ui.select(permitted, value=suggested_tlp(source_tlp, permitted), label='TLP').props(
            'outlined'
        )
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
                    targets = [target]
                    if technique.value:
                        targets.append(
                            RuleLinkInput(target_kind='technique', target_id=technique.value.strip())
                        )
                    if cve.value:
                        targets.append(RuleLinkInput(target_kind='cve', target_id=cve.value.strip()))
                    if family.value:
                        targets.append(RuleLinkInput(target_kind='malware', target_id=family.value.strip()))
                    for link in targets:
                        services.link_rule(db, rule.id, link, max_tlp=limit)
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
            ui.button('Save', on_click=save).mark('save-detection-rule')
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()
