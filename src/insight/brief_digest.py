"""Short workspace takeaways from the same date-checked facts as the detailed brief."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from .brief_facts import _facts, _product, count_of, name_list

if TYPE_CHECKING:
    from .landscape import Landscape
    from .services import BriefData


def executive_takeaways(data: BriefData, landscape: Landscape) -> tuple[str, ...]:
    """At most three takeaways; full findings remain in the cards and briefing export."""
    facts = _facts(data, datetime.fromisoformat(landscape.brief.as_of))
    known = {item.cve: item for item in facts.kev_added}
    known.update((item.cve, item) for item, _, _, _ in facts.kev_mentioned)
    if not facts.fresh and not known:
        return ('No recent intelligence is available. Sync your sources and check their status in Settings.',)

    lines = []
    if known:
        products = sorted(known.values(), key=lambda item: not item.ransomware)
        names = name_list([_product(item) for item in products], limit=2)
        verb = 'has' if len(known) == 1 else 'have'
        line = (
            f'Known attacks: {count_of(len(known), "flaw")} in this brief {verb} been used in attacks. '
            f'Affected products include {names}.'
        )
        if ransomware := sum(item.ransomware for item in products):
            verb = 'has' if ransomware == 1 else 'have'
            line += f' {ransomware} {verb} been used in ransomware.'
        lines.append(line)

    context = []
    if facts.severe:
        verb = 'is' if len(facts.severe) == 1 else 'are'
        context.append(
            f'{count_of(len(facts.severe), "flaw")} {verb} rated critical: '
            'potential serious harm, not proof of attacks.'
        )
    if landscape.threats:
        top = landscape.threats[0]
        if top.change.label == 'rising':
            context.append(f'Reports about {top.name.lower()} are rising.')
        elif top.change.label == 'new':
            context.append(f'{top.name} is a new topic in your reports.')
        else:
            top = max(landscape.threats, key=lambda item: item.change.current)
            context.append(f'{top.name} is the most reported threat type.')
    if context:
        lines.append('Also watch: ' + ' '.join(context) if lines else 'In focus: ' + ' '.join(context))

    if known or facts.severe:
        action = 'Next step: Check whether you use the named products and versions. '
        action += (
            'Prioritize fixes for flaws already used in attacks.'
            if known
            else "Review the vendor's fix guidance for affected systems."
        )
        lines.append(action)
    elif landscape.threats:
        lines.append('Next step: ' + landscape.threats[0].check)
    else:
        lines.append('No clear priority stands out in these reports. Review the latest advisories in Triage.')
    return tuple(lines)
