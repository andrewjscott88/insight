"""Fixed, source-based steps for a hunt plan; not detections or findings."""

from __future__ import annotations

from collections.abc import Iterable

from .hunt_guide import GuideSection
from .threat_library import library, technique_name

MAX_TECHNIQUES = 12


def planning_sections(ids: Iterable[str]) -> tuple[GuideSection, ...]:
    """Map known techniques to the pinned library's data sources, without inferring an actor."""
    lib = library()
    found = tuple(dict.fromkeys(ids))
    steps = [
        'Choose the systems and dates to check. Confirm you have permission to search their logs.',
        'Check that the logs cover those dates. Start with a small sample and compare it with normal use.',
        'Use the checks below in your own search tool. A match is a lead to review, not proof of an attack.',
        'Record the time, host, account and source for each lead in your hunt or case tool. '
        'Send confirmed sightings or requests for more information back to Insight.',
    ]
    techniques, data, checks = [], [], []
    for tid in found[:MAX_TECHNIQUES]:
        techniques.append(
            f'{tid}: {technique_name(tid)}. '
            f'Source: https://attack.mitre.org/techniques/{tid.replace(".", "/")}/'
        )
        context = lib.techniques.get(tid)
        parent = False
        if (context is None or not context.detections) and '.' in tid:
            context = lib.techniques.get(tid.split('.')[0])
            parent = bool(context and context.detections)
        if context is None or not context.detections:
            checks.append(f'{tid}: No log-based check is in this library. Read the technique page first.')
            continue
        for detection in context.detections[:3]:
            note = ' Uses the parent technique as a starting point.' if parent else ''
            checks.append(f'{tid}: Review {detection.name}.{note} Source: {detection.url}')
            data += [lib.data_components.get(c, c) for c in detection.components[:6]]
            data += list(detection.log_sources[:6])
    if len(found) > MAX_TECHNIQUES:
        techniques.append(f'Shows the first {MAX_TECHNIQUES} techniques. Review the full profile for more.')
    sources = list(dict.fromkeys(data))
    source_lines = sources[:30]
    if len(sources) > 30:
        source_lines.append('Shows the first 30 log and data sources. Use the technique pages for more.')
    return (
        GuideSection('Start the hunt', tuple(steps)),
        GuideSection(
            'Behaviours to check', tuple(checks) or ('Choose a report with a clear behaviour to test.',)
        ),
        GuideSection(
            'Logs and data to gather',
            tuple(source_lines)
            or ('No log sources are mapped for this choice. Use the source report to plan what to collect.',),
        ),
        GuideSection(
            'Techniques and sources', tuple(techniques) or ('No fixed technique mapping is available.',)
        ),
    )
