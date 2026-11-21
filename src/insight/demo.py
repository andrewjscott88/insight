"""Clearly labelled synthetic training data using reserved documentation address space only."""

from __future__ import annotations

from typing import Final

from sqlalchemy.orm import Session

from .schemas import TLP, DocumentInput
from .services import ingest, visible_levels
from .services.alerts import QUIET

REPORTS: Final[tuple[tuple[str, str, str, TLP], ...]] = (
    (
        'Training scenario: edge appliance activity',
        'Synthetic lab bulletin',
        'This is synthetic training data, not real intelligence. An analyst observed 192.0.2.44 '
        'connecting to https://relay.example.org/beacon?case=Alpha. The bulletin mentions CVE-2024-3400 '
        'as a research reference, not evidence that the lab appliance was exploited. Validate the context '
        'before accepting any observation.',
        'CLEAR',
    ),
    (
        'Training scenario: shared infrastructure pivot',
        'Synthetic hunt notes',
        'This is synthetic training data. The host relay.example.org and 192.0.2.44 appear in a second lab '
        'report. Their co-occurrence is a lead, not proof of attribution. Another host used 2001:db8::42. '
        'Track the source evidence and record your assessment.',
        'GREEN',
    ),
    (
        'Training scenario: suspicious file reference',
        'Synthetic malware exercise',
        'This is synthetic training data. Sample SHA256: ' + 'a3' * 32 + '. The text includes CVE-2023-34362 '
        'as background reading. A hash appearing in a report does not establish that the file is malicious.',
        'AMBER+STRICT',
    ),
)


def seed(db: Session, *, max_tlp: str | None = None) -> int:
    """Ingest the synthetic reports; returns how many were newly created (0 on repeat runs).

    Reports above ``max_tlp`` (the instance's ``INSIGHT_MAX_TLP``) are left out rather than stored past the
    limit (code review L4). Synthetic reports never fire alerts, even when they mention a watch term.
    """
    allowed = visible_levels(max_tlp)
    quiet = db.info.get(QUIET)
    db.info[QUIET] = True
    try:
        return sum(
            ingest(db, DocumentInput(title=title, source_name=source, body=body, tlp=tlp), max_tlp=max_tlp)[1]
            for title, source, body, tlp in REPORTS
            if tlp in allowed
        )
    finally:
        db.info[QUIET] = quiet
