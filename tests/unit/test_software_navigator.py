"""Software context does not increase direct group/report scores or alter hunt hypotheses."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.orm import Session

from insight import services
from insight.attack import catalog
from insight.software_navigator import software_navigator
from insight.threat_guide import compose, navigator_layer
from insight.threat_library import Software, library


def test_software_only_rows_have_zero_score_and_leave_existing_scores_and_hypotheses(db: Session) -> None:
    lib = library()
    data = services.guide_data(db, 'G0016', now=datetime.now(UTC))
    before = compose(data, lib)
    group = data.subject.catalog
    assert group is not None
    direct = group.techniques[0]
    extra = next(t.id for t in catalog().techniques.values() if t.id not in group.techniques)
    source = cast(
        'Software',
        SimpleNamespace(
            id='S9999',
            name='Synthetic software',
            type='tool',
            techniques=(direct, extra, 'T9999'),
            url='https://attack.mitre.org/software/S9999/',
        ),
    )
    test_lib = replace(lib, software={**lib.software, source.id: source})
    test_data = replace(
        data, subject=replace(data.subject, catalog=replace(group, software=(*group.software, source.id)))
    )
    after = compose(test_data, test_lib)
    old = {r['techniqueID']: r['score'] for r in navigator_layer(before)['techniques']}
    rows = {r['techniqueID']: r for r in navigator_layer(after)['techniques']}
    assert {tid: rows[tid]['score'] for tid in old} == old
    assert rows[extra]['score'] == 0
    assert 'Software only' in rows[extra]['comment']
    assert 'S9999 Synthetic software' in rows[extra]['comment']
    assert 'T9999' not in rows
    assert after.hypotheses == before.hypotheses
    assert after.techniques == before.techniques
    layer = software_navigator(test_lib, 's9999')
    assert {r['techniqueID'] for r in layer['techniques']} == {direct, extra}
    assert all(r['score'] == 1 for r in layer['techniques'])
    assert layer['versions']['layer'] == '4.5'
    assert {'name': 'TLP', 'value': 'TLP:CLEAR'} in layer['metadata']
    analyst = compose(
        replace(
            data, subject=replace(data.subject, catalog=None), linked_software=(source.id,), labels=('AMBER',)
        ),
        test_lib,
    )
    analyst_layer = navigator_layer(analyst)
    assert all(row['score'] == 0 for row in analyst_layer['techniques'])
    assert {row['techniqueID'] for row in analyst_layer['techniques']} == {direct, extra}
    assert analyst.hypotheses == ()
    assert {'name': 'TLP', 'value': 'TLP:AMBER'} in analyst_layer['metadata']


def test_legacy_software_without_techniques_is_valid_and_unknown_software_is_missing() -> None:
    lib = replace(library(), software={'S9998': Software('S9998', 'Legacy tool', 'tool')})
    assert software_navigator(lib, 'S9998')['techniques'] == []
    with pytest.raises(LookupError):
        software_navigator(lib, 'S0000')


def test_enterprise_actor_layers_exclude_mobile_and_ics_report_tags(db: Session) -> None:
    """Regression: adding new domain catalogs must not put their IDs into an Enterprise Navigator layer."""
    data = services.guide_data(db, 'G0016', now=datetime.now(UTC))
    guide = compose(replace(data, report_techniques={'T1398': 1, 'T0800': 1}), library())
    assert {'T1398', 'T0800'} <= {row.id for row in guide.techniques}
    assert not {'T1398', 'T0800'} & {row['techniqueID'] for row in navigator_layer(guide)['techniques']}
