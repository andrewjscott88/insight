"""Hunt packages (TIP 4.3, ADR 0034): labels, status rules, STIX projection and the TAXII collection."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, HuntPackage
from insight.schemas import (
    DocumentInput,
    HuntPackageInput,
    HuntPackageItemInput,
    HuntPackageUpdate,
    RuleInput,
    RuleLinkInput,
)
from insight.stix_export import TLP_MARKINGS
from insight.taxii import HUNT_PACKAGES_COLLECTION

SIGMA = (
    'title: Encoded PowerShell\nlogsource:\n  product: windows\n'
    'detection:\n  sel:\n    CommandLine|contains: -enc\n  condition: sel\n'
)
SURICATA = (
    'alert dns any any -> any any (msg:"Insight lab C2 domain"; dns.query; content:"example.test"; '
    'sid:1000001; rev:1;)'
)


def report(db: Session, body: str, tlp: str = 'GREEN', title: str = 'Note') -> Document:
    doc, _ = services.ingest(db, DocumentInput(title=title, body=body, source_name='Vendor', tlp=tlp))
    return doc


def entity(db: Session, value: str) -> str:
    found: str = db.scalars(select(Entity.id).where(Entity.value == value)).one()
    return found


def item(kind: str, target: str) -> HuntPackageItemInput:
    return HuntPackageItemInput.model_validate({'kind': kind, 'target_id': target})


def package(db: Session, *items: HuntPackageItemInput, tlp: str = 'GREEN', **fields: Any) -> HuntPackage:
    payload = {
        'title': 'Encoded PowerShell beacons',
        'hypothesis': 'A crew runs encoded PowerShell.',
        'tlp': tlp,
    }
    return services.create_hunt_package(
        db, HuntPackageInput.model_validate(payload | fields | {'items': items})
    )


def rule(db: Session, kind: str = 'sigma', body: str = SIGMA, tlp: str = 'GREEN') -> str:
    payload = RuleInput.model_validate({'kind': kind, 'name': f'{kind} rule', 'body': body, 'tlp': tlp})
    return services.add_rule(db, payload).id


def by_type(objects: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, list[dict[str, Any]]] = {}
    for obj in objects:
        found.setdefault(obj['type'], []).append(obj)
    return found


def test_a_package_takes_the_strictest_label_and_keeps_it(db: Session) -> None:
    amber = report(db, 'C2 at 203.0.113.60.', tlp='AMBER')
    created = package(db, item('technique', 't1059.001'), item('indicator', entity(db, '203.0.113.60')))
    assert (created.status, created.tlp) == ('draft', 'AMBER')
    view = services.get_hunt_package(db, created.id)
    assert [(i.kind, i.target_id, i.tlp) for i in view.items] == [
        ('indicator', entity(db, '203.0.113.60'), 'AMBER'),
        ('technique', 'T1059.001', 'CLEAR'),
    ]
    assert view.items[1].name == 'Command and Scripting Interpreter: PowerShell'
    indicator = view.items[0]
    services.remove_hunt_package_item(db, created.id, indicator.id)
    assert services.get_hunt_package(db, created.id).tlp == 'AMBER'  # removing never lowers the label
    lowered = services.update_hunt_package(db, created.id, HuntPackageUpdate(tlp='GREEN'))
    assert lowered.tlp == 'GREEN'
    services.add_hunt_package_item(db, created.id, item('document', amber.id))
    assert services.update_hunt_package(db, created.id, HuntPackageUpdate(tlp='CLEAR')).tlp == 'AMBER'
    marked = services.update_hunt_package(db, created.id, HuntPackageUpdate(hypothesis='TLP:RED source.'))
    assert marked.tlp == 'RED'


def test_hidden_targets_and_limits_are_refused(db: Session) -> None:
    hidden = report(db, 'C2 at 203.0.113.61.', tlp='AMBER')
    with pytest.raises(LookupError):
        services.create_hunt_package(
            db,
            HuntPackageInput(title='T', hypothesis='H', tlp='GREEN', items=[item('document', hidden.id)]),
            max_tlp='GREEN',
        )
    with pytest.raises(LookupError):
        package(db, item('technique', 'T9999'))
    with pytest.raises(services.TlpNotPermitted):
        services.create_hunt_package(
            db, HuntPackageInput(title='T', hypothesis='H', tlp='AMBER'), max_tlp='GREEN'
        )
    with pytest.raises(LookupError):
        package(db, group='G9999')
    assert package(db, group='g0016').group_ref == 'G0016'


def test_publishing_retiring_and_publishing_again(db: Session) -> None:
    draft = package(db)
    with pytest.raises(services.HuntPackageConflict):
        services.publish_hunt_package(db, draft.id)  # nothing to hunt for yet
    services.add_hunt_package_item(db, draft.id, item('technique', 'T1059.001'))
    published = services.publish_hunt_package(db, draft.id)
    assert (published.status, published.publication, published.published_at is not None) == (
        'published',
        0,
        True,
    )
    only = services.get_hunt_package(db, draft.id).items[0]
    with pytest.raises(services.HuntPackageConflict):
        services.remove_hunt_package_item(db, draft.id, only.id)  # the last huntable item
    with pytest.raises(services.HuntPackageConflict):
        services.delete_hunt_package(db, draft.id)  # retire first
    first = services.export_hunt_package(db, draft.id)
    services.retire_hunt_package(db, draft.id)
    with pytest.raises(services.HuntPackageConflict):
        services.update_hunt_package(db, draft.id, HuntPackageUpdate(title='New'))
    revoked = services.export_hunt_package(db, draft.id)
    assert all(o.get('revoked') for o in revoked['objects'] if o['type'] != 'marking-definition')
    assert {o['id'] for o in revoked['objects']} == {o['id'] for o in first['objects']}
    again = services.publish_hunt_package(db, draft.id)
    assert again.publication == 1
    fresh = services.export_hunt_package(db, draft.id)
    old_ids = {o['id'] for o in first['objects'] if o['type'] != 'marking-definition'}
    assert not old_ids & {o['id'] for o in fresh['objects']}  # a revoked STIX object never comes back
    services.retire_hunt_package(db, draft.id)
    services.delete_hunt_package(db, draft.id)
    actions = [e.action for e in db.scalars(select(AuditEvent).where(AuditEvent.object_id == draft.id))]
    for action in ('create', 'item.add', 'publish', 'retire', 'export', 'delete'):
        assert f'hunt_package.{action}' in actions


def test_stix_has_a_grouping_with_techniques_indicators_and_rules(db: Session) -> None:
    doc = report(db, 'C2 at 203.0.113.62, CVE-2024-3400 and example.test.', title='Vendor advisory')
    sigma, suricata = rule(db), rule(db, 'suricata', SURICATA)
    services.link_rule(db, sigma, RuleLinkInput(target_kind='technique', target_id='T1059.001'))
    created = package(
        db,
        item('technique', 'T1059.001'),
        item('indicator', entity(db, '203.0.113.62')),
        item('indicator', entity(db, 'CVE-2024-3400')),
        item('rule', sigma),
        item('rule', suricata),
        item('document', doc.id),
        group='G0016',
    )
    bundle = services.export_hunt_package(db, created.id)
    found = by_type(bundle['objects'])
    assert [m['id'] for m in found['marking-definition']] == [TLP_MARKINGS['GREEN']]
    (grouping,) = found['grouping']
    assert (grouping['name'], grouping['description']) == (created.title, created.hypothesis)
    assert grouping['context'] == 'suspicious-activity'
    assert len(grouping['object_refs']) == len(bundle['objects']) - 2
    references = {(r['source_name'], r.get('external_id')) for r in grouping['external_references']}
    assert {('mitre-attack', 'G0016'), ('Vendor', doc.id), ('Insight hunt package', created.id)} <= references
    patterns = {i['pattern_type']: i for i in found['indicator']}
    assert patterns['stix']['pattern'] == "[ipv4-addr:value = '203.0.113.62']"
    assert patterns['sigma']['pattern'] == SIGMA
    assert patterns['suricata']['pattern'] == SURICATA
    assert found['vulnerability'][0]['name'] == 'CVE-2024-3400'
    (technique,) = found['attack-pattern']
    (link,) = found['relationship']
    assert (link['source_ref'], link['relationship_type'], link['target_ref']) == (
        patterns['sigma']['id'], 'indicates', technique['id'],
    )  # fmt: skip
    for obj in bundle['objects']:
        if obj['type'] != 'marking-definition':
            assert obj['object_marking_refs'] == [TLP_MARKINGS['GREEN']]
            assert obj['created'] <= obj['modified']
    # Removing an item and adding it again gives it a new ID; every object gets the new version time.
    rule_item = next(i for i in services.get_hunt_package(db, created.id).items if i.target_id == sigma)
    services.remove_hunt_package_item(db, created.id, rule_item.id)
    services.add_hunt_package_item(db, created.id, item('rule', sigma))
    later = by_type(services.export_hunt_package(db, created.id)['objects'])
    assert patterns['sigma']['id'] not in {i['id'] for i in later['indicator']}
    assert later['grouping'][0]['modified'] > grouping['modified']


def test_deleting_a_rule_or_report_updates_the_package(db: Session) -> None:
    doc = report(db, 'C2 at 203.0.113.63.')
    sigma = rule(db)
    created = package(db, item('rule', sigma), item('technique', 'T1059.001'),
                      item('indicator', entity(db, '203.0.113.63')))  # fmt: skip
    services.publish_hunt_package(db, created.id)
    before = services.get_hunt_package(db, created.id).updated_at
    services.delete_rule(db, sigma)
    after = services.get_hunt_package(db, created.id)
    assert after.updated_at > before
    assert sorted(i.kind for i in after.items) == ['indicator', 'technique']
    services.delete_document(db, doc.id, 'retention test')  # its only report: the indicator goes too
    assert [i.kind for i in services.get_hunt_package(db, created.id).items] == ['technique']


def test_the_taxii_collection_serves_published_and_retired_packages_within_the_limit(db: Session) -> None:
    report(db, 'C2 at 203.0.113.64.', tlp='AMBER')
    draft = package(db, item('technique', 'T1059.001'), title='Draft')
    shared = package(db, item('technique', 'T1059.001'), title='Shared')
    amber = package(db, item('indicator', entity(db, '203.0.113.64')), title='Amber', tlp='AMBER')
    gone = package(db, item('technique', 'T1486'), title='Gone')
    for row in (shared, amber, gone):
        services.publish_hunt_package(db, row.id)
    services.retire_hunt_package(db, gone.id)
    services.retire_hunt_package(db, draft.id)  # retired without ever being published: never served

    def groupings(max_tlp: str | None) -> dict[str, bool]:
        served = services.taxii_collection_objects(db, HUNT_PACKAGES_COLLECTION, max_tlp=max_tlp)
        return {o.obj['name']: bool(o.obj.get('revoked')) for o in served if o.obj['type'] == 'grouping'}

    assert groupings('GREEN') == {'Shared': False, 'Gone': True}
    assert groupings(None) == {'Shared': False, 'Gone': True, 'Amber': False}


def test_network_rules_are_shape_checked(db: Session) -> None:
    assert services.rule_shape_problem('suricata', SURICATA) is None
    assert services.rule_shape_problem('snort', 'alert http (msg:"x"; content:"/a"; sid:1000002;)') is None
    assert services.rule_shape_problem('snort', 'not a rule') == (
        'This does not look like a Snort rule (alert ... (msg:"..."; sid:NUMBER;)).'
    )
    assert services.rule_shape_problem('suricata', 'alert tcp any any -> any any (msg:"no sid";)') is not None
    exported = services.export_rule(db, rule(db, 'suricata', SURICATA), max_tlp=None)
    assert b'rule.rules' in exported
