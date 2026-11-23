"""An operator feed excerpt keeps the marking on the complete publisher item."""

import pytest
from sqlalchemy.orm import Session

from insight import connectors, services
from insight.source_registry import Source


@pytest.mark.parametrize('feed', ['rss', 'atom', 'atom-xhtml'])
def test_omitted_publisher_marking_still_restricts_the_excerpt(db: Session, feed: str) -> None:
    source = Source('op-test', 'Publisher', 'https://feeds.example.org/', 'rss', '')
    if feed == 'rss':
        title = 'A' * 300 + ' TLP:RED'
        xml = (
            f'<rss><channel><item><title>{title}</title>'
            '<description>Excerpt</description></item></channel></rss>'
        )
    else:
        retained = 'A' * connectors.MAX_FEED_SUMMARY
        summary = (
            f'<summary type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">'
            f'<p>{retained}</p><p>TLP:RED</p></div></summary>'
            if feed == 'atom-xhtml'
            else f'<summary>{retained} TLP:RED</summary>'
        )
        xml = (
            '<feed xmlns="http://www.w3.org/2005/Atom"><entry>'
            f'<title>Bulletin</title>{summary}</entry></feed>'
        )
    [item] = connectors.parse_feed(xml.encode(), source, operator_tlp='GREEN')
    assert item.document.tlp == 'RED'
    assert 'TLP:RED' not in item.document.body
    assert item.external_id is not None
    ref = services.SourceRef(source.key, item.external_id)
    with pytest.raises(services.TlpNotPermitted):
        services.ingest(db, item.document, ref=ref, max_tlp='GREEN')
    report, created = services.ingest(db, item.document, ref=ref, max_tlp='RED')
    assert created
    assert services.get_document(db, report.id, max_tlp='GREEN') is None
