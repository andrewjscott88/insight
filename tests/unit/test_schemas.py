"""Input validation boundaries."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from insight.schemas import (
    DOCUMENT_STATUSES,
    REVIEW_STATUSES,
    TLP_LEVELS,
    DocumentInput,
    DocumentReview,
    NoteInput,
    ObservationReview,
    most_restrictive,
    tlp_markings,
)

VALID: dict[str, Any] = {'title': 'T', 'body': 'B', 'source_name': 'S'}


def test_defaults_and_exact_text_preserved() -> None:
    item = DocumentInput(**{**VALID, 'body': '  padded body  '})
    assert item.tlp == 'AMBER'  # never less restrictive than the ingest dialog's default
    assert item.source_url == ''
    assert item.body == '  padded body  '  # never stripped: offsets must stay exact


@pytest.mark.parametrize('tlp', TLP_LEVELS)
def test_all_tlp_levels_accepted(tlp: str) -> None:
    assert DocumentInput(**VALID, tlp=tlp).tlp == tlp


@pytest.mark.parametrize('tlp', ['WHITE', 'amber', '', 'AMBER STRICT'])
def test_unknown_tlp_rejected(tlp: str) -> None:
    with pytest.raises(ValidationError):
        DocumentInput(**VALID, tlp=tlp)


@pytest.mark.parametrize('field', ['title', 'body', 'source_name'])
@pytest.mark.parametrize('value', ['', '   ', '\n\t'])
def test_blank_required_fields_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        DocumentInput(**{**VALID, field: value})


@pytest.mark.parametrize(
    ('field', 'limit'),
    [('title', 300), ('body', 200_000), ('source_name', 160), ('source_url', 2000)],
)
def test_length_limits(field: str, limit: int) -> None:
    prefix = 'https://example.com/' if field == 'source_url' else ''
    at_limit = prefix + 'a' * (limit - len(prefix))
    DocumentInput(**{**VALID, field: at_limit})
    with pytest.raises(ValidationError):
        DocumentInput(**{**VALID, field: at_limit + 'a'})


@pytest.mark.parametrize(
    'url', ['https://example.com/report', 'http://example.com', 'https://example.com:8443/x', '']
)
def test_safe_source_urls(url: str) -> None:
    assert DocumentInput(**VALID, source_url=url).source_url == url


@pytest.mark.parametrize(
    'url',
    [
        'javascript:alert(1)',
        'file:///etc/passwd',
        'data:text/html,x',
        '//evil.example',
        'https://user:pass@example.com',
        'https://user@example.com',
        'https://example.com:bad',
        'https://example.com:70000/',
        'ftp://example.com/',
        'https:///nohost',
    ],
)
def test_dangerous_source_urls_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        DocumentInput(**VALID, source_url=url)


@pytest.mark.parametrize('status', DOCUMENT_STATUSES)
def test_document_review_statuses(status: str) -> None:
    assert DocumentReview(status=status).status == status


@pytest.mark.parametrize('status', REVIEW_STATUSES)
def test_observation_review_statuses(status: str) -> None:
    assert ObservationReview(status=status).status == status


def test_review_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        DocumentReview(status='invented')
    with pytest.raises(ValidationError):
        ObservationReview(status='malicious')


def test_note_bounds() -> None:
    assert NoteInput(body='x' * 10_000).body == 'x' * 10_000
    for bad in ['', '   ', 'x' * 10_001]:
        with pytest.raises(ValidationError):
            NoteInput(body=bad)


def test_line_endings_are_normalised_and_nothing_else() -> None:
    item = DocumentInput(**{**VALID, 'body': '  a\r\nb\rc\n  '})
    assert item.body == '  a\nb\nc\n  '


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('TLP:RED', ['RED']),
        ('tlp: amber+strict and TLP:GREEN', ['AMBER+STRICT', 'GREEN']),
        ('TLP:WHITE (1.0 name)', ['CLEAR']),
        ('no marking; TLPRED; TLP-RED', []),
    ],
)
def test_tlp_markings(text: str, expected: list[str]) -> None:
    assert tlp_markings(text) == expected


def test_most_restrictive() -> None:
    assert most_restrictive('CLEAR', 'AMBER', 'GREEN') == 'AMBER'
    assert most_restrictive('AMBER', 'AMBER+STRICT') == 'AMBER+STRICT'
    assert most_restrictive('RED', 'CLEAR') == 'RED'
