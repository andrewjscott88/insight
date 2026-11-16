"""Bounded, validated inputs. All user- and feed-supplied data passes through these models."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Annotated, Literal, get_args
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

from .extraction import Kind

TLP = Literal['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED']
DocumentStatus = Literal['new', 'reviewing', 'reviewed']
ReviewStatus = Literal['unreviewed', 'accepted', 'rejected']

TLP_LEVELS: tuple[str, ...] = get_args(TLP)  # least to most restrictive
#: Default when a client does not choose a label. Deliberately not CLEAR: an unlabelled report must never end
#: up *less* restricted than the workspace's own ingest dialog would have made it.
DEFAULT_TLP: TLP = 'AMBER'
_TLP_MARKING = re.compile(r'\bTLP\s*:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)\b', re.IGNORECASE)
DOCUMENT_STATUSES: tuple[str, ...] = get_args(DocumentStatus)
REVIEW_STATUSES: tuple[str, ...] = get_args(ReviewStatus)
INDICATOR_KINDS: tuple[Kind, ...] = get_args(Kind)
#: IOC exports leave out mentions an analyst rejected as wrong extractions, unless asked for explicitly.
DEFAULT_EXPORT_REVIEW_STATUSES: tuple[ReviewStatus, ...] = ('unreviewed', 'accepted')  # canonical order
#: Report IDs are UUID strings. An export can be limited to at most this many explicitly chosen reports.
MAX_EXPORT_DOCUMENT_IDS = 200
DocumentId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=36)]


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError('Must not be blank')
    # Line endings are normalised (browsers already send LF), so CRLF and LF copies of a report de-duplicate.
    # Nothing else is touched: evidence offsets index exactly this text.
    return value.replace('\r\n', '\n').replace('\r', '\n')


def tlp_markings(text: str) -> list[str]:
    """TLP labels written in ``text`` (``TLP:WHITE`` is the TLP 1.0 name for CLEAR)."""
    return ['CLEAR' if m.upper() == 'WHITE' else m.upper() for m in _TLP_MARKING.findall(text)]


def most_restrictive(*levels: str) -> str:
    return max(levels, key=TLP_LEVELS.index)


class DocumentInput(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    body: str = Field(min_length=1, max_length=200_000)
    source_name: str = Field(min_length=1, max_length=160)
    source_url: str = Field(default='', max_length=2000)
    tlp: TLP = DEFAULT_TLP

    @field_validator('title', 'body', 'source_name')
    @classmethod
    def not_blank(cls, value: str) -> str:
        return _not_blank(value)

    @field_validator('source_url')
    @classmethod
    def safe_url(cls, value: str) -> str:
        if not value:
            return value
        parts = urlsplit(value)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
            raise ValueError('Source URL must be an HTTP(S) URL without credentials')
        _ = parts.port  # Raises ValueError for a malformed/out-of-range port.
        return value


class DocumentReview(BaseModel):
    status: DocumentStatus


class ObservationReview(BaseModel):
    status: ReviewStatus


class NoteInput(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)

    @field_validator('body')
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Note must not be blank')
        return value


class IocExportQuery(BaseModel):
    """Filters for the cross-report IOC export (``insight-ioc-v1``), shared by the API, UI and CLI.

    ``q``, ``status``, ``tlp`` and ``include_superseded`` select reports exactly like the inbox search.
    ``document_ids`` limits the export to those reports (each is included even if superseded).
    ``max_tlp`` drops reports labelled more restrictively (e.g. ``GREEN`` before sharing with a community).
    ``defang`` rewrites network indicators (``hxxps://example[.]com``) in values, titles and evidence.
    ``include_evidence=False`` leaves out the report text around each mention (``evidence: null``), which can
    carry victim details or indicators an analyst rejected; recommended when sharing.
    """

    model_config = ConfigDict(frozen=True, extra='forbid')

    q: str = Field(default='', max_length=200)
    status: DocumentStatus | None = None
    tlp: TLP | None = None
    include_superseded: bool = False
    kinds: tuple[Kind, ...] = Field(default=INDICATOR_KINDS, min_length=1)
    review_statuses: tuple[ReviewStatus, ...] = Field(default=DEFAULT_EXPORT_REVIEW_STATUSES, min_length=1)
    max_tlp: TLP | None = None
    document_ids: tuple[DocumentId, ...] = Field(default=(), max_length=MAX_EXPORT_DOCUMENT_IDS)
    include_evidence: bool = True
    defang: bool = False

    @field_validator('kinds')
    @classmethod
    def canonical_kinds(cls, value: tuple[Kind, ...]) -> tuple[Kind, ...]:
        """De-duplicate and use one fixed order, so equal filters are reported (and audited) identically."""
        return tuple(sorted(set(value), key=INDICATOR_KINDS.index))

    @field_validator('review_statuses')
    @classmethod
    def canonical_review_statuses(cls, value: tuple[ReviewStatus, ...]) -> tuple[ReviewStatus, ...]:
        return tuple(sorted(set(value), key=REVIEW_STATUSES.index))

    @field_validator('document_ids')
    @classmethod
    def canonical_document_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


def validation_message(exc: ValidationError, names: Mapping[str, str] | None = None) -> str:
    """One short line per problem, naming the field as the caller knows it.

    ``names`` maps model fields to the caller's names: ``{'kinds': '--kind'}`` for the CLI and
    ``{'kinds': 'kind'}`` for the API. A bad list item is shown with its value
    (``--kind 'ipv4': Input should be 'cve', ...``), and the follow-on "should have at least 1 item" error
    that pydantic adds for the same list is left out.
    """
    errors = exc.errors(include_url=False)
    bad_items = {error['loc'][0] for error in errors if len(error['loc']) > 1}
    lines: list[str] = []
    for error in errors:
        loc = error['loc']
        field = str(loc[0]) if loc else ''
        if len(loc) == 1 and error['type'] == 'too_short' and field in bad_items:
            continue
        label = (names or {}).get(field, field) or 'input'
        if len(loc) > 1:
            label = f'{label} {error["input"]!r}'
        lines.append(f'{label}: {error["msg"]}')
    return '; '.join(lines)
