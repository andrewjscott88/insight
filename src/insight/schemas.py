"""Bounded, validated inputs. All user- and feed-supplied data passes through these models."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, date, datetime
from typing import Annotated, Literal, get_args
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

from .extraction import Kind
from .flags import FLAGS, Flag

TLP = Literal['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED']
DocumentStatus = Literal['new', 'reviewing', 'reviewed']
ReviewStatus = Literal['unreviewed', 'accepted', 'rejected']
#: What an indicator means (Design 1). ``unknown`` is the default: no assessment recorded.
Verdict = Literal['unknown', 'benign', 'suspicious', 'malicious']

TLP_LEVELS: tuple[str, ...] = get_args(TLP)  # least to most restrictive
#: Default when a client does not choose a label. Deliberately not CLEAR: an unlabelled report must never end
#: up *less* restricted than the workspace's own ingest dialog would have made it.
DEFAULT_TLP: TLP = 'AMBER'
_TLP_MARKING = re.compile(r'\bTLP\s*:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)\b', re.IGNORECASE)
DOCUMENT_STATUSES: tuple[str, ...] = get_args(DocumentStatus)
REVIEW_STATUSES: tuple[str, ...] = get_args(ReviewStatus)
VERDICTS: tuple[Verdict, ...] = get_args(Verdict)
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


class ScheduleInput(BaseModel):
    """``PUT /api/schedules/{key}``: how often the source syncs by itself, in minutes (0: off), and optionally
    the time of day (``HH:MM`` UTC) its syncs start from."""

    interval_minutes: int
    at: str | None = Field(default=None, pattern=r'^([01]\d|2[0-3]):[0-5]\d$')


class TechniqueInput(BaseModel):
    """A MITRE ATT&CK technique to add to a report, by ID (``T1059`` or ``T1059.001``)."""

    model_config = ConfigDict(extra='forbid')
    technique_id: str = Field(min_length=5, max_length=9, pattern=r'^[Tt]\d{4}(\.\d{3})?$')


class AssessmentInput(BaseModel):
    """``POST /api/entities/{id}/assessment``: an analyst's verdict on an indicator.

    ``reason`` says why (it may quote a restricted report, so it carries its own ``tlp``, default AMBER).
    ``valid_until`` is the last day the verdict holds (addresses and domains change hands); omit it for no
    expiry. ``unknown`` clears a recorded verdict.
    """

    model_config = ConfigDict(frozen=True, extra='forbid')

    verdict: Verdict
    reason: str = Field(default='', max_length=2_000)
    tlp: TLP = DEFAULT_TLP
    valid_until: date | None = None

    @field_validator('valid_until')
    @classmethod
    def not_in_the_past(cls, value: date | None) -> date | None:
        if value is not None and value < datetime.now(UTC).date():
            raise ValueError('Must be today or later')
        return value

    def valid_until_timestamp(self) -> str | None:
        """The end of ``valid_until`` (UTC), stored like every other timestamp."""
        if self.valid_until is None:
            return None
        return datetime(*self.valid_until.timetuple()[:3], 23, 59, 59, tzinfo=UTC).isoformat()


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
    ``verdicts`` keeps indicators with these verdicts (default: all); ``exclude_flags`` drops indicators
    with any of these warning flags (``non-routable``, ``documentation``, ...).
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
    verdicts: tuple[Verdict, ...] = Field(default=VERDICTS, min_length=1)
    exclude_flags: tuple[Flag, ...] = ()

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

    @field_validator('verdicts')
    @classmethod
    def canonical_verdicts(cls, value: tuple[Verdict, ...]) -> tuple[Verdict, ...]:
        return tuple(sorted(set(value), key=VERDICTS.index))

    @field_validator('exclude_flags')
    @classmethod
    def canonical_flags(cls, value: tuple[Flag, ...]) -> tuple[Flag, ...]:
        return tuple(sorted(set(value), key=FLAGS.index))

    def filters_by_meaning(self) -> bool:
        """Whether verdicts or flags narrow the export (judged per indicator, not by one SQL count)."""
        return self.verdicts != VERDICTS or bool(self.exclude_flags)


# ------------------------------------------------------------------------- threat guides (TIP 2.10, ADR 0024)

ClaimDecision = Literal['added', 'removed']
RuleKind = Literal['yara', 'sigma']
RuleTarget = Literal['group', 'technique', 'document']
HuntStatus = Literal['open', 'closed']
HuntResult = Literal['not-checked', 'nothing-found', 'suspicious', 'confirmed']
HUNT_RESULTS: tuple[str, ...] = get_args(HuntResult)
#: An ATT&CK group ID (``G0016``) or the ID of an actor the analyst created.
GroupRef = Annotated[str, StringConstraints(strip_whitespace=True, min_length=5, max_length=36)]
MAX_ALIASES = 50


def _https_url(value: str) -> str:
    """Empty, or an ``https://`` URL without credentials (citations are links people open)."""
    if not value:
        return value
    parts = urlsplit(value)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError('Must be an https:// link without a user name or password')
    _ = parts.port
    return value


class ActorInput(BaseModel):
    """``POST /api/actors``: an actor the analyst tracks (TIP 2.5). Never created by Insight itself."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    name: str = Field(min_length=1, max_length=120)
    aliases: tuple[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)], ...
    ] = Field(default=(), max_length=MAX_ALIASES)
    description: str = Field(default='', max_length=5_000)
    attack_group_id: str | None = Field(default=None, pattern=r'^[Gg]\d{4}$')
    tlp: TLP = DEFAULT_TLP

    @field_validator('name')
    @classmethod
    def name_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Must not be blank')
        return ' '.join(value.split())


class ActorLinkInput(BaseModel):
    """``POST /api/actors/{id}/documents``: link a report to a group or actor (the analyst's decision)."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    document_id: DocumentId
    note: str = Field(default='', max_length=2_000)


class IndustryClaimInput(BaseModel):
    """``POST /api/actors/{id}/industries``: add an industry with a citation, or remove a catalog claim.

    ``added`` needs ``citation_url`` or ``document_id`` (a report that says so); ``removed`` needs a
    ``reason``. The reason may quote a report, so the claim carries its own ``tlp``.
    """

    model_config = ConfigDict(frozen=True, extra='forbid')

    industry: str = Field(min_length=2, max_length=40)
    decision: ClaimDecision = 'added'
    citation_url: str = Field(default='', max_length=2_000)
    document_id: DocumentId | None = None
    reason: str = Field(default='', max_length=2_000)
    tlp: TLP = DEFAULT_TLP

    @field_validator('citation_url')
    @classmethod
    def https_only(cls, value: str) -> str:
        return _https_url(value.strip())

    def problem(self) -> str | None:
        """Why the claim cannot be stored, or ``None``."""
        if self.decision == 'added' and not (self.citation_url or self.document_id):
            return 'Give the link or the report that says this group targets the industry.'
        if self.decision == 'removed' and not self.reason.strip():
            return 'Say why the catalog is wrong about this group.'
        return None


class RuleInput(BaseModel):
    """``POST /api/rules``: a YARA or Sigma rule, carried as text (TIP 2.7). Insight never runs it."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    kind: RuleKind
    name: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=100_000)
    source_url: str = Field(default='', max_length=2_000)
    licence: str = Field(default='', max_length=120)
    tlp: TLP = DEFAULT_TLP

    @field_validator('name', 'body')
    @classmethod
    def not_blank(cls, value: str) -> str:
        return _not_blank(value)

    @field_validator('source_url')
    @classmethod
    def https_only(cls, value: str) -> str:
        return _https_url(value.strip())


class RuleLinkInput(BaseModel):
    """``POST /api/rules/{id}/links``: what a rule is for."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    target_kind: RuleTarget
    target_id: str = Field(min_length=1, max_length=36)


class HuntInput(BaseModel):
    """``POST /api/actors/{id}/hunts``: start a hunt record from a group's threat guide."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    title: str = Field(min_length=1, max_length=200)
    tlp: TLP = DEFAULT_TLP

    @field_validator('title')
    @classmethod
    def not_blank(cls, value: str) -> str:
        return _not_blank(value)


class HuntUpdate(BaseModel):
    """``PUT /api/hunts/{id}``: close or reopen a hunt, and its summary."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    status: HuntStatus
    summary: str = Field(default='', max_length=10_000)


class HuntCheckInput(BaseModel):
    """``PUT /api/hunts/{id}/checks/{technique}``: what was checked for one hypothesis, when, the result."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    result: HuntResult
    data_checked: str = Field(default='', max_length=2_000)
    period_start: date | None = None
    period_end: date | None = None
    notes: str = Field(default='', max_length=10_000)

    def problem(self) -> str | None:
        if self.period_start and self.period_end and self.period_end < self.period_start:
            return 'The end of the time range is before its start.'
        return None


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
