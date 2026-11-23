"""Bounded, validated inputs. All user- and feed-supplied data passes through these models."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Literal, get_args
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

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


class ReportMetadata(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    source_name: str = Field(min_length=1, max_length=160)
    source_url: str = Field(default='', max_length=2000)
    tlp: TLP = DEFAULT_TLP

    @field_validator('title', 'source_name')
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


class DocumentInput(ReportMetadata):
    body: str = Field(min_length=1, max_length=200_000)

    @field_validator('body')
    @classmethod
    def body_not_blank(cls, value: str) -> str:
        return _not_blank(value)


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


# ------------------------------------------------------------------------- threat guides (TIP 2.10, ADR 0025)

ClaimDecision = Literal['added', 'removed']
RuleKind = Literal['yara', 'sigma', 'suricata', 'snort']
RULE_KINDS: tuple[str, ...] = get_args(RuleKind)
RuleTarget = Literal['group', 'technique', 'document', 'cve', 'malware']
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


class CampaignInput(BaseModel):
    """A manually curated campaign."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    name: str = Field(min_length=1, max_length=120)
    aliases: tuple[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)], ...
    ] = Field(default=(), max_length=MAX_ALIASES)
    description: str = Field(default='', max_length=5_000)
    tlp: TLP = DEFAULT_TLP

    @field_validator('name')
    @classmethod
    def name_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Must not be blank')
        return ' '.join(value.split())


class ActorInput(CampaignInput):
    """An analyst actor optionally matched by the analyst to one catalog group."""

    attack_group_id: str | None = Field(default=None, pattern=r'^[Gg]\d{4}$')


ThreatSubjectKind = Literal['actor', 'campaign']
ThreatTargetKind = Literal['document', 'indicator', 'technique', 'software']


class ThreatLinkInput(BaseModel):
    """An explicit link to an existing report, indicator, catalog technique or software."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    target_kind: ThreatTargetKind
    target_id: DocumentId
    tlp: TLP = DEFAULT_TLP


CaseItemKind = Literal['document', 'indicator', 'actor', 'campaign']
CaseStatusFilter = Literal['open', 'closed', 'all']


ProductType = Literal['assessment', 'alert', 'profile', 'summary']
#: ICD 203's expressions of likelihood, least to most likely (TIP 4.4, ADR 0036).
Likelihood = Literal[
    'almost-no-chance', 'very-unlikely', 'unlikely', 'roughly-even-chance', 'likely', 'very-likely',
    'almost-certain',
]  # fmt: skip
AnalyticConfidence = Literal['low', 'moderate', 'high']
ProductExportFormat = Literal['md', 'stix', 'pdf']
MAX_ANALYSIS = 30_000


class CaseInput(BaseModel):
    """``POST /api/cases``: start an intelligence product (TIP 3.8, 4.4). TLP markings in the text raise the
    label. ``summary`` is the product's analysis; ``bluf`` its bottom line up front."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(default='', max_length=MAX_ANALYSIS)
    tlp: TLP = DEFAULT_TLP
    product_type: ProductType = 'assessment'
    audience: str = Field(default='', max_length=200)
    bluf: str = Field(default='', max_length=2_000)


class CaseUpdate(BaseModel):
    """``PATCH /api/cases/{id}``: change what is given. A lower ``tlp`` never goes below the labels of the
    items, judgements and gaps, or the markings in the text."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    title: str | None = Field(default=None, min_length=1, max_length=200)
    summary: str | None = Field(default=None, max_length=MAX_ANALYSIS)
    tlp: TLP | None = None
    product_type: ProductType | None = None
    audience: str | None = Field(default=None, max_length=200)
    bluf: str | None = Field(default=None, max_length=2_000)


class JudgementInput(BaseModel):
    """``POST /api/cases/{id}/judgements``: a key judgement in ICD 203's estimative language, with the items
    of the product that support it. Labelled like the product unless ``tlp`` says otherwise; TLP markings in
    the statement raise it."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    statement: str = Field(min_length=1, max_length=1_000)
    likelihood: Likelihood
    confidence: AnalyticConfidence
    evidence: list[DocumentId] = Field(default_factory=list, max_length=50)
    tlp: TLP | None = None

    @field_validator('statement')
    @classmethod
    def not_blank(cls, value: str) -> str:
        return _not_blank(value)


class JudgementUpdate(BaseModel):
    """``PATCH /api/cases/{id}/judgements/{judgement_id}``: change what is given; ``evidence`` replaces the
    list; ``position`` moves it (1 is first)."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    statement: str | None = Field(default=None, min_length=1, max_length=1_000)
    likelihood: Likelihood | None = None
    confidence: AnalyticConfidence | None = None
    evidence: list[DocumentId] | None = Field(default=None, max_length=50)
    position: int | None = Field(default=None, ge=1, le=1_000)

    @field_validator('statement')
    @classmethod
    def not_blank(cls, value: str | None) -> str | None:
        return None if value is None else _not_blank(value)


class GapInput(BaseModel):
    """``POST /api/cases/{id}/gaps``: a question the product cannot answer yet. Labelled like the product
    unless ``tlp`` says otherwise; TLP markings in the question raise it."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    question: str = Field(min_length=5, max_length=300)
    tlp: TLP | None = None

    @field_validator('question')
    @classmethod
    def not_blank(cls, value: str) -> str:
        return _not_blank(value)


class CaseItemInput(BaseModel):
    """``POST /api/cases/{id}/items``: add a report, indicator, actor or campaign. The item is labelled at
    least as restrictively as the target itself (``tlp`` can only raise that)."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    kind: CaseItemKind
    target_id: DocumentId
    tlp: TLP = 'CLEAR'


class CaseNoteInput(BaseModel):
    """``POST /api/cases/{id}/notes``: an analyst note, labelled like the case unless ``tlp`` says otherwise;
    TLP markings in the text raise its label."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    text: str = Field(min_length=1, max_length=10_000)
    tlp: TLP | None = None


class CaseCloseInput(BaseModel):
    """``POST /api/cases/{id}/close``: close with a note saying what was found or decided."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    note: str = Field(min_length=1, max_length=10_000)


RequirementKind = Literal['pir', 'ir', 'rfi']
RequirementStatus = Literal['open', 'answered', 'retired']
RequirementStatusFilter = Literal['open', 'answered', 'retired', 'all']
Priority = Literal['high', 'medium', 'low']
CriterionKind = Literal['term', 'cve', 'technique', 'group', 'campaign']
CRITERION_PATTERNS: Mapping[str, re.Pattern[str]] = {
    'cve': re.compile(r'^CVE-\d{4}-\d{4,}$', re.ASCII),
    'technique': re.compile(r'^T\d{4}(?:\.\d{3})?$', re.ASCII),
}


def _due(value: date | None) -> date | None:
    if value is not None and value < datetime.now(UTC).date():
        raise ValueError('Must be today or later')
    return value


def end_of_day(value: date | None) -> str | None:
    """The end of a due date (UTC), stored like every other timestamp."""
    return None if value is None else datetime(*value.timetuple()[:3], 23, 59, 59, tzinfo=UTC).isoformat()


# ------------------------------------------------------------------------- hunt packages (TIP 4.3, ADR 0034)

HuntPackageStatus = Literal['draft', 'published', 'retired']
HuntPackageStatusFilter = Literal['draft', 'published', 'retired', 'all']
HuntPackageItemKind = Literal['technique', 'indicator', 'rule', 'document']
MAX_HUNT_PACKAGE_INPUT_ITEMS = 100


class HuntPackageItemInput(BaseModel):
    """``POST /api/hunt-packages/{id}/items``: an ATT&CK technique (``T1059.001``), or the ID of an indicator,
    a detection rule or a report. The package label rises to the item's own label."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    kind: HuntPackageItemKind
    target_id: DocumentId


class HuntPackageInput(BaseModel):
    """``POST /api/hunt-packages``: a draft hunt package. TLP markings in the text, the group and any items
    raise the label."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field(min_length=1, max_length=10_000)
    group: GroupRef | None = None
    tlp: TLP = DEFAULT_TLP
    items: list[HuntPackageItemInput] = Field(default_factory=list, max_length=MAX_HUNT_PACKAGE_INPUT_ITEMS)

    @field_validator('title', 'hypothesis')
    @classmethod
    def not_blank(cls, value: str) -> str:
        return _not_blank(value)


class HuntPackageUpdate(BaseModel):
    """``PATCH /api/hunt-packages/{id}``: change what is given; ``group: null`` removes the group. A lower
    ``tlp`` never goes below the items, the group or the markings in the text."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    title: str | None = Field(default=None, min_length=1, max_length=200)
    hypothesis: str | None = Field(default=None, min_length=1, max_length=10_000)
    group: GroupRef | None = None
    tlp: TLP | None = None

    @field_validator('title', 'hypothesis')
    @classmethod
    def not_blank(cls, value: str | None) -> str | None:
        return None if value is None else _not_blank(value)


class CriterionInput(BaseModel):
    """``POST /api/requirements/{id}/criteria``: what makes a report relevant. ``term`` is a word or phrase in
    the report's text; ``cve`` a CVE it mentions; ``technique`` an ATT&CK technique tagged on it; ``group`` a
    threat group (an ATT&CK ID such as ``G0016``, or one of your actors' IDs) and ``campaign`` one of your
    campaigns' IDs, linked to the report."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    kind: CriterionKind
    value: str = Field(min_length=2, max_length=120)

    @field_validator('value')
    @classmethod
    def tidy(cls, value: str) -> str:
        return ' '.join(value.split())

    def normalised(self) -> str:
        """The stored value: CVE and technique IDs in upper case, checked against their formats."""
        value = self.value.upper() if self.kind in CRITERION_PATTERNS else self.value
        pattern = CRITERION_PATTERNS.get(self.kind)
        if pattern is not None and not pattern.match(value):
            example = 'CVE-2024-3400' if self.kind == 'cve' else 'T1190 or T1059.001'
            raise ValueError(f'Not a valid ID: try {example}')
        return value


class RequirementInput(BaseModel):
    """``POST /api/requirements``: a priority intelligence requirement (``pir``), an intelligence
    requirement under one (``ir`` with ``parent_id``) or a request for information (``rfi``). TLP markings in
    the text raise the label."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    kind: RequirementKind
    question: str = Field(min_length=5, max_length=300)
    context: str = Field(default='', max_length=10_000)
    stakeholder: str = Field(default='', max_length=120)
    priority: Priority = 'medium'
    tlp: TLP = DEFAULT_TLP
    parent_id: DocumentId | None = None
    due: date | None = None
    criteria: list[CriterionInput] = Field(default_factory=list, max_length=50)

    @field_validator('due')
    @classmethod
    def not_in_the_past(cls, value: date | None) -> date | None:
        return _due(value)


class SightingInput(BaseModel):
    """``POST /api/sightings``: a hunt tool saw a known indicator in its own data (TIP 4.2, ADR 0035).
    ``value`` is the indicator as Insight serves it; ``kind`` is needed only when a value could be more than
    one kind. An API key with ``read-feedback`` access may send one. TLP markings in the text raise the
    label."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    value: str = Field(min_length=1, max_length=2048)
    kind: Kind | None = None
    first_seen: datetime
    last_seen: datetime | None = None
    count: int = Field(default=1, ge=1, le=1_000_000_000)
    where: str = Field(default='', max_length=120)
    observer: str = Field(default='', max_length=120)
    note: str = Field(default='', max_length=2_000)
    external_ref: str = Field(default='', max_length=200)
    hunt_package_id: str | None = Field(default=None, min_length=1, max_length=36)
    tlp: TLP = DEFAULT_TLP

    @field_validator('first_seen', 'last_seen')
    @classmethod
    def utc_and_not_ahead(cls, value: datetime | None) -> datetime | None:
        """A time without a zone is UTC; a time more than five minutes ahead is a clock or typing mistake."""
        if value is None:
            return None
        stamp = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        if stamp > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError('a sighting cannot be in the future')
        return stamp.astimezone(UTC)

    @model_validator(mode='after')
    def in_order(self) -> SightingInput:
        if self.last_seen is not None and self.last_seen < self.first_seen:
            raise ValueError('last_seen cannot be before first_seen')
        return self


class RfiInput(BaseModel):
    """``POST /api/rfis``: a request for information from another tool or person. An API key with
    ``read-feedback`` access may file one; it cannot change anything else. ``external_ref`` is the requester's
    own reference."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    question: str = Field(min_length=5, max_length=300)
    context: str = Field(default='', max_length=10_000)
    requester: str = Field(default='', max_length=120)
    priority: Priority = 'medium'
    tlp: TLP = DEFAULT_TLP
    due: date | None = None
    external_ref: str = Field(default='', max_length=200)

    @field_validator('due')
    @classmethod
    def not_in_the_past(cls, value: date | None) -> date | None:
        return _due(value)


class RequirementUpdate(BaseModel):
    """``PATCH /api/requirements/{id}``: change what is given. A lower ``tlp`` never goes below the criteria,
    the cited reports or the markings in the text."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    question: str | None = Field(default=None, min_length=5, max_length=300)
    context: str | None = Field(default=None, max_length=10_000)
    stakeholder: str | None = Field(default=None, max_length=120)
    priority: Priority | None = None
    tlp: TLP | None = None
    due: date | None = None

    @field_validator('due')
    @classmethod
    def not_in_the_past(cls, value: date | None) -> date | None:
        return _due(value)


class EvidenceInput(BaseModel):
    """``POST /api/requirements/{id}/evidence``: cite a report as evidence. Raises the requirement's label to
    the report's."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    document_id: DocumentId
    note: str = Field(default='', max_length=2_000)


class AnswerInput(BaseModel):
    """``POST /api/requirements/{id}/answer``: the current answer. An RFI becomes ``answered``; a PIR or IR
    keeps its status and shows the answer as its latest assessment."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    answer: str = Field(min_length=1, max_length=20_000)


Reliability = Literal['A', 'B', 'C', 'D', 'E', 'F']


class SourceRatingInput(BaseModel):
    """``PUT /api/source-ratings``: the analyst's Admiralty reliability grade for a source (by the reports'
    source name), and optionally how fast its indicators age (``half_life_days``; ``None``: the default)."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    source_name: str = Field(min_length=1, max_length=160)
    reliability: Reliability
    half_life_days: int | None = Field(default=None, ge=1, le=3650)
    note: str = Field(default='', max_length=2_000)


class CredibilityInput(BaseModel):
    """``PUT /api/documents/{id}/credibility``: the Admiralty credibility of what a report says, 1 (confirmed)
    to 6 (cannot be judged)."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    credibility: int = Field(ge=1, le=6)


class ActorLinkInput(BaseModel):
    """``POST /api/actors/{id}/documents``: link a report to a group or actor (the analyst's decision)."""

    model_config = ConfigDict(frozen=True, extra='forbid')

    document_id: DocumentId
    note: str = Field(default='', max_length=2_000)
    tlp: TLP = 'CLEAR'


class SoftwareLinkInput(ActorLinkInput):
    """An explicit, labelled software/report link; no attribution follows from the association."""


class ActorCampaignInput(BaseModel):
    """An explicit association, not an attribution inferred from shared reports."""

    model_config = ConfigDict(frozen=True, extra='forbid')
    campaign_id: DocumentId
    note: str = Field(default='', max_length=2_000)
    tlp: TLP = 'CLEAR'


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
    """``POST /api/rules``: a YARA, Sigma, Suricata or Snort rule, carried as text (TIP 2.7, 4.3). Insight
    never runs it."""

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
