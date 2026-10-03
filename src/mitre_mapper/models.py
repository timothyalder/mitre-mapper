"""Pydantic contracts shared by the deterministic core, MCP server and LangChain layer.

Stdlib + pydantic only. Input-facing models (intake, proposal) forbid extra fields so
neither the user file nor the LLM can smuggle data through.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Domain = Literal["enterprise-attack", "mobile-attack", "ics-attack"]
SoftwareType = Literal["malware", "tool"]
TerminalState = Literal[
    "minted",
    "declined",
    "lint_failed",
    "judge_rejected",
    "budget_exhausted",
    "provider_error",
    "error",
    "abandoned",  # MCP session that never ended
]

TechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
GroupId = Annotated[str, StringConstraints(pattern=r"^G\d{4}$")]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]

_STRICT = ConfigDict(extra="forbid")


class Severity(str, Enum):
    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"


class ExternalReference(BaseModel):
    """An ATT&CK-style external reference."""

    model_config = _STRICT

    source_name: NonEmptyStr
    url: str | None = None
    description: str | None = None
    external_id: str | None = None


# --- Intake (PLAN 3.1) -------------------------------------------------------


class NewGroup(BaseModel):
    """A user-defined group; minted as GX####."""

    model_config = _STRICT

    name: NonEmptyStr
    aliases: list[str] = []
    description: str
    references: list[ExternalReference] = []
    techniques: list[TechniqueId] = []


class IntakeGroup(BaseModel):
    """Exactly one of `ref` (existing ATT&CK group) or `new` (user-defined group)."""

    model_config = _STRICT

    ref: GroupId | None = None
    new: NewGroup | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> IntakeGroup:
        if (self.ref is None) == (self.new is None):
            raise ValueError("exactly one of 'ref' or 'new' must be set")
        return self


class IntakeSpec(BaseModel):
    """Parsed intake file: YAML frontmatter fields plus the markdown body."""

    model_config = _STRICT

    name: NonEmptyStr
    type: SoftwareType
    aliases: list[str] = []
    platforms: list[str] = []
    domains: list[Domain] | None = None
    references: list[ExternalReference] = []
    techniques: list[TechniqueId] = []
    groups: list[IntakeGroup] = []
    body: str = ""


# --- Proposal ----------------------------------------------------------------


class EvidenceQuote(BaseModel):
    model_config = _STRICT

    source_name: str
    quote: str


class TechniqueMapping(BaseModel):
    model_config = _STRICT

    technique_id: TechniqueId
    rationale: str
    evidence: list[EvidenceQuote] = []
    user_asserted: bool = False


class GroupMapping(BaseModel):
    """Link to an EXISTING group only; the agent never mints groups (D15)."""

    model_config = _STRICT

    group_id: GroupId
    quote: str
    source_name: str
    user_asserted: bool = False


class MappingProposal(BaseModel):
    """Agent output for one domain.

    E001 (>=1 technique unless declined) is a lint rule, so an empty non-declined
    proposal must still parse.
    """

    model_config = _STRICT

    domain: Domain
    techniques: list[TechniqueMapping] = []
    groups: list[GroupMapping] = []
    declined: bool = False
    decline_rationale: str | None = None

    @model_validator(mode="after")
    def _decline_rules(self) -> MappingProposal:
        if self.declined:
            if self.techniques:
                raise ValueError("a declined proposal must have no techniques")
            if not (self.decline_rationale and self.decline_rationale.strip()):
                raise ValueError("a declined proposal needs a decline_rationale")
        return self


# --- Judge -------------------------------------------------------------------


class RubricItem(BaseModel):
    name: str
    passed: bool
    rationale: str


class Verdict(BaseModel):
    approved: bool
    items: list[RubricItem]
    summary: str = ""

    @property
    def failed_items(self) -> list[RubricItem]:
        return [i for i in self.items if not i.passed]


# --- Lint --------------------------------------------------------------------

_SEVERITY_PREFIX = {Severity.ERROR: "E", Severity.WARN: "W", Severity.INFO: "I"}


class LintFinding(BaseModel):
    rule_id: Annotated[str, StringConstraints(pattern=r"^[EWI]\d{3}$")]
    severity: Severity
    message: str
    target: str | None = None
    details: dict[str, Any] = {}

    @model_validator(mode="after")
    def _prefix_matches_severity(self) -> LintFinding:
        if self.rule_id[0] != _SEVERITY_PREFIX[self.severity]:
            raise ValueError(
                f"rule_id {self.rule_id} does not match severity {self.severity.value}"
            )
        return self


# --- Fetch -------------------------------------------------------------------


class FetchResult(BaseModel):
    source_name: str
    url: str | None = None
    ok: bool
    text: str | None = None
    error: str | None = None
    content_type: str | None = None
    original_length: int | None = None
    truncated: bool = False
    cache_path: str | None = None

    @model_validator(mode="after")
    def _ok_or_error(self) -> FetchResult:
        if self.ok and self.text is None:
            raise ValueError("ok result requires text")
        if not self.ok and not self.error:
            raise ValueError("failed result requires a non-empty error")
        return self


# --- Delta (PLAN 3.7) --------------------------------------------------------


class Delta(BaseModel):
    schema_version: int = 1
    run_id: str
    created: str
    dataset_manifest: dict[str, Any]
    tool_version: str
    git_sha: str
    prompt_sha256: str
    allocations: dict[str, str]  # ATT&CK id -> stix id
    target_domains: list[Domain]
    objects: list[dict[str, Any]]


# --- Index records (PLAN 3.9) ------------------------------------------------


class RunRecord(BaseModel):
    """One append-only index row per run."""

    record: Literal["run"] = "run"
    run_id: str
    ts: str
    software_name: str
    intake_sha256: str
    domains: list[Domain]
    model: str
    judge_model: str | None = None
    git_sha: NonEmptyStr
    prompt_sha256: NonEmptyStr
    tool_version: str
    dataset_release: dict[str, str]
    n_model_calls: int = 0
    tokens: dict[str, int] = {"in": 0, "out": 0}
    wall_s: float = 0
    attempts: dict[str, int] = {}
    terminal_state: TerminalState
    error_rule_ids: list[str] = []
    warn_rule_ids: list[str] = []
    judge_fail_items: list[str] = []
    zero_hit_queries: int = 0
    unmatched_actors: int = 0
    fetch_failures: int = 0
    eval_case: str | None = None
    eval_scores: dict[str, Any] | None = None
    review: dict[str, Any] | None = None


class Review(BaseModel):
    """The user's verdict on a run (review.json)."""

    run_id: str
    ts: str
    reviewer: str | None = None
    techniques: dict[str, Literal["accepted", "rejected"]] = {}
    groups: dict[str, Literal["accepted", "rejected"]] = {}
    missed_techniques: list[str] = []
    missed_groups: list[str] = []
    notes: str = ""


class ReviewRecord(BaseModel):
    """Appended to the index when a review is recorded; `report` joins on run_id."""

    record: Literal["review"] = "review"
    run_id: str
    ts: str
    summary: dict[str, Any]


IndexRecord = Annotated[RunRecord | ReviewRecord, Field(discriminator="record")]
