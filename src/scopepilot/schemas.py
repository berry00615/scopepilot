from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator
from .url_paths import decoded_path, encoded_path


class PolicyStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"


class FindingStatus(StrEnum):
    PENDING = "pending_review"
    NEEDS_EVIDENCE = "needs_evidence"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNRATED = "unrated"


class FindingCategory(StrEnum):
    HARDENING = "hardening"
    VULNERABILITY = "vulnerability"


class SourceKind(StrEnum):
    RULE = "rule"
    TOOL = "tool"
    MODEL = "model"
    HUMAN = "human"


class ScopeRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: str = Field(pattern=r"^https?$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    path_prefix: str = "/"

    @field_validator("host")
    @classmethod
    def exact_hosts_only(cls, value: str) -> str:
        value = value.rstrip(".").lower()
        if "*" in value:
            raise ValueError("MVP only supports exact hosts")
        try:
            return value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("host cannot be normalized") from exc

    @field_validator("path_prefix")
    @classmethod
    def absolute_path(cls, value: str) -> str:
        if '?' in value or '#' in value:
            raise ValueError('path_prefix must be a path without query or fragment')
        return encoded_path(decoded_path(value))


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authorization_reference: str = Field(min_length=3, max_length=500)
    valid_from: datetime
    valid_until: datetime
    status: PolicyStatus = PolicyStatus.DRAFT
    allow: list[ScopeRule] = Field(min_length=1)
    deny: list[ScopeRule] = Field(default_factory=list)
    external_model_egress: bool = False

    @field_validator("valid_until")
    @classmethod
    def has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("valid_until must include a timezone")
        return value

    def model_post_init(self, __context: object) -> None:
        if self.valid_from.tzinfo is None:
            raise ValueError("valid_from must include a timezone")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    owner: str = Field(min_length=1, max_length=120)
    policy: PolicyCreate


class ReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: FindingStatus
    reviewer: str = Field(min_length=1, max_length=120)
    actual_result: str = Field(min_length=3, max_length=4000)
    tested_identity: str = Field(min_length=1, max_length=120)
    tested_object: str = Field(min_length=1, max_length=120)
    stop_reason: str = Field(min_length=1, max_length=1000)
    success_criteria: str = Field(default="", max_length=2000)
    criteria_met: bool = False
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    control_required: bool = False
    control_result: str = Field(default="", max_length=4000)
    control_passed: bool | None = None
    severity: Severity | None = None
    severity_reason: str = Field(default="", max_length=2000)

    @field_validator("status")
    @classmethod
    def final_status_only(cls, value: FindingStatus) -> FindingStatus:
        if value == FindingStatus.PENDING:
            raise ValueError("a review must choose a human decision")
        return value


class IdentityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alias: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=120)
    ownership_notes: str = Field(min_length=1, max_length=1000)

    @field_validator("alias", "role", "ownership_notes")
    @classmethod
    def reject_secret_material(cls, value: str) -> str:
        lowered = value.lower()
        if any(marker in lowered for marker in ("password=", "token=", "cookie=", "authorization:")):
            raise ValueError("identity metadata must not contain credentials")
        return value


class ModelFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_type: str = Field(min_length=1, max_length=120)
    claim: str = Field(min_length=3, max_length=2000)
    evidence_refs: list[str] = Field(min_length=1, max_length=10)
    missing_information: str = Field(min_length=1, max_length=2000)
    suggested_manual_check: str = Field(min_length=3, max_length=2000)
    confidence: float = Field(ge=0, le=1)


class ModelOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[ModelFinding] = Field(default_factory=list, max_length=50)
