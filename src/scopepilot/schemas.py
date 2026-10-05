from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
        if not value.startswith("/"):
            raise ValueError("path_prefix must start with /")
        return value


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
    model_config = ConfigDict(extra="forbid")
    status: FindingStatus
    reviewer: str = Field(min_length=1, max_length=120)
    actual_result: str = Field(min_length=3, max_length=4000)
    tested_identity: str = Field(min_length=1, max_length=120)
    tested_object: str = Field(min_length=1, max_length=120)
    stop_reason: str = Field(min_length=1, max_length=1000)

    @field_validator("status")
    @classmethod
    def final_status_only(cls, value: FindingStatus) -> FindingStatus:
        if value == FindingStatus.PENDING:
            raise ValueError("a review must choose a human decision")
        return value
