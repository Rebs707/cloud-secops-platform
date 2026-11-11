from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, ConfigDict


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(BaseModel):
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    source: str


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(min_length=1, max_length=128)
    resource_type: str = Field(default="cloud_resource", max_length=64)
    configuration: dict[str, Any] = Field(default_factory=dict)
    packages: dict[str, str] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    controls: dict[str, bool | None] = Field(default_factory=dict)


class AgentResult(BaseModel):
    status: str
    findings: list[Finding]
    checks_performed: int


class ScanResponse(BaseModel):
    resource_id: str
    overall_status: str
    risk_score: int
    summary: dict[str, int]
    results: dict[str, AgentResult]
    findings: list[Finding]
    limitations: list[str]
