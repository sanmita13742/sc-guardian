from typing import Any, Literal

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    repository_url: str = Field(min_length=1, max_length=300)


class ErrorDetail(BaseModel):
    code: str
    message: str
    detail: str | None = None


class AnalysisStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "completed_with_warnings", "failed", "cancelled"]
    stage: str
    stage_label: str
    progress: int = Field(ge=0, le=100)
    repository_url: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    commit_sha: str | None = None
    error: ErrorDetail | None = None
    summary: dict[str, Any] | None = None
    artifacts: dict[str, str] = Field(default_factory=dict)

