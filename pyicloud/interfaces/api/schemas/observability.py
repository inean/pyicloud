"""Observability request/response schemas."""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import BaseModel, Field, model_validator


class ObservabilityQueryRequest(BaseModel):
    query: str = Field(min_length=1)
    source: str | None = Field(default=None, min_length=1)
    start: int | None = None
    end: int | None = None
    step: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_range_fields(self) -> Self:
        provided = [self.start is not None, self.end is not None, self.step is not None]
        if not any(provided):
            return self
        if not all(provided):
            raise ValueError("Range query requires start, end, and step together")
        assert self.start is not None
        assert self.end is not None
        if self.start > self.end:
            raise ValueError("Range query requires start <= end")
        return self


class ObservabilityQueryResponse(BaseModel):
    status: str
    language: Literal["promql", "traceql", "logql"]
    data: Any
    warnings: list[str] = Field(default_factory=list)
    source: str
