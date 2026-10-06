"""Shared strict HTTP contracts for completed-flow research inference."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field

MAX_BATCH = 256


class Flow(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    duration_us: Annotated[int, Field(ge=0, le=86_400_000_000)]
    packets: Annotated[int, Field(ge=0, le=2**63 - 1)]
    bytes: Annotated[int, Field(ge=0, le=2**63 - 1)]
    protocol: Literal["TCP", "UDP", "ICMP"]


class Batch(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    events: Annotated[list[Flow], Field(min_length=1, max_length=MAX_BATCH)]


class CaseInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    event_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
    flow: Flow


class FeedbackInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    expected_revision: Annotated[int, Field(ge=0)]
    reviewer: Annotated[str, Field(min_length=1, max_length=80)]
    verdict: Literal["suspicious", "benign", "uncertain"]
    note: Annotated[str, Field(max_length=2000)] = ""
