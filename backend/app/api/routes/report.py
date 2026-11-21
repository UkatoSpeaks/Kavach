from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.api.errors import ApiError
from app.api.protection import rate_limit
from app.core.enums import EntityType
from app.db.models import Analysis, Report
from app.services.reputation import normalize, upsert_reported_entity
from app.services.scan_cache import ScanCache

router = APIRouter(tags=["reports"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]


class ReportRequest(BaseModel):
    entity_type: EntityType
    value: str = Field(min_length=1, max_length=2048)
    reason: str | None = Field(default=None, max_length=1000)
    analysis_id: UUID | None = None

    @model_validator(mode="after")
    def _normalize(self) -> "ReportRequest":
        self.value = normalize(self.entity_type, self.value)  # ValueError -> 422
        return self


class ReportResponse(BaseModel):
    id: UUID = Field(description="The reported entity's id.")
    entity_type: EntityType
    value: str = Field(description="Normalized value.")
    report_count: int
    is_verified_scam: bool


@router.post(
    "/report",
    response_model=ReportResponse,
    status_code=201,
    dependencies=[rate_limit("report", "RATE_LIMIT_REPORT")],
)
async def report_entity(
    body: ReportRequest, session: SessionDep, request: Request
) -> ReportResponse:
    if body.analysis_id is not None and await session.get(Analysis, body.analysis_id) is None:
        raise ApiError(404, "analysis not found")
    entity = await upsert_reported_entity(session, body.entity_type, body.value)
    session.add(Report(entity_id=entity.id, analysis_id=body.analysis_id, reason=body.reason))
    response = ReportResponse(
        id=entity.id,
        entity_type=EntityType(entity.entity_type),
        value=entity.value,
        report_count=entity.report_count,
        is_verified_scam=entity.is_verified_scam,
    )
    await session.commit()
    # Cached scans that looked this entity up are now out of date: drop them (every scan
    # type and language_hint) so the next scan includes this report. Done after the commit
    # so a scan starting from here on reads the report. (A scan already in flight that
    # looked reputation up before the commit can still cache its result; that narrow
    # window ages out with the entry's TTL.)
    cache: ScanCache | None = getattr(request.app.state, "scan_cache", None)
    if cache is not None:
        await cache.invalidate(body.entity_type, body.value)
    return response
