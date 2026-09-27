import asyncio
import logging
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.core.config import Settings, get_settings
from app.core.enums import InputType
from app.db.models import Analysis
from app.schemas.analysis import AnalysisResult
from app.services.pipeline import analyze_text

router = APIRouter(tags=["analysis"])
logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 5000
DB_SAVE_TIMEOUT_S = 5

SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


class AnalyzeTextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)
    language_hint: Literal["en", "hi", "hinglish"] | None = Field(
        default=None, description="'hi' returns advice in Hindi. Explanations are always both."
    )

    @field_validator("text")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("text must not be blank")
        return v


@router.post("/analyze/text", response_model=AnalysisResult)
async def analyze_text_route(
    body: AnalyzeTextRequest, session: SessionDep, settings: SettingsDep
) -> AnalysisResult:
    out = analyze_text(body.text, settings, body.language_hint)
    result = out.result
    row = Analysis(
        input_type=InputType.TEXT,
        raw_input=body.text,
        normalized_text=out.entities.normalized_text,
        extracted_entities=out.entities.model_dump(mode="json"),
        language_hint=body.language_hint,
        latency_ms=out.latency_ms,
        **result.model_dump(
            mode="json",
            include={
                "risk_score", "verdict", "scam_type", "red_flags", "signal_breakdown",
                "explanation_en", "explanation_hi", "advice", "similar_patterns",
            },
        ),
    )  # fmt: skip
    # Fail soft: if the database is down the user still gets the verdict, just no id.
    try:
        async with asyncio.timeout(DB_SAVE_TIMEOUT_S):
            session.add(row)
            await session.commit()
    except (SQLAlchemyError, OSError, TimeoutError) as exc:
        logger.warning("could not save analysis: %s: %s", type(exc).__name__, exc)
        await session.rollback()
        return result
    return result.model_copy(update={"id": row.id, "created_at": row.created_at})


@router.get("/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: UUID, session: SessionDep) -> AnalysisResult:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return AnalysisResult.model_validate(row)
