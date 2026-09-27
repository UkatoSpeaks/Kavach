import asyncio
import logging
from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_http_client, get_session, get_session_factory
from app.core.config import Settings, get_settings
from app.core.enums import InputType
from app.db.models import Analysis
from app.db.session import SessionFactory
from app.schemas.analysis import AnalysisResult
from app.services import qr
from app.services.cache import LookupCache
from app.services.extractors import extract_upi_ids, extract_urls, parse_upi_uri
from app.services.pipeline import Checks, PipelineOutput, analyze

router = APIRouter(tags=["analysis"])
logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 5000
MAX_URL_CHARS = 2048
DB_SAVE_TIMEOUT_S = 5

SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


async def get_checks(
    settings: SettingsDep,
    client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
    session_factory: Annotated[SessionFactory | None, Depends(get_session_factory)],
) -> Checks:
    cache = LookupCache(session_factory, timedelta(hours=settings.URL_CACHE_TTL_HOURS))
    return Checks(client=client, cache=cache, session_factory=session_factory)


ChecksDep = Annotated[Checks, Depends(get_checks)]


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


class AnalyzeURLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_CHARS)

    @field_validator("url")
    @classmethod
    def _one_url(cls, v: str) -> str:
        v = v.strip()
        urls = extract_urls(v)
        if len(urls) != 1 or urls[0].raw != v:
            raise ValueError("must be a single URL, e.g. https://example.com/path")
        return v


class AnalyzeUPIRequest(BaseModel):
    upi_id: str | None = Field(default=None, max_length=256, examples=["someone@ybl"])
    upi_uri: str | None = Field(
        default=None, max_length=MAX_URL_CHARS, examples=["upi://pay?pa=someone@ybl&am=10"]
    )

    @model_validator(mode="after")
    def _exactly_one(self) -> "AnalyzeUPIRequest":
        if (self.upi_id is None) == (self.upi_uri is None):
            raise ValueError("give exactly one of upi_id or upi_uri")
        if self.upi_id is not None:
            self.upi_id = self.upi_id.strip()
            found = extract_upi_ids(self.upi_id)
            if len(found) != 1 or found[0].value != self.upi_id.lower():
                raise ValueError("upi_id must look like name@handle")
        if self.upi_uri is not None:
            self.upi_uri = self.upi_uri.strip()
            parsed = parse_upi_uri(self.upi_uri)
            if parsed is None or not parsed.pa:
                raise ValueError("upi_uri must be a upi://pay?pa=... link")
        return self


async def _save(
    session: AsyncSession,
    out: PipelineOutput,
    input_type: InputType,
    raw_input: str,
    language_hint: str | None = None,
) -> AnalysisResult:
    result = out.result
    row = Analysis(
        input_type=input_type,
        raw_input=raw_input,
        normalized_text=out.entities.normalized_text,
        extracted_entities=out.entities.model_dump(mode="json"),
        language_hint=language_hint,
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


@router.post("/analyze/text", response_model=AnalysisResult)
async def analyze_text_route(
    body: AnalyzeTextRequest, session: SessionDep, settings: SettingsDep, checks: ChecksDep
) -> AnalysisResult:
    out = await analyze(body.text, settings, checks=checks, language_hint=body.language_hint)
    return await _save(session, out, InputType.TEXT, body.text, body.language_hint)


@router.post("/analyze/url", response_model=AnalysisResult)
async def analyze_url_route(
    body: AnalyzeURLRequest, session: SessionDep, settings: SettingsDep, checks: ChecksDep
) -> AnalysisResult:
    out = await analyze(body.url, settings, checks=checks, message_text=False)
    return await _save(session, out, InputType.URL, body.url)


@router.post("/analyze/upi", response_model=AnalysisResult)
async def analyze_upi_route(
    body: AnalyzeUPIRequest, session: SessionDep, settings: SettingsDep, checks: ChecksDep
) -> AnalysisResult:
    value = body.upi_id or body.upi_uri or ""
    out = await analyze(value, settings, checks=checks, message_text=False)
    return await _save(session, out, InputType.UPI, value)


@router.post(
    "/analyze/qr",
    response_model=AnalysisResult,
    responses={
        413: {"description": "Image larger than 5 MB"},
        415: {"description": "Not a PNG or JPEG image"},
        422: {"description": "No QR code found in the image"},
    },
)
async def analyze_qr_route(
    session: SessionDep,
    settings: SettingsDep,
    checks: ChecksDep,
    image: Annotated[UploadFile, File(description="PNG or JPEG, max 5 MB")],
) -> AnalysisResult:
    data = await image.read(qr.MAX_IMAGE_BYTES + 1)
    try:
        decoded = await asyncio.to_thread(qr.decode_qr, data)
    except qr.ImageTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except qr.UnsupportedImageError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except qr.NoQRCodeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # upi:// payloads go to the UPI check and URLs to url_intel (both via the entities the
    # extractor finds); plain text is analyzed like a message.
    out = await analyze(
        decoded.payload, settings, checks=checks, message_text=decoded.kind == "text"
    )
    return await _save(session, out, InputType.QR, decoded.payload)


@router.get("/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: UUID, session: SessionDep) -> AnalysisResult:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return AnalysisResult.model_validate(row)
