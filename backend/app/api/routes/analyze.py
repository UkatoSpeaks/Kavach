import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_http_client,
    get_pattern_search,
    get_reasoner,
    get_session,
    get_session_factory,
)
from app.core.config import Settings, get_settings
from app.core.enums import InputType
from app.db.models import Analysis
from app.db.session import SessionFactory
from app.schemas.analysis import AnalysisResult
from app.services import qr, rag, reputation
from app.services.agent.graph import run_analysis
from app.services.agent.llm import Reasoner
from app.services.cache import LookupCache
from app.services.extractors import extract_upi_ids, extract_urls, parse_upi_uri
from app.services.pipeline import Checks, PipelineOutput

router = APIRouter(tags=["analysis"])
logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 5000
MAX_URL_CHARS = 2048
DB_SAVE_TIMEOUT_S = 5

SessionDep = Annotated[AsyncSession, Depends(get_session)]
SessionFactoryDep = Annotated[SessionFactory | None, Depends(get_session_factory)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


async def get_checks(
    settings: SettingsDep,
    client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
    session_factory: Annotated[SessionFactory | None, Depends(get_session_factory)],
    patterns: Annotated[rag.PatternSearch | None, Depends(get_pattern_search)],
) -> Checks:
    cache = LookupCache(session_factory, timedelta(hours=settings.URL_CACHE_TTL_HOURS))
    find = reputation.find_reported_in(session_factory) if session_factory else None
    return Checks(client=client, cache=cache, find_reported=find, patterns=patterns)


ChecksDep = Annotated[Checks, Depends(get_checks)]
ReasonerDep = Annotated[Reasoner | None, Depends(get_reasoner)]
ExplainQuery = Annotated[
    bool,
    Query(description="false skips the LLM step: template explanations, no LLM quota used."),
]


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


class Saver:
    """Saves analyses after the response is sent (FastAPI BackgroundTasks).

    The id and created_at are generated up front, so the response carries them even though
    the row isn't written yet. If the save fails it is logged and GET /analysis/{id}
    returns 404. The save runs on a session of its own: the request's session is closed
    by the time background tasks run.
    """

    def __init__(self, background: BackgroundTasks, sessions: SessionFactoryDep) -> None:
        self.background = background
        self.sessions = sessions

    def __call__(
        self,
        out: PipelineOutput,
        input_type: InputType,
        raw_input: str,
        language_hint: str | None = None,
    ) -> AnalysisResult:
        result = out.result.model_copy(update={"id": uuid4(), "created_at": datetime.now(UTC)})
        row = Analysis(
            id=result.id,
            created_at=result.created_at,
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
                    "confidence",
                },
            ),
        )  # fmt: skip
        self.background.add_task(save_analysis, self.sessions, row)
        return result


async def save_analysis(sessions: SessionFactory | None, row: Analysis) -> None:
    """Background task. Never raises: nobody is left to handle it."""
    if sessions is None:
        logger.warning("analysis %s not saved: no database configured", row.id)
        return
    start = time.perf_counter()
    try:
        async with asyncio.timeout(DB_SAVE_TIMEOUT_S), sessions() as session:
            session.add(row)
            await session.commit()
    except Exception as exc:
        logger.warning("could not save analysis %s: %s: %s", row.id, type(exc).__name__, exc)
        return
    logger.info(
        "analysis saved",
        extra={
            "extra_fields": {
                "analysis_id": str(row.id),
                "save_ms": round((time.perf_counter() - start) * 1000, 1),
            }
        },
    )


SaverDep = Annotated[Saver, Depends()]


@router.post("/analyze/text", response_model=AnalysisResult)
async def analyze_text_route(
    body: AnalyzeTextRequest,
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    explain: ExplainQuery = True,
) -> AnalysisResult:
    out = await run_analysis(
        body.text,
        settings,
        checks=checks,
        reasoner=reasoner,
        language_hint=body.language_hint,
        explain=explain,
    )
    return save(out, InputType.TEXT, body.text, body.language_hint)


@router.post("/analyze/url", response_model=AnalysisResult)
async def analyze_url_route(
    body: AnalyzeURLRequest,
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    explain: ExplainQuery = True,
) -> AnalysisResult:
    out = await run_analysis(
        body.url, settings, checks=checks, reasoner=reasoner, message_text=False, explain=explain
    )
    return save(out, InputType.URL, body.url)


@router.post("/analyze/upi", response_model=AnalysisResult)
async def analyze_upi_route(
    body: AnalyzeUPIRequest,
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    explain: ExplainQuery = True,
) -> AnalysisResult:
    value = body.upi_id or body.upi_uri or ""
    out = await run_analysis(
        value, settings, checks=checks, reasoner=reasoner, message_text=False, explain=explain
    )
    return save(out, InputType.UPI, value)


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
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    image: Annotated[UploadFile, File(description="PNG or JPEG, max 5 MB")],
    explain: ExplainQuery = True,
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
    out = await run_analysis(
        decoded.payload,
        settings,
        checks=checks,
        reasoner=reasoner,
        message_text=decoded.kind == "text",
        explain=explain,
    )
    return save(out, InputType.QR, decoded.payload)


@router.get("/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: UUID, session: SessionDep) -> AnalysisResult:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return AnalysisResult.model_validate(row)
