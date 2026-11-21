import asyncio
import logging
import re
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, TypeVar
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Query, Request, UploadFile
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_http_client,
    get_ocr_reader,
    get_pattern_search,
    get_reasoner,
    get_session,
    get_session_factory,
)
from app.api.errors import ApiError
from app.api.protection import rate_limit
from app.core.config import Settings, get_settings
from app.core.enums import InputType
from app.db.models import Analysis
from app.db.session import SessionFactory
from app.schemas.analysis import AnalysisResult, ScreenshotAnalysisResult
from app.schemas.entities import ExtractedEntities
from app.services import ocr, qr, rag, reputation
from app.services import scan_cache as sc
from app.services.agent.graph import run_analysis
from app.services.agent.llm import Reasoner
from app.services.cache import LookupCache
from app.services.extractors import extract_upi_ids, extract_urls, parse_upi_uri
from app.services.ocr import ScreenshotReader
from app.services.pipeline import Checks, PipelineOutput
from app.services.scan_cache import ScanCache
from app.services.screenshot import ScreenshotContext

router = APIRouter(tags=["analysis"])
logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 5000
MAX_URL_CHARS = 2048
DB_SAVE_TIMEOUT_S = 5
R = TypeVar("R", bound=AnalysisResult)

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


# One budget per client IP shared by all /analyze/* routes: each can cost Groq quota.
ANALYZE_LIMIT = rate_limit("analyze", "RATE_LIMIT_ANALYZE")

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
        return self.save_result(
            out.result,
            input_type,
            raw_input,
            out.entities.normalized_text,
            out.entities.model_dump(mode="json"),
            language_hint,
            out.latency_ms,
        )

    def save_result(
        self,
        result: R,
        input_type: InputType,
        raw_input: str,
        normalized_text: str | None,
        extracted_entities: dict[str, Any],
        language_hint: str | None,
        latency_ms: dict[str, float],
    ) -> R:
        """Gives the result a new id and saves it (also used for scan-cache hits, so every
        scan is its own analysis)."""
        result = result.model_copy(update={"id": uuid4(), "created_at": datetime.now(UTC)})
        row = Analysis(
            id=result.id,
            created_at=result.created_at,
            input_type=input_type,
            raw_input=raw_input,
            normalized_text=normalized_text,
            extracted_entities=extracted_entities,
            language_hint=language_hint,
            latency_ms=latency_ms,
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


class ScanCacher:
    """Route-side glue for the scan cache (app/services/scan_cache.py).

    lookup() returns a cached result as a fresh analysis (new id, saved like any other, with
    cached=True); store() caches a result whose LLM step succeeded. Database writes (the L2
    row, hit_count) run after the response is sent. Without a cache, or with
    ?explain=false (which promises template explanations), both do nothing.
    """

    def __init__(self, request: Request, background: BackgroundTasks, save: SaverDep) -> None:
        self.cache: ScanCache | None = getattr(request.app.state, "scan_cache", None)
        self.background = background
        self.save = save

    async def lookup(
        self,
        key: str,
        explain: bool,
        model: type[R],
        input_type: InputType,
        raw_input: str | None,
        language_hint: str | None = None,
    ) -> R | None:
        """`raw_input` None: the one stored with the cached result (images)."""
        if self.cache is None or not explain:
            return None
        start = time.perf_counter()
        hit = await self.cache.get(key)
        if hit is None:
            return None
        try:
            result = model.model_validate(hit.payload["result"])
            row = hit.payload["row"]
        except Exception as exc:  # an entry from an older format: treat as a miss
            logger.warning("unusable scan_cache entry %s: %s", key, type(exc).__name__)
            return None
        if hit.layer == "l2":
            self.background.add_task(self.cache.record_hit, key)
        ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("scan cache hit", extra={"extra_fields": {"key": key, "layer": hit.layer}})
        return self.save.save_result(
            result.model_copy(update={"cached": True}),
            input_type,
            row["raw_input"] if raw_input is None else raw_input,
            row["normalized_text"],
            row["extracted_entities"],
            language_hint,
            {"cache": ms, "total": ms},
        )

    def store(
        self, key: str, explain: bool, result: AnalysisResult, out: PipelineOutput, raw_input: str
    ) -> None:
        # confidence is set only when the LLM's assessment was used: never cache template
        # fallbacks (timeouts, 429s, invalid output, no API key).
        if self.cache is None or not explain or result.confidence is None:
            return
        payload = {
            "result": result.model_dump(mode="json", exclude={"id", "created_at", "cached"}),
            "row": {
                "raw_input": raw_input,
                "normalized_text": out.entities.normalized_text,
                "extracted_entities": out.entities.model_dump(mode="json"),
            },
        }
        tags = sc.entity_tags(out.entities)
        expires_at = self.cache.put(key, payload, tags)
        self.background.add_task(self.cache.persist, key, payload, expires_at, tags)


CacherDep = Annotated[ScanCacher, Depends()]


@router.post("/analyze/text", response_model=AnalysisResult, dependencies=[ANALYZE_LIMIT])
async def analyze_text_route(
    body: AnalyzeTextRequest,
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    cacher: CacherDep,
    explain: ExplainQuery = True,
) -> AnalysisResult:
    key = sc.key_message(body.text, body.language_hint)
    hit = await cacher.lookup(
        key, explain, AnalysisResult, InputType.TEXT, body.text, body.language_hint
    )
    if hit is not None:
        return hit
    out = await run_analysis(
        body.text,
        settings,
        checks=checks,
        reasoner=reasoner,
        language_hint=body.language_hint,
        explain=explain,
    )
    result = save(out, InputType.TEXT, body.text, body.language_hint)
    cacher.store(key, explain, result, out, body.text)
    return result


@router.post("/analyze/url", response_model=AnalysisResult, dependencies=[ANALYZE_LIMIT])
async def analyze_url_route(
    body: AnalyzeURLRequest,
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    cacher: CacherDep,
    explain: ExplainQuery = True,
) -> AnalysisResult:
    key = sc.key_url(body.url)
    if hit := await cacher.lookup(key, explain, AnalysisResult, InputType.URL, body.url):
        return hit
    out = await run_analysis(
        body.url, settings, checks=checks, reasoner=reasoner, message_text=False, explain=explain
    )
    result = save(out, InputType.URL, body.url)
    cacher.store(key, explain, result, out, body.url)
    return result


@router.post("/analyze/upi", response_model=AnalysisResult, dependencies=[ANALYZE_LIMIT])
async def analyze_upi_route(
    body: AnalyzeUPIRequest,
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    cacher: CacherDep,
    explain: ExplainQuery = True,
) -> AnalysisResult:
    value = body.upi_id or body.upi_uri or ""
    key = sc.key_upi(body.upi_id, body.upi_uri)
    if hit := await cacher.lookup(key, explain, AnalysisResult, InputType.UPI, value):
        return hit
    out = await run_analysis(
        value, settings, checks=checks, reasoner=reasoner, message_text=False, explain=explain
    )
    result = save(out, InputType.UPI, value)
    cacher.store(key, explain, result, out, value)
    return result


@router.post(
    "/analyze/qr",
    response_model=AnalysisResult,
    dependencies=[ANALYZE_LIMIT],
    responses={
        413: {"description": "Image larger than 5 MB (code image_too_large)"},
        415: {"description": "Not a PNG or JPEG image (code unsupported_image)"},
        422: {"description": "No QR code found in the image (code no_qr_code)"},
    },
)
async def analyze_qr_route(
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    cacher: CacherDep,
    image: Annotated[UploadFile, File(description="PNG or JPEG, max 5 MB")],
    explain: ExplainQuery = True,
) -> AnalysisResult:
    data = await image.read(qr.MAX_IMAGE_BYTES + 1)
    try:
        decoded = await asyncio.to_thread(qr.decode_qr, data)
    except qr.ImageTooLargeError as exc:
        raise ApiError(413, str(exc), code="image_too_large") from exc
    except qr.UnsupportedImageError as exc:
        raise ApiError(415, str(exc), code="unsupported_image") from exc
    except qr.NoQRCodeError as exc:
        raise ApiError(422, str(exc), code="no_qr_code") from exc
    key = sc.key_image("qr", data)
    if hit := await cacher.lookup(key, explain, AnalysisResult, InputType.QR, decoded.payload):
        return hit
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
    result = save(out, InputType.QR, decoded.payload)
    cacher.store(key, explain, result, out, decoded.payload)
    return result


# Fewer letters/digits than this: nothing to analyze ("no readable text found").
MIN_SCREENSHOT_CHARS = 3
_WORD_CHAR = re.compile(r"\w")
OCRReaderDep = Annotated[ScreenshotReader | None, Depends(get_ocr_reader)]


@router.post(
    "/analyze/screenshot",
    response_model=ScreenshotAnalysisResult,
    dependencies=[ANALYZE_LIMIT],
    responses={
        413: {"description": "Image larger than 5 MB"},
        415: {"description": "Not a PNG, JPEG or WEBP image (code unsupported_image)"},
        422: {"description": "No readable text in the image (code no_text_found)"},
        503: {"description": "No OCR engine could read the image (code ocr_unavailable)"},
    },
)
async def analyze_screenshot_route(
    save: SaverDep,
    settings: SettingsDep,
    checks: ChecksDep,
    reasoner: ReasonerDep,
    reader: OCRReaderDep,
    cacher: CacherDep,
    image: Annotated[UploadFile, File(description="PNG, JPEG or WEBP, max 5 MB")],
    language_hint: Annotated[
        Literal["en", "hi", "hinglish"] | None,
        Form(description="'hi' returns advice in Hindi. Explanations are always both."),
    ] = None,
    explain: ExplainQuery = True,
) -> ScreenshotAnalysisResult:
    """OCR (Groq vision, else local) -> the usual analysis on the extracted text, plus the
    screenshot signals (sender_check, fake_payment_proof). A QR code in the image is decoded
    and analyzed with the text. The image is never stored."""
    data = await image.read(ocr.MAX_IMAGE_BYTES + 1)
    try:
        prepared = await asyncio.to_thread(ocr.prepare_image, data)
    except ocr.ImageTooLargeError as exc:
        raise ApiError(413, str(exc), code="image_too_large") from exc
    except ocr.UnsupportedImageError as exc:
        raise ApiError(415, str(exc), code="unsupported_image") from exc
    if reader is None:
        raise ApiError(503, "screenshot reading is not configured", code="ocr_unavailable")
    key = sc.key_image("screenshot", data, language_hint)
    hit = await cacher.lookup(
        key, explain, ScreenshotAnalysisResult, InputType.SCREENSHOT, None, language_hint
    )
    if hit is not None:
        return hit

    async def find_qr() -> tuple[qr.QRPayload | None, float]:
        start = time.perf_counter()
        try:
            found = await asyncio.to_thread(qr.find_qr, prepared.full)
        except Exception as exc:  # fail soft: the text is still analyzed
            logger.warning("screenshot QR decoding failed: %s: %s", type(exc).__name__, exc)
            found = None
        return found, round((time.perf_counter() - start) * 1000, 2)

    start = time.perf_counter()
    read, (found, qr_ms) = await asyncio.gather(reader.read(prepared), find_qr())
    ocr_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "screenshot read",
        extra={"extra_fields": {
            "ocr_engine": read.engine, "ocr_ms": ocr_ms, "chars": len(read.text),
            "qr": found is not None, "notes": list(read.notes),
        }},
    )  # fmt: skip
    qr_payload = found.payload if found else None
    text = "\n".join(t for t in (read.text, qr_payload) if t)[:MAX_TEXT_CHARS]
    if len(_WORD_CHAR.findall(text)) < MIN_SCREENSHOT_CHARS:
        if read.engine == "none" and read.rate_limited:
            raise ApiError(
                503,
                "Kavach is seeing high traffic right now. Please try again in a minute.",
                code="high_traffic",
                headers={"Retry-After": "60"},
            )
        if read.engine == "none":
            raise ApiError(
                503,
                "could not read the screenshot right now; paste the message text instead",
                code="ocr_unavailable",
            )
        raise ApiError(422, "no readable text found in the image", code="no_text_found")

    out = await run_analysis(
        text,
        settings,
        checks=checks,
        reasoner=reasoner,
        language_hint=language_hint,
        explain=explain,
        screenshot=ScreenshotContext(read.sender, read.app, read.is_payment_receipt),
    )
    out = replace(out, latency_ms={**out.latency_ms, **read.latency_ms, "ocr": ocr_ms, "qr": qr_ms})
    result = save(out, InputType.SCREENSHOT, text, language_hint)
    response = ScreenshotAnalysisResult(
        **result.model_dump(),
        extracted_text=read.text,
        ocr_engine=read.engine,
        sender=read.sender,
        app=read.app,
        is_payment_receipt=read.is_payment_receipt,
        qr_payload=qr_payload,
        ocr_notes=list(read.notes),
    )
    # A local-OCR reading after vision failed is a degraded result: not cached, so the next
    # scan tries vision again. (Local is the best there is when vision isn't configured.)
    if read.engine == "groq_vision" or reader.vision is None:
        cacher.store(key, explain, response, out, text)
    return response


@router.get("/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: UUID, session: SessionDep) -> AnalysisResult:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise ApiError(404, "analysis not found")
    result = AnalysisResult.model_validate(row)
    entities = ExtractedEntities.model_validate(row.extracted_entities)
    return result.model_copy(update={"entities": reputation.reportable(entities)})
