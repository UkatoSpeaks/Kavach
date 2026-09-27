"""One error shape for every non-2xx response: {"error": {"code": ..., "message": ...}}.

Validation errors (422) also carry "details": [{"field", "message"}]. Nothing internal (stack
traces, exception messages) is returned in prod; the full error is in the logs.
"""

import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import Settings

logger = logging.getLogger(__name__)

CODES = {
    400: "bad_request",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}

# Set on every response by SecurityHeadersMiddleware; repeated on 500s, which Starlette
# renders outside all user middleware.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class ApiError(HTTPException):
    """An HTTPException with a machine-readable code (default: derived from the status)."""

    def __init__(
        self,
        status_code: int,
        message: str,
        code: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code or CODES.get(status_code, "error")


def error_body(code: str, message: str, details: list[dict[str, str]] | None = None) -> dict:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return {"error": error}


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = getattr(exc, "code", None) or CODES.get(exc.status_code, "error")
    message = exc.detail if isinstance(exc.detail, str) else HTTPStatus(exc.status_code).phrase
    return JSONResponse(error_body(code, message), exc.status_code, headers=exc.headers)


def _field(loc: tuple[Any, ...], error_type: str) -> str:
    if error_type == "json_invalid":
        return "body"  # loc is ("body", <character offset>)
    parts = [str(p) for p in loc]
    if len(parts) > 1 and parts[0] in ("body", "query", "path"):
        parts = parts[1:]
    return ".".join(parts) or "request"


def _message(msg: str) -> str:
    # Pydantic prefixes errors raised in validators with "Value error, ".
    return msg.removeprefix("Value error, ")


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    # Only loc and msg: the "input" of an error can echo 5000 characters of the request.
    details = [
        {"field": _field(tuple(e.get("loc", ())), e.get("type", "")), "message": _message(e["msg"])}
        for e in exc.errors()
    ]
    first = details[0] if details else {"field": "request", "message": "invalid"}
    message = f"Invalid request: {first['field']}: {first['message']}"
    if len(details) > 1:
        message += f" (and {len(details) - 1} more)"
    return JSONResponse(error_body("validation_error", message, details), 422)


def install_error_handlers(app: FastAPI, settings: Settings) -> None:
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Starlette re-raises after this handler, so the traceback still reaches the logs.
        message = (
            "Internal server error"
            if settings.is_prod
            else f"Internal server error: {type(exc).__name__}: {exc}"
        )
        return JSONResponse(
            error_body("internal_error", message), 500, headers=dict(SECURITY_HEADERS)
        )

    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, unhandled)
