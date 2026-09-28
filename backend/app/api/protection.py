"""Abuse protection: real client IP behind a proxy, per-IP rate limits, body size limits and
security headers.

Rate limits use `limits` (the engine behind slowapi) directly, with one in-memory limiter per
app: the budgets come from Settings through FastAPI dependencies, so they follow dependency
overrides, and every app (every test) starts with empty counters. In-memory means
per-process: with several workers or instances each has its own counters.
"""

import ipaddress
import logging
import math
import time
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request, params
from fastapi.responses import JSONResponse
from limits import RateLimitItem, parse_many
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import SECURITY_HEADERS, ApiError, error_body
from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------- client IP


def is_internal(host: str) -> bool:
    """Not a public internet address: private, loopback, link-local, or the 100.64.0.0/10
    shared range that platforms use internally (Python counts that one as neither private
    nor global)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not ip.is_global


def _valid_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def forwarded_hops(forwarded_for: list[str]) -> list[str]:
    """All X-Forwarded-For entries, repeated headers joined in order."""
    return [h.strip() for value in forwarded_for for h in value.split(",") if h.strip()]


def forwarded_client(peer: str, forwarded_for: list[str], trusted_hops: int) -> str | None:
    """The client IP from X-Forwarded-For, or None to keep the peer address.

    Only trusted when the direct peer is internal (the platform's proxy; the app isn't
    reachable any other way on Render). Proxies append, so the last `trusted_hops` entries
    were written by them and anything further left may be the client's own forgery: take
    the entry `trusted_hops` from the right, never the leftmost. Trailing internal
    addresses (a platform proxy adding its own hop) are dropped first, so an extra
    internal hop can't shift the pick onto the Cloudflare edge IP; a client can't add
    entries to the right of the ones proxies append.
    """
    if trusted_hops <= 0 or not is_internal(peer):
        return None
    hops = forwarded_hops(forwarded_for)
    while hops and is_internal(hops[-1]):
        hops.pop()
    if not hops:
        return None
    candidate = hops[-trusted_hops] if len(hops) >= trusted_hops else hops[0]
    return candidate if _valid_ip(candidate) else None


class ProxyHeadersMiddleware:
    """Replaces scope["client"] with the real client IP (see forwarded_client).

    Uvicorn's own --proxy-headers can't do this on Render: with --forwarded-allow-ips='*' it
    takes the leftmost X-Forwarded-For entry, which the client controls, and trusting only
    the proxy's network would make every request come from a Cloudflare edge IP.
    """

    def __init__(self, app: ASGIApp, trusted_hops: int) -> None:
        self.app = app
        self.trusted_hops = trusted_hops

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and self.trusted_hops > 0:
            peer = scope["client"][0] if scope.get("client") else ""
            headers = Headers(scope=scope)
            client = forwarded_client(peer, headers.getlist("x-forwarded-for"), self.trusted_hops)
            scope = dict(scope, proxy_peer=peer)  # for GET /debug/client-ip
            if client is not None:
                scope["client"] = (client, 0)
                proto = headers.get("x-forwarded-proto", "").split(",")[-1].strip()
                if proto in ("http", "https"):
                    scope["scheme"] = proto
        await self.app(scope, receive, send)


# ----------------------------------------------------------------------------- rate limits


@lru_cache(maxsize=32)
def _parse(rate: str) -> list[RateLimitItem]:
    return parse_many(rate)


class RateLimiter:
    def __init__(self) -> None:
        self._limiter = MovingWindowRateLimiter(MemoryStorage())

    def hit(self, scope: str, rate: str, key: str) -> int | None:
        """Count one request. Returns None if allowed, else the seconds until it would be."""
        for item in _parse(rate):
            if not self._limiter.hit(item, scope, key):
                reset_at, _ = self._limiter.get_window_stats(item, scope, key)
                return max(1, math.ceil(reset_at - time.time()))
        return None


def rate_limit(scope: str, setting: str) -> params.Depends:
    """Dependency: per-client-IP limit named by a Settings field (e.g. RATE_LIMIT_ANALYZE).

    Routes that share a scope share one budget. 429 with Retry-After when exceeded.
    """

    async def check(request: Request, settings: Annotated[Settings, Depends(get_settings)]) -> None:
        limiter: RateLimiter | None = getattr(request.app.state, "rate_limiter", None)
        if not settings.RATE_LIMIT_ENABLED or limiter is None:
            return
        rate = getattr(settings, setting)
        key = request.client.host if request.client else "unknown"
        retry_after = limiter.hit(scope, rate, key)
        if retry_after is not None:
            logger.warning(
                "rate limited",
                extra={"extra_fields": {"scope": scope, "limit": rate, "path": request.url.path}},
            )
            raise ApiError(
                429,
                f"Too many requests (limit: {rate}). Try again in {retry_after} s.",
                headers={"Retry-After": str(retry_after)},
            )

    return Depends(check)


# ----------------------------------------------------------------------------- body size


def _human(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB".replace(".0 MB", " MB")
    return f"{n // 1024} KB"


class BodyTooLarge(ApiError):
    # An HTTPException, so FastAPI's body parsing re-raises it as is (it turns other
    # errors into a 400) and the exception handlers render it.
    def __init__(self, limit: int) -> None:
        super().__init__(413, f"Request body is too large (max {_human(limit)}).")


class BodySizeLimitMiddleware:
    """Rejects request bodies over the limit with 413: up front from Content-Length, and
    while streaming for chunked requests (which have none). Multipart uploads get the
    upload limit, everything else the JSON limit."""

    def __init__(self, app: ASGIApp, json_limit: int, upload_limit: int) -> None:
        self.app = app
        self.json_limit = json_limit
        self.upload_limit = upload_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        multipart = headers.get("content-type", "").startswith("multipart/form-data")
        limit = self.upload_limit if multipart else self.json_limit

        declared = headers.get("content-length")
        if declared is not None:
            if not declared.isdigit():
                await _send_error(send, 400, "bad_request", "Invalid Content-Length header.")
                return
            if int(declared) > limit:
                exc = BodyTooLarge(limit)
                await _send_error(send, 413, exc.code, exc.detail)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge(limit)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge as exc:  # body read outside the route's exception handling
            if not started:
                await _send_error(send, 413, exc.code, exc.detail)


async def _send_error(send: Send, status: int, code: str, message: str) -> None:
    response = JSONResponse(error_body(code, message), status)
    await send({"type": "http.response.start", "status": status, "headers": response.raw_headers})
    await send({"type": "http.response.body", "body": response.body})


# ----------------------------------------------------------------------------- headers


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)
