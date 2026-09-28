"""Temporary diagnostics. Only mounted when DEBUG_IP_ENDPOINT=true (see create_app)."""

import ipaddress
import os
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from app.api.protection import forwarded_hops, is_internal
from app.core.config import Settings, get_settings

router = APIRouter(tags=["debug"])

# Other headers some proxies use for the client IP; reported as present or not, never values.
_OTHER_IP_HEADERS = ("cf-connecting-ip", "true-client-ip", "x-real-ip", "forwarded")


def _kind(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "not an ip"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    return "internal" if is_internal(host) else "public"


@router.get("/debug/client-ip")
async def client_ip(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, Any]:
    """How this request's client IP was resolved, and which worker process served it. Call
    it several times: the IP should be yours every time, and one PID means one worker (one
    set of rate-limit counters)."""
    client = request.client.host if request.client else None
    peer = request.scope.get("proxy_peer")
    return {
        "client_ip": client,  # the rate-limit key
        "resolved_from": "x-forwarded-for" if peer is not None and client != peer else "peer",
        "peer_kind": _kind(peer) if peer is not None else None,
        "x_forwarded_for_hops": len(forwarded_hops(request.headers.getlist("x-forwarded-for"))),
        "trusted_proxy_hops": settings.TRUSTED_PROXY_HOPS,
        "other_ip_headers_present": [h for h in _OTHER_IP_HEADERS if h in request.headers],
        "pid": os.getpid(),
        "web_concurrency_env": os.environ.get("WEB_CONCURRENCY"),
    }
