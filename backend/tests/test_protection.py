"""Abuse protection and production hardening: rate limits, client IP behind Render's proxy,
body limits, the error format, security headers, CORS, docs, /health."""

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import httpx
import pytest
import respx
from fastapi import FastAPI

from app.api.protection import forwarded_client
from app.api.routes import report
from app.api.routes.health import CachedCheck
from app.core.config import Settings, get_settings
from app.core.enums import EntityType
from app.db.models import ReportedEntity
from app.main import create_app
from app.services.agent.llm import GroqReasoner, PingResult
from tests.conftest import ClientFactory, settings_for_tests
from tests.fakes import scripted_groq

TEXT = {"text": "Your electricity bill is due tomorrow, pay at the office."}


def _app(**overrides: Any) -> tuple[FastAPI, httpx.AsyncClient]:
    settings = settings_for_tests(**overrides)
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return app, httpx.AsyncClient(transport=transport, base_url="http://test")


# ----------------------------------------------------------------------------- rate limits


async def test_analyze_routes_share_one_limit(make_client: ClientFactory) -> None:
    async with make_client(RATE_LIMIT_ENABLED=True, RATE_LIMIT_ANALYZE="2/minute") as client:
        assert (await client.post("/analyze/text?explain=false", json=TEXT)).status_code == 200
        upi = {"upi_id": "someone@ybl"}
        assert (await client.post("/analyze/upi?explain=false", json=upi)).status_code == 200
        resp = await client.post("/analyze/text?explain=false", json=TEXT)
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"
    assert "2/minute" in resp.json()["error"]["message"]
    assert 1 <= int(resp.headers["Retry-After"]) <= 60


async def test_report_has_its_own_limit(
    make_client: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def upsert(session: object, entity_type: EntityType, value: str) -> ReportedEntity:
        return ReportedEntity(
            id=uuid4(), entity_type=entity_type, value=value, report_count=1,
            is_verified_scam=False,
        )  # fmt: skip

    monkeypatch.setattr(report, "upsert_reported_entity", upsert)
    payload = {"entity_type": "upi", "value": "refund.help@ybl"}
    async with make_client(
        RATE_LIMIT_ENABLED=True, RATE_LIMIT_REPORT="1/minute", RATE_LIMIT_ANALYZE="1/minute"
    ) as client:
        assert (await client.post("/report", json=payload)).status_code == 201
        assert (await client.post("/report", json=payload)).status_code == 429
        # a different budget: analyses are still allowed
        assert (await client.post("/analyze/text?explain=false", json=TEXT)).status_code == 200


async def test_limit_is_per_forwarded_client(make_client: ClientFactory) -> None:
    def via_render(client_ip: str) -> dict[str, str]:
        # What Render delivers: "<client>, <Cloudflare edge>", after anything the client sent.
        return {"X-Forwarded-For": f"6.6.6.6, {client_ip}, 104.22.17.40"}

    async with make_client(
        RATE_LIMIT_ENABLED=True, RATE_LIMIT_ANALYZE="1/minute", TRUSTED_PROXY_HOPS=2
    ) as client:

        async def analyze(ip: str) -> int:
            resp = await client.post(
                "/analyze/text?explain=false", json=TEXT, headers=via_render(ip)
            )
            return resp.status_code

        assert await analyze("1.1.1.1") == 200
        assert await analyze("1.1.1.1") == 429
        assert await analyze("2.2.2.2") == 200  # same forged leftmost entry, other client


@pytest.mark.parametrize(
    ("peer", "header", "hops", "expected"),
    [
        ("10.1.2.3", ["1.1.1.1, 104.22.17.40"], 2, "1.1.1.1"),
        # the client prepends forged entries; they are never picked
        ("10.1.2.3", ["6.6.6.6, 7.7.7.7, 1.1.1.1, 104.22.17.40"], 2, "1.1.1.1"),
        # repeated headers are one list
        ("10.1.2.3", ["6.6.6.6", "1.1.1.1, 104.22.17.40"], 2, "1.1.1.1"),
        # fewer entries than hops: the leftmost was still written by a proxy
        ("10.1.2.3", ["1.1.1.1"], 2, "1.1.1.1"),
        ("10.1.2.3", ["1.1.1.1, 104.22.17.40"], 1, "104.22.17.40"),
        # a proxy in the shared 100.64.0.0/10 range (neither private nor global) is trusted
        ("100.64.12.7", ["1.1.1.1, 104.22.17.40"], 2, "1.1.1.1"),
        ("fd00::12", ["1.1.1.1, 104.22.17.40"], 2, "1.1.1.1"),
        # an internal proxy appending its own hop doesn't shift the pick onto the edge IP
        ("10.1.2.3", ["6.6.6.6, 1.1.1.1, 104.22.17.40, 10.9.8.7"], 2, "1.1.1.1"),
        ("10.1.2.3", ["1.1.1.1, 104.22.17.40, 100.64.0.9, 10.9.8.7"], 2, "1.1.1.1"),
        ("10.1.2.3", ["2401:4900:1c2a::1, 104.22.17.40"], 2, "2401:4900:1c2a::1"),
        # a public peer is not our proxy: the header is ignored
        ("8.8.8.8", ["1.1.1.1, 104.22.17.40"], 2, None),
        ("10.1.2.3", ["1.1.1.1, 104.22.17.40"], 0, None),
        ("10.1.2.3", [], 2, None),
        ("10.1.2.3", ["10.0.0.1, 10.0.0.2"], 2, None),  # nothing but internal hops
        ("10.1.2.3", ["not-an-ip, 104.22.17.40"], 2, None),
    ],
)
def test_forwarded_client(peer: str, header: list[str], hops: int, expected: str | None) -> None:
    assert forwarded_client(peer, header, hops) == expected


# ----------------------------------------------------------------------------- /debug/client-ip


async def test_debug_client_ip_is_off_by_default() -> None:
    _, client = _app(TRUSTED_PROXY_HOPS=2)
    async with client:
        assert (await client.get("/debug/client-ip")).status_code == 404


async def test_debug_client_ip_reports_resolution_without_header_values() -> None:
    _, client = _app(DEBUG_IP_ENDPOINT=True, TRUSTED_PROXY_HOPS=2)
    headers = {
        "X-Forwarded-For": "6.6.6.6, 1.1.1.1, 104.22.17.40",
        "CF-Connecting-IP": "1.1.1.1",
    }
    async with client:
        body = (await client.get("/debug/client-ip", headers=headers)).json()
    assert body["client_ip"] == "1.1.1.1"
    assert body["resolved_from"] == "x-forwarded-for"
    assert body["peer_kind"] == "loopback"  # the test transport's peer, 127.0.0.1
    assert body["x_forwarded_for_hops"] == 3 and body["trusted_proxy_hops"] == 2
    assert body["other_ip_headers_present"] == ["cf-connecting-ip"]
    assert isinstance(body["pid"], int)
    assert "6.6.6.6" not in str(body) and "104.22.17.40" not in str(body)


# ----------------------------------------------------------------------------- /health/llm

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
PING_REPLY = {
    "id": "x", "object": "chat.completion", "created": 0, "model": "m",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                 "finish_reason": "length"}],
}  # fmt: skip


def _groq(key: str = "gsk_testkey123") -> GroqReasoner:
    return GroqReasoner(key, "big-model", "small-model", timeout_s=2)


async def test_health_llm_disabled_without_a_key(make_client: ClientFactory) -> None:
    async with make_client() as client:
        body = (await client.get("/health/llm")).json()
    assert body["status"] == "ok" and body["llm"] == "disabled"
    assert body["config"]["key_set"] in (True, False)  # the local .env's; never the value


@respx.mock
async def test_health_llm_ok_and_cached(make_client: ClientFactory) -> None:
    route = respx.post(GROQ_URL).mock(return_value=httpx.Response(200, json=PING_REPLY))
    async with make_client(reasoner=_groq()) as client:
        first = (await client.get("/health/llm")).json()
        second = (await client.get("/health/llm")).json()
    assert route.call_count == 1  # the second answer is the cached one
    assert first["llm"] == "ok" and first["reachable"] and not first["cached"]
    assert first["model"] == "big-model" and first["error_class"] is None
    assert second["llm"] == "ok" and second["cached"]


async def test_health_llm_reports_the_error_class_without_secrets(
    make_client: ClientFactory,
) -> None:
    groq_client, _ = scripted_groq(
        httpx.ConnectError("refused while sending Bearer gsk_testkey123"), api_key="gsk_testkey123"
    )
    llm = GroqReasoner("gsk_testkey123", "big-model", "small-model", client=groq_client)
    async with make_client(reasoner=llm) as client:
        resp = await client.get("/health/llm")
    body = resp.json()
    assert resp.status_code == 200
    assert body["llm"] == "error" and body["reachable"] is False
    assert body["error_class"] == "APIConnectionError"
    assert body["error_causes"] == ["httpx.ConnectError"]
    assert body["error_message"] == "refused while sending [redacted]"
    assert "gsk_testkey123" not in resp.text
    assert isinstance(body["elapsed_ms"], float)


async def test_health_llm_is_rate_limited(make_client: ClientFactory) -> None:
    async with make_client(RATE_LIMIT_ENABLED=True, RATE_LIMIT_HEALTH_LLM="1/minute") as client:
        assert (await client.get("/health/llm")).status_code == 200
        assert (await client.get("/health/llm")).status_code == 429


async def test_cached_check_runs_once_for_concurrent_callers() -> None:
    calls = 0
    now = [0.0]

    async def check() -> PingResult:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return PingResult(True, "m", 1.0, True, 200)

    cache = CachedCheck(60, clock=lambda: now[0])
    results = await asyncio.gather(*(cache.get(check) for _ in range(5)))
    assert calls == 1 and all(r.ok for r, _ in results)
    assert sorted(age is None for _, age in results) == [False] * 4 + [True]  # one fresh
    now[0] = 59
    assert (await cache.get(check))[1] == 59 and calls == 1
    now[0] = 61
    assert (await cache.get(check))[1] is None and calls == 2


# ----------------------------------------------------------------------------- body limits


async def test_json_body_over_limit_is_413() -> None:
    _, client = _app(MAX_JSON_BODY_BYTES=1000)
    async with client:
        resp = await client.post("/analyze/text", json={"text": "a" * 2000})
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


async def test_chunked_body_over_limit_is_413() -> None:
    async def chunks() -> AsyncIterator[bytes]:  # no Content-Length
        yield b'{"text": "'
        for _ in range(10):
            yield b"a" * 500
        yield b'"}'

    _, client = _app(MAX_JSON_BODY_BYTES=1000)
    async with client:
        resp = await client.post(
            "/analyze/text", content=chunks(), headers={"Content-Type": "application/json"}
        )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"


async def test_text_over_5000_chars_is_422(make_client: ClientFactory) -> None:
    async with make_client() as client:
        resp = await client.post("/analyze/text", json={"text": "a" * 5001})
    assert resp.status_code == 422
    error = resp.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["field"] == "text"
    assert "5000" in error["message"]
    assert "aaaa" not in resp.text  # the input is not echoed back


# ----------------------------------------------------------------------------- error format


async def test_errors_share_one_shape(make_client: ClientFactory) -> None:
    async with make_client() as client:
        not_found = await client.get("/nope")
        bad_upi = await client.post("/analyze/upi", json={})
        bad_json = await client.post(
            "/analyze/text", content=b"{", headers={"Content-Type": "application/json"}
        )
        wrong_method = await client.get("/analyze/text")
    assert not_found.json() == {"error": {"code": "not_found", "message": "Not Found"}}
    assert bad_upi.json()["error"]["message"] == (
        "Invalid request: body: give exactly one of upi_id or upi_uri"
    )
    assert bad_json.status_code == 422 and bad_json.json()["error"]["details"][0]["field"] == (
        "body"
    )
    assert wrong_method.json()["error"]["code"] == "method_not_allowed"


@pytest.mark.parametrize(("env", "leaks"), [("prod", False), ("dev", True)])
async def test_unhandled_errors_hide_details_in_prod(env: str, leaks: bool) -> None:
    app, client = _app(ENV=env)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("secret connection string")

    async with client:
        resp = await client.get("/boom")
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "internal_error"
    assert ("secret connection string" in resp.text) is leaks
    assert "Traceback" not in resp.text
    assert resp.headers["X-Frame-Options"] == "DENY"


# ----------------------------------------------------------------------------- headers, CORS, docs


async def test_security_headers() -> None:
    _, client = _app()
    async with client:
        resp = await client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


async def test_cors_allows_only_configured_origins() -> None:
    preflight = {"Access-Control-Request-Method": "POST"}
    _, client = _app(ENV="prod", CORS_ORIGINS=["https://kavach.example"])
    async with client:
        ok = await client.options(
            "/analyze/text", headers={"Origin": "https://kavach.example", **preflight}
        )
        other = await client.options(
            "/analyze/text", headers={"Origin": "https://evil.example", **preflight}
        )
    assert ok.headers["access-control-allow-origin"] == "https://kavach.example"
    assert "access-control-allow-origin" not in other.headers

    _, client = _app(ENV="prod", CORS_ORIGINS=[])
    async with client:
        resp = await client.get("/health", headers={"Origin": "https://kavach.example"})
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.parametrize(
    ("env", "enable_docs", "served"),
    [("prod", None, False), ("prod", True, True), ("dev", None, True), ("dev", False, False)],
)
async def test_docs_off_in_prod_unless_enabled(
    env: str, enable_docs: bool | None, served: bool
) -> None:
    _, client = _app(ENV=env, ENABLE_DOCS=enable_docs)
    async with client:
        for path in ("/docs", "/openapi.json"):
            assert ((await client.get(path)).status_code == 200) is served


async def test_health_needs_no_database() -> None:
    app, client = _app()  # no lifespan: no engine on app.state
    async with client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ----------------------------------------------------------------------------- settings


def _settings(**values: Any) -> Settings:
    return Settings(DATABASE_URL="postgresql://u:p@h/db", **values)


def test_env_aliases_and_derived_settings() -> None:
    prod = _settings(ENV="production", CORS_ORIGINS="", ENABLE_DOCS=None)
    assert prod.ENV == "prod" and prod.is_prod and not prod.docs_enabled
    assert prod.cors_origins == []  # nothing unless configured
    dev = _settings(ENV="development", CORS_ORIGINS="", ENABLE_DOCS=None)
    assert dev.ENV == "dev" and dev.docs_enabled
    assert dev.cors_origins == ["http://localhost:3000"]


def test_cors_origins_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example/, https://b.example")
    assert _settings().CORS_ORIGINS == ["https://a.example", "https://b.example"]
    monkeypatch.setenv("CORS_ORIGINS", '["https://c.example"]')
    assert _settings().CORS_ORIGINS == ["https://c.example"]


def test_pasted_keys_are_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    # A trailing newline in the key made every Groq call fail with APIConnectionError.
    monkeypatch.setenv("GROQ_API_KEY", " gsk_abc123\n")
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "AIza-key\r\n")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b ")
    settings = _settings()
    assert settings.GROQ_API_KEY == "gsk_abc123"
    assert settings.SAFE_BROWSING_API_KEY == "AIza-key"
    assert settings.GROQ_MODEL == "openai/gpt-oss-120b"


def test_bad_rate_limit_fails_at_startup() -> None:
    with pytest.raises(ValueError, match="RATE_LIMIT_ANALYZE"):
        _settings(RATE_LIMIT_ANALYZE="lots")


async def test_pattern_signal_flag_skips_the_embedding_model() -> None:
    app = create_app(
        get_settings().model_copy(update={"PATTERN_SIGNAL_ENABLED": False, "GROQ_API_KEY": ""})
    )
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level  # the lifespan installs JSON logging
    try:
        async with app.router.lifespan_context(app):  # creates the engine; doesn't connect
            assert app.state.embedder is None
    finally:
        root.handlers[:], root.level = handlers, level
