"""Abuse protection and production hardening: rate limits, client IP behind Render's proxy,
body limits, the error format, security headers, CORS, docs, /health."""

import logging
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.api.protection import forwarded_client
from app.api.routes import report
from app.core.config import Settings, get_settings
from app.core.enums import EntityType
from app.db.models import ReportedEntity
from app.main import create_app
from tests.conftest import ClientFactory, settings_for_tests

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
        # a public peer is not our proxy: the header is ignored
        ("8.8.8.8", ["1.1.1.1, 104.22.17.40"], 2, None),
        ("10.1.2.3", ["1.1.1.1, 104.22.17.40"], 0, None),
        ("10.1.2.3", [], 2, None),
        ("10.1.2.3", ["not-an-ip, 104.22.17.40"], 2, None),
    ],
)
def test_forwarded_client(peer: str, header: list[str], hops: int, expected: str | None) -> None:
    assert forwarded_client(peer, header, hops) == expected


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
