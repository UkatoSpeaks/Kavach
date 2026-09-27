"""url_intel: link expansion, RDAP domain age, Safe Browsing, allowlist.

All outbound HTTP is mocked with respx; unmatched requests raise instead of going out.
"""

import asyncio
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import UrlCache
from app.services import url_intel
from app.services.url_intel import SAFE_BROWSING_URL, expand, is_official, registration_date
from tests.conftest import ClientFactory

RDAP = "https://rdap.org/domain/{}"


def rdap_registered(days_ago: int) -> httpx.Response:
    when = datetime.now(UTC) - timedelta(days=days_ago)
    return httpx.Response(
        200,
        json={
            "objectClassName": "domain",
            "events": [
                {"eventAction": "registration", "eventDate": when.strftime("%Y-%m-%dT%H:%M:%SZ")},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
        },
    )


def signal(body: dict, source: str) -> dict:
    return next(s for s in body["signal_breakdown"] if s["source"] == source)


def flag_codes(body: dict) -> set[str]:
    return {f["code"] for f in body["red_flags"]}


# ----------------------------------------------------------------------------- API


@respx.mock
async def test_lookalike_on_5_day_old_domain_scores_scam(make_client: ClientFactory) -> None:
    rdap = respx.get(RDAP.format("sbi-kyc-update.xyz")).mock(return_value=rdap_registered(5))
    async with make_client() as client:
        resp = await client.post("/analyze/url", json={"url": "https://sbi-kyc-update.xyz/login"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_score"] >= 70
    assert body["verdict"] == "scam"
    assert body["scam_type"] == "phishing_link"
    assert rdap.called
    intel = signal(body, "url_intel")
    assert intel["weight"] > 0 and intel["score"] >= 80
    assert "url_new_domain" in flag_codes(body)
    assert "imitates 'sbi'" in intel["detail"] and "registered 5 day(s) ago" in intel["detail"]


@respx.mock
async def test_shortened_link_caught_via_final_domain(make_client: ClientFactory) -> None:
    respx.head("https://bit.ly/3xRwd9").mock(
        return_value=httpx.Response(301, headers={"Location": "https://t.co/abc"})
    )
    respx.head("https://t.co/abc").mock(
        return_value=httpx.Response(302, headers={"Location": "https://hdfc-reward-points.top/c"})
    )
    respx.head("https://hdfc-reward-points.top/c").mock(return_value=httpx.Response(200))
    respx.get(RDAP.format("hdfc-reward-points.top")).mock(return_value=httpx.Response(404))

    async with make_client() as client:
        resp = await client.post(
            "/analyze/text",
            json={"text": "Your HDFC reward points expire today, redeem: https://bit.ly/3xRwd9"},
        )

    body = resp.json()
    assert resp.status_code == 200
    intel = signal(body, "url_intel")
    assert "hdfc-reward-points.top" in intel["detail"]
    assert "2 hop(s)" in intel["detail"]
    lookalike = next(f for f in body["red_flags"] if f["code"] == "url_lookalike")
    assert lookalike["evidence"] == "hdfc-reward-points.top (imitates 'hdfc')"
    assert "url_shortener_redirect" in flag_codes(body)
    # The rules only see bit.ly; the final domain is what makes this a scam.
    assert signal(body, "rules")["score"] < 70
    assert body["verdict"] == "scam"


@respx.mock
async def test_shortener_to_established_clean_site_is_safe(make_client: ClientFactory) -> None:
    respx.head("https://bit.ly/pydocs").mock(
        return_value=httpx.Response(301, headers={"Location": "https://docs.python.org/3/"})
    )
    respx.head("https://docs.python.org/3/").mock(return_value=httpx.Response(200))
    respx.get(RDAP.format("python.org")).mock(return_value=rdap_registered(11_000))
    async with make_client() as client:
        body = (await client.post("/analyze/url", json={"url": "https://bit.ly/pydocs"})).json()
    intel = signal(body, "url_intel")
    assert intel["detail"].startswith(
        "bit.ly: redirects to python.org (1 hop(s)); via a shortener, to an established site; "
        "registered 1996"
    )
    assert intel["score"] == 10
    assert body["verdict"] == "safe"


@respx.mock
async def test_official_link_stays_safe_without_network(make_client: ClientFactory) -> None:
    async with make_client() as client:
        resp = await client.post(
            "/analyze/url", json={"url": "https://www.onlinesbi.sbi/sbicollect/"}
        )
        text = await client.post(
            "/analyze/text",
            json={"text": "Your statement is ready. Login at https://www.hdfcbank.com/ -HDFC"},
        )

    assert respx.calls.call_count == 0  # allowlisted: nothing is looked up
    for r in (resp, text):
        body = r.json()
        assert body["verdict"] == "safe"
        assert body["risk_score"] < 35
        intel = signal(body, "url_intel")
        assert (intel["score"], "official domain" in intel["detail"]) == (0, True)
        assert intel["weight"] > 0  # an official domain is evidence of safety


@respx.mock
async def test_shortener_to_official_domain_is_safe(make_client: ClientFactory) -> None:
    respx.head("https://amzn.to/4abc").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.amazon.in/dp/B0C"})
    )
    async with make_client() as client:
        resp = await client.post("/analyze/url", json={"url": "https://amzn.to/4abc"})
    body = resp.json()
    assert body["verdict"] == "safe"
    assert signal(body, "url_intel")["score"] == 0


@pytest.mark.parametrize(
    "error",
    [httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow")],
    ids=["read-timeout", "connect-timeout"],
)
async def test_rdap_and_safe_browsing_timeouts_fail_soft(
    make_client: ClientFactory, error: Exception
) -> None:
    text = "Get 70% off on shoes today only: https://shoe-mega-deals.com/sale"
    with respx.mock:
        respx.get(RDAP.format("shoe-mega-deals.com")).mock(side_effect=error)
        respx.post(SAFE_BROWSING_URL).mock(side_effect=error)
        async with make_client(SAFE_BROWSING_API_KEY="test-key") as client:
            resp = await client.post("/analyze/text", json={"text": text})

    assert resp.status_code == 200
    body = resp.json()
    intel = signal(body, "url_intel")
    assert intel["weight"] == 0
    assert intel["detail"].startswith("unavailable")
    assert "domain age (RDAP): timed out" in intel["detail"]
    assert "Safe Browsing: timed out" in intel["detail"]
    assert signal(body, "rules")["weight"] == 1.0  # the remaining signals decide
    assert body["id"] is not None


async def test_slow_lookup_is_cut_off_by_timeout(make_client: ClientFactory) -> None:
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return rdap_registered(5)

    with respx.mock:
        respx.get(RDAP.format("shoe-mega-deals.com")).mock(side_effect=hang)
        async with make_client(HTTP_TIMEOUT_S=0.2) as client:
            resp = await client.post("/analyze/url", json={"url": "https://shoe-mega-deals.com"})

    assert resp.status_code == 200
    intel = signal(resp.json(), "url_intel")
    assert intel["weight"] == 0 and "RDAP): timed out" in intel["detail"]


@respx.mock
async def test_safe_browsing_hit_is_decisive(make_client: ClientFactory) -> None:
    url = "https://plain-looking-site.com/page"
    sb = respx.post(SAFE_BROWSING_URL).mock(
        return_value=httpx.Response(
            200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": url}}]}
        )
    )
    respx.get(RDAP.format("plain-looking-site.com")).mock(return_value=rdap_registered(4000))
    async with make_client(SAFE_BROWSING_API_KEY="test-key") as client:
        resp = await client.post("/analyze/url", json={"url": url})

    body = resp.json()
    assert signal(body, "url_intel")["score"] == 100
    assert body["risk_score"] >= 90 and body["verdict"] == "scam"
    assert "url_safe_browsing" in flag_codes(body)
    request = sb.calls.last.request
    assert request.headers["X-Goog-Api-Key"] == "test-key"
    assert "test-key" not in str(request.url)  # never in the URL (it would be logged)


@respx.mock
async def test_clean_old_domain_does_not_dilute_rules(make_client: ClientFactory) -> None:
    respx.get(RDAP.format("telegram.me")).mock(return_value=rdap_registered(4000))
    text = (
        "Earn ₹5000 daily by liking YouTube videos. Part time job, pay ₹1000 to unlock VIP "
        "tasks. Join https://telegram.me/earn_daily_hr"
    )
    async with make_client() as client:
        body = (await client.post("/analyze/text", json={"text": text})).json()
    intel = signal(body, "url_intel")
    assert intel["weight"] == 0 and "no issues found" in intel["detail"]
    # The score is the mean of the other signals alone: url_intel is not in it.
    counted = [s for s in body["signal_breakdown"] if s["weight"] > 0]
    assert "url_intel" not in {s["source"] for s in counted}
    assert body["risk_score"] == round(sum(s["score"] * s["weight"] for s in counted))


@pytest.mark.db
@respx.mock
async def test_lookups_are_cached_in_url_cache(
    make_db_client: ClientFactory, db_session: AsyncSession
) -> None:
    rdap = respx.get(RDAP.format("sbi-kyc-update.xyz")).mock(return_value=rdap_registered(5))
    async with make_db_client() as client:
        for _ in range(2):
            resp = await client.post("/analyze/url", json={"url": "https://sbi-kyc-update.xyz/"})
            assert resp.json()["verdict"] == "scam"

    assert rdap.call_count == 1
    row = await db_session.get(UrlCache, "rdap:sbi-kyc-update.xyz")
    assert row is not None and row.result["registered"] is not None


@pytest.mark.db
@respx.mock
async def test_stale_cache_entry_is_refreshed(
    make_db_client: ClientFactory, db_session: AsyncSession
) -> None:
    db_session.add(
        UrlCache(
            url="rdap:sbi-kyc-update.xyz",
            result={"registered": "2001-01-01"},
            checked_at=datetime.now(UTC) - timedelta(hours=25),
        )
    )
    await db_session.flush()
    rdap = respx.get(RDAP.format("sbi-kyc-update.xyz")).mock(return_value=rdap_registered(5))
    async with make_db_client() as client:
        body = (
            await client.post("/analyze/url", json={"url": "https://sbi-kyc-update.xyz/"})
        ).json()
    assert rdap.call_count == 1
    assert "url_new_domain" in flag_codes(body)
    rows = (await db_session.execute(select(UrlCache.result).where(
        UrlCache.url == "rdap:sbi-kyc-update.xyz"
    ))).scalars().all()  # fmt: skip
    assert rows[0]["registered"] != "2001-01-01"


@pytest.mark.parametrize("payload", [{}, {"url": "not a url"}, {"url": "a.com b.com"}])
async def test_analyze_url_rejects_bad_input(make_client: ClientFactory, payload: dict) -> None:
    async with make_client() as client:
        assert (await client.post("/analyze/url", json=payload)).status_code == 422


# ----------------------------------------------------------------------------- expansion


@respx.mock
async def test_expand_falls_back_to_streamed_get_when_head_rejected() -> None:
    respx.head("https://tinyurl.com/x").mock(return_value=httpx.Response(405))
    get = respx.get("https://tinyurl.com/x").mock(
        return_value=httpx.Response(301, headers={"Location": "/final"}, content=b"x" * 10_000)
    )
    respx.head("https://tinyurl.com/final").mock(return_value=httpx.Response(200))
    async with httpx.AsyncClient() as client:
        chain = await expand(client, "https://tinyurl.com/x")
    assert chain == ["https://tinyurl.com/x", "https://tinyurl.com/final"]
    assert get.called


@respx.mock
async def test_expand_stops_after_max_hops() -> None:
    for i in range(10):
        respx.head(f"https://bit.ly/{i}").mock(
            return_value=httpx.Response(302, headers={"Location": f"https://bit.ly/{i + 1}"})
        )
    async with httpx.AsyncClient() as client:
        chain = await expand(client, "https://bit.ly/0")
    assert len(chain) == url_intel.MAX_HOPS + 1
    assert respx.calls.call_count == url_intel.MAX_HOPS


@respx.mock
@pytest.mark.parametrize(
    "target",
    ["http://127.0.0.1:8000/admin", "http://localhost/", "http://169.254.169.254/latest",
     "http://[::1]/", "file:///etc/passwd"],
)  # fmt: skip
async def test_expand_never_contacts_private_hosts(target: str) -> None:
    respx.head("https://bit.ly/ssrf").mock(
        return_value=httpx.Response(302, headers={"Location": target})
    )
    async with httpx.AsyncClient() as client:
        chain = await expand(client, "https://bit.ly/ssrf")
    assert chain == ["https://bit.ly/ssrf", target]
    assert respx.calls.call_count == 1


@respx.mock
@pytest.mark.parametrize(
    "addresses",
    [["127.0.0.1"], ["10.1.2.3"], ["::1"], ["93.184.215.14", "192.168.0.5"],
     ["::ffff:127.0.0.1"], ["169.254.169.254"], ["fe80::1"], ["224.0.0.1"], []],
    ids=["loopback-v4", "private-10", "loopback-v6", "one-of-many-private",
         "v4-mapped-v6-loopback", "link-local-metadata", "link-local-v6", "multicast",
         "does-not-resolve"],
)  # fmt: skip
async def test_expand_refuses_hosts_resolving_to_private_addresses(
    fake_dns: dict[str, list[str]], addresses: list[str]
) -> None:
    # A public-looking name the static check lets through; only DNS reveals the target.
    fake_dns["innocent-looking.com"] = addresses
    respx.head("https://bit.ly/rebind").mock(
        return_value=httpx.Response(302, headers={"Location": "https://innocent-looking.com/x"})
    )
    target = respx.head("https://innocent-looking.com/x").mock(return_value=httpx.Response(200))
    async with httpx.AsyncClient() as client:
        chain = await expand(client, "https://bit.ly/rebind")
    assert chain == ["https://bit.ly/rebind", "https://innocent-looking.com/x"]
    assert not target.called


@respx.mock
async def test_expand_checks_the_first_hop_too(fake_dns: dict[str, list[str]]) -> None:
    fake_dns["bit.ly"] = ["127.0.0.1"]
    respx.route().mock(return_value=httpx.Response(200))
    async with httpx.AsyncClient() as client:
        assert await expand(client, "https://bit.ly/x") == ["https://bit.ly/x"]
    assert respx.calls.call_count == 0


@respx.mock
async def test_expand_follows_hosts_resolving_to_public_addresses(
    fake_dns: dict[str, list[str]],
) -> None:
    fake_dns["example.com"] = ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
    respx.head("https://bit.ly/ok").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    final = respx.head("https://example.com/").mock(return_value=httpx.Response(200))
    async with httpx.AsyncClient() as client:
        chain = await expand(client, "https://bit.ly/ok")
    assert chain == ["https://bit.ly/ok", "https://example.com/"]
    assert final.called


async def test_slow_dns_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    async def hang(host: str) -> list:
        await asyncio.sleep(5)
        return []

    monkeypatch.setattr(url_intel, "_getaddrinfo", hang)
    monkeypatch.setattr(url_intel, "DNS_TIMEOUT_S", 0.05)
    with respx.mock:
        async with httpx.AsyncClient() as client:
            assert await expand(client, "https://bit.ly/x") == ["https://bit.ly/x"]


# ----------------------------------------------------------------------------- pure helpers


@pytest.mark.parametrize(
    ("domain", "official"),
    [("sbi.co.in", True), ("onlinesbi.sbi", True), ("npci.org.in", True),
     ("echallan.parivahan.gov.in", True), ("icici.bank.in", True), ("flipkart.com", True),
     ("sbi-kyc.co.in", False), ("amazonaws.com", False), ("google.com", False),
     ("gov.in.evil.com", False)],
)  # fmt: skip
def test_is_official(domain: str, official: bool) -> None:
    assert is_official(domain) is official


def test_registration_date() -> None:
    assert registration_date(
        {"events": [{"eventAction": "registration", "eventDate": "2026-09-22T10:00:00Z"}]}
    ) == date(2026, 9, 22)
    assert registration_date({"events": [{"eventAction": "expiration", "eventDate": "x"}]}) is None
    assert registration_date({}) is None
    bad = {"events": [{"eventAction": "registration", "eventDate": "not a date"}]}
    assert registration_date(bad) is None
