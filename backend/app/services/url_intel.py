"""Real-world link checks -> the "url_intel" signal.

For every URL in the input:
1. Official domains (allowlist below, or registry-restricted suffixes like .gov.in/.bank.in)
   are low risk immediately, with no network calls.
2. Shortened links are expanded by following redirects (HEAD, falling back to a streamed
   GET whose body is never read), at most MAX_HOPS hops. Only public http(s) hosts are
   contacted, so a shortener can't point us at localhost or a private network.
3. The final domain gets the lookalike / cheap-TLD checks from the rules engine, a domain
   age lookup via RDAP and, if SAFE_BROWSING_API_KEY is set, a Google Safe Browsing lookup.

Every lookup has a timeout and fails soft: a failed lookup is noted in the signal detail,
and the signal is only "unavailable" if nothing could be concluded without it.
Successful lookups are cached for URL_CACHE_TTL_HOURS in url_cache.
"""

import asyncio
import ipaddress
import logging
import math
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import Settings
from app.core.enums import ScamType
from app.schemas.analysis import RedFlag
from app.schemas.entities import ExtractedURL
from app.services.cache import LookupCache
from app.services.extractors import extract_urls
from app.services.rules import RESTRICTED_SUFFIXES, SUSPICIOUS_TLDS, lookalike_brand
from app.services.scoring import SignalOutcome, severity_for

logger = logging.getLogger(__name__)

# Registered domains of banks, payment apps, regulators and big retailers. Hosting and
# link platforms (google.com, amazonaws.com, t.me, ...) are deliberately absent: anyone can
# put a page there.
OFFICIAL_DOMAINS = frozenset(
    {
        # banks
        "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "hdfcbank.com",
        "hdfc.com", "icicibank.com", "axisbank.com", "kotak.com", "pnbindia.in",
        "netpnb.com", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
        "idfcfirstbank.com", "yesbank.in", "indusind.com", "federalbank.co.in",
        # payments and regulators
        "npci.org.in", "bhimupi.org.in", "rbi.org.in", "paytm.com", "paytm.in",
        "phonepe.com", "amazonpay.in", "sebi.gov.in",
        # government services
        "indiapost.gov.in", "ippbonline.com", "parivahan.gov.in", "uidai.gov.in",
        "incometax.gov.in", "cybercrime.gov.in", "india.gov.in", "irctc.co.in",
        # shopping and delivery
        "amazon.in", "amazon.com", "amzn.in", "flipkart.com", "myntra.com", "swiggy.com",
        "zomato.com", "bluedart.com", "delhivery.com",
    }
)  # fmt: skip

MAX_HOPS = 5
MAX_URLS = 5
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 180
ESTABLISHED_DOMAIN_DAYS = 365
RDAP_URL = "https://rdap.org/domain/{domain}"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_EVIDENCE_MAX = 200

# Final-score floors for evidence that is decisive on its own (see scoring.py).
SAFE_BROWSING_FLOOR = 90
LOOKALIKE_CONFIRMED_FLOOR = 75


@dataclass(frozen=True)
class Finding:
    code: str
    weight: float  # 0-1, combined like rule weights
    en: str
    hi: str
    evidence: str
    label: str  # short form for the signal detail
    # Already flagged by the rules engine (same domain, same check): scored here, but not
    # repeated in red_flags.
    duplicate_of_rule: bool = False


@dataclass
class UrlReport:
    url: str
    chain: list[str]
    final_domain: str
    allowlisted: bool = False
    registered: date | None = None
    findings: list[Finding] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    floor: int | None = None

    @property
    def score(self) -> int:
        if any(f.code == "url_safe_browsing" for f in self.findings):
            return 100
        return round(100 * (1 - math.prod(1 - f.weight for f in self.findings)))


# --------------------------------------------------------------------------- helpers


def is_official(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return domain in OFFICIAL_DOMAINS or ("." + domain).endswith(RESTRICTED_SUFFIXES)


def _parse(url: str) -> ExtractedURL | None:
    return next(iter(extract_urls(url)), None)


def _is_public_http(url: str) -> bool:
    """True if `url` is http(s) on a public host. Blocks SSRF via redirects."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True  # a hostname


def _clip(text: str) -> str:
    return text if len(text) <= _EVIDENCE_MAX else text[: _EVIDENCE_MAX - 1] + "…"


def _reason(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


async def _cached(
    cache: LookupCache, key: str, fetch: Callable[[], Awaitable[dict[str, Any]]]
) -> dict[str, Any]:
    hit = await cache.get(key)
    if hit is not None:
        return hit
    value = await fetch()
    await cache.set(key, value)
    return value


# --------------------------------------------------------------------------- lookups


async def _probe(client: httpx.AsyncClient, url: str) -> tuple[int, str | None]:
    """(status, Location header) without downloading the body."""
    try:
        resp = await client.head(url, follow_redirects=False)
        if resp.status_code not in (400, 403, 404, 405, 501):
            return resp.status_code, resp.headers.get("location")
    except httpx.TimeoutException:
        raise
    except httpx.HTTPError:
        pass  # some servers reject or drop HEAD; retry with GET
    async with client.stream("GET", url, follow_redirects=False) as resp:
        return resp.status_code, resp.headers.get("location")


async def expand(client: httpx.AsyncClient, url: str, max_hops: int = MAX_HOPS) -> list[str]:
    """Follow redirects from `url`. Returns the chain, starting with `url`."""
    chain = [url]
    for _ in range(max_hops):
        current = chain[-1]
        if not _is_public_http(current):
            break
        status, location = await _probe(client, current)
        if status not in REDIRECT_STATUSES or not location:
            break
        chain.append(urljoin(current, location.strip()))
    return chain


def registration_date(rdap: dict[str, Any]) -> date | None:
    """The 'registration' event date from an RDAP domain response."""
    for event in rdap.get("events") or []:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00")).date()
            except ValueError:
                return None
    return None


async def rdap_lookup(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    """{"registered": "YYYY-MM-DD" | None}. None if RDAP has no record or no date (common
    for some ccTLDs); raises on network/server errors."""
    resp = await client.get(
        RDAP_URL.format(domain=domain),
        follow_redirects=True,  # rdap.org redirects to the registry's RDAP server
        headers={"Accept": "application/rdap+json, application/json"},
    )
    if resp.status_code == 404:
        return {"registered": None}
    resp.raise_for_status()
    registered = registration_date(resp.json())
    return {"registered": registered.isoformat() if registered else None}


async def safe_browsing_lookup(
    client: httpx.AsyncClient, api_key: str, urls: Sequence[str]
) -> dict[str, list[str]]:
    """url -> threat types (empty list if not listed)."""
    body = {
        "client": {"clientId": "kavach", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }  # fmt: skip
    # Key in a header, not the query string, so it never shows up in request logs.
    resp = await client.post(SAFE_BROWSING_URL, json=body, headers={"X-Goog-Api-Key": api_key})
    resp.raise_for_status()
    threats: dict[str, list[str]] = {u: [] for u in urls}
    for match in resp.json().get("matches") or []:
        url = (match.get("threat") or {}).get("url")
        if url in threats:
            threats[url].append(match.get("threatType", "UNKNOWN"))
    return threats


async def _safe_browsing_cached(
    client: httpx.AsyncClient, cache: LookupCache, api_key: str, urls: list[str]
) -> list[str]:
    """All threat types for `urls`, using the cache per URL."""
    threats: list[str] = []
    missing: list[str] = []
    for url in urls:
        hit = await cache.get(f"sb:{url}")
        if hit is None:
            missing.append(url)
        else:
            threats += hit["threats"]
    if missing:
        fresh = await safe_browsing_lookup(client, api_key, missing)
        for url, found in fresh.items():
            await cache.set(f"sb:{url}", {"threats": found})
            threats += found
    return sorted(set(threats))


# --------------------------------------------------------------------------- per URL


async def check_url(
    url: ExtractedURL,
    *,
    client: httpx.AsyncClient,
    cache: LookupCache,
    settings: Settings,
    today: date | None = None,
) -> UrlReport:
    today = today or datetime.now(UTC).date()
    timeout = settings.HTTP_TIMEOUT_S
    report = UrlReport(url=url.url, chain=[url.url], final_domain=url.registered_domain)

    if is_official(url.registered_domain) and not url.is_shortener:
        report.allowlisted = True
        return report

    # 1. Expand shortened links.
    if url.is_shortener:
        try:
            async with asyncio.timeout(timeout):
                data = await _cached(
                    cache, f"expand:{url.url}", lambda: _expand_json(client, url.url)
                )
            report.chain = data["chain"]
        except Exception as exc:  # fail soft
            report.unavailable.append(f"link expansion: {_reason(exc)}")

    final_url = report.chain[-1]
    final = _parse(final_url) if _is_public_http(final_url) else None
    if final is None:
        final = url
    report.final_domain = final.registered_domain
    redirected = final.registered_domain != url.registered_domain

    if redirected and is_official(final.registered_domain):
        report.allowlisted = True
        return report

    # 2. Static checks on the final domain.
    if redirected and url.is_shortener:
        report.findings.append(Finding(
            "url_shortener_redirect", 0.3,
            "Shortened link hides where it really goes",
            "छोटा लिंक असली वेबसाइट का पता छुपाता है",
            _clip(" → ".join(report.chain)), "via a shortener",
        ))  # fmt: skip
    brand = lookalike_brand(final)
    if brand:
        report.findings.append(Finding(
            "url_lookalike", 0.7,
            f"Link leads to a website imitating '{brand}'",
            f"लिंक '{brand}' की नकली वेबसाइट पर ले जाता है",
            f"{final.host} (imitates '{brand}')", f"imitates '{brand}'",
            duplicate_of_rule=not redirected,
        ))  # fmt: skip
    tld = final.host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        report.findings.append(Finding(
            "url_suspicious_tld", 0.25,
            f"Link leads to a cheap '.{tld}' domain often used by scammers",
            f"लिंक सस्ते '.{tld}' डोमेन पर ले जाता है जो अक्सर ठग इस्तेमाल करते हैं",
            final.host, f"cheap .{tld} domain", duplicate_of_rule=not redirected,
        ))  # fmt: skip

    # 3. Network checks on the final domain, in parallel.
    async def age() -> None:
        if final.is_ip:
            return
        try:
            async with asyncio.timeout(timeout):
                data = await _cached(
                    cache,
                    f"rdap:{final.registered_domain}",
                    lambda: rdap_lookup(client, final.registered_domain),
                )
        except Exception as exc:  # fail soft
            report.unavailable.append(f"domain age (RDAP): {_reason(exc)}")
            return
        if data.get("registered"):
            report.registered = date.fromisoformat(data["registered"])

    async def blocklist() -> list[str]:
        if not settings.SAFE_BROWSING_API_KEY:
            return []  # optional check, skipped silently
        urls = list(dict.fromkeys([url.url, final_url]))
        try:
            async with asyncio.timeout(timeout):
                return await _safe_browsing_cached(
                    client, cache, settings.SAFE_BROWSING_API_KEY, urls
                )
        except Exception as exc:  # fail soft
            report.unavailable.append(f"Safe Browsing: {_reason(exc)}")
            return []

    _, threats = await asyncio.gather(age(), blocklist())

    if report.registered:
        days = (today - report.registered).days
        if days < NEW_DOMAIN_DAYS:
            report.findings.append(Finding(
                "url_new_domain", 0.6,
                f"The website was registered only {days} day(s) ago",
                f"यह वेबसाइट सिर्फ {days} दिन पहले बनी है",
                f"{final.registered_domain} registered {report.registered}",
                f"registered {days} day(s) ago",
            ))  # fmt: skip
        elif days < YOUNG_DOMAIN_DAYS:
            report.findings.append(Finding(
                "url_young_domain", 0.3,
                f"The website is new (registered {days} days ago)",
                f"यह वेबसाइट नई है ({days} दिन पहले बनी)",
                f"{final.registered_domain} registered {report.registered}",
                f"registered {days} days ago",
            ))  # fmt: skip
    if threats:
        report.findings.append(Finding(
            "url_safe_browsing", 1.0,
            "Google Safe Browsing lists this link as dangerous",
            "Google Safe Browsing ने इस लिंक को खतरनाक बताया है",
            f"{final_url}: {', '.join(threats)}", f"Safe Browsing: {', '.join(threats)}",
        ))  # fmt: skip

    codes = {f.code for f in report.findings}
    if (
        codes == {"url_shortener_redirect"}
        and report.registered
        and ((today - report.registered).days >= ESTABLISHED_DOMAIN_DAYS)
    ):
        # The shortener hid the destination, but it turned out to be an established,
        # clean site: the concern is mostly resolved.
        report.findings = [
            replace(f, weight=0.1, label="via a shortener, to an established site")
            for f in report.findings
        ]
    if "url_safe_browsing" in codes:
        report.floor = SAFE_BROWSING_FLOOR
    elif "url_lookalike" in codes and codes & {"url_new_domain", "url_shortener_redirect"}:
        # A brand lookalike that is days old, or hidden behind a shortener.
        report.floor = LOOKALIKE_CONFIRMED_FLOOR
    return report


async def _expand_json(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    return {"chain": await expand(client, url)}


# --------------------------------------------------------------------------- signal


def _describe(r: UrlReport) -> str:
    parts: list[str] = []
    if len(r.chain) > 1:
        parts.append(f"redirects to {r.final_domain} ({len(r.chain) - 1} hop(s))")
    if r.allowlisted:
        parts.append("official domain")
    parts += [f.label for f in r.findings]
    if r.registered and not any(f.code.endswith("_domain") for f in r.findings):
        parts.append(f"registered {r.registered}")
    if r.unavailable:
        parts.append("unavailable: " + ", ".join(r.unavailable))
    host = urlsplit(r.url).hostname or r.final_domain
    return f"{host}: {'; '.join(parts) or 'no issues found'}"


def url_intel_signal(reports: Sequence[UrlReport]) -> SignalOutcome | None:
    """Combine per-URL reports: the riskiest URL decides. Pure."""
    if not reports:
        return None
    detail = " | ".join(_describe(r) for r in reports)
    flagged = [r for r in reports if r.findings]

    if flagged:
        flags: dict[tuple[str, str], RedFlag] = {}
        for r in flagged:
            for f in r.findings:
                if not f.duplicate_of_rule:
                    flags.setdefault((f.code, f.evidence), RedFlag(
                        code=f.code, message=f.en, message_hi=f.hi,
                        severity=severity_for(f.weight), evidence=f.evidence,
                    ))  # fmt: skip
        floors = [r.floor for r in flagged if r.floor is not None]
        return SignalOutcome(
            "url_intel",
            max(r.score for r in flagged),
            detail,
            floor=max(floors, default=None),
            red_flags=tuple(flags.values()),
            scam_type=ScamType.PHISHING_LINK,
        )
    if all(r.allowlisted for r in reports):
        return SignalOutcome("url_intel", 0, detail)  # real evidence of safety
    if any(r.unavailable for r in reports):
        return SignalOutcome("url_intel", None, detail)
    return SignalOutcome("url_intel", 0, f"no issues found: {detail}", informative=False)


async def url_intel(
    urls: Sequence[ExtractedURL],
    *,
    client: httpx.AsyncClient,
    cache: LookupCache,
    settings: Settings,
    today: date | None = None,
) -> SignalOutcome | None:
    reports = await asyncio.gather(
        *(
            check_url(u, client=client, cache=cache, settings=settings, today=today)
            for u in urls[:MAX_URLS]
        )
    )
    return url_intel_signal(reports)
