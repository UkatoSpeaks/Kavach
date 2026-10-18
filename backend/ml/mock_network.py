"""A fake internet for ml/evaluate.py --mock-network: url_intel runs its real code (link
expansion, RDAP domain age, lookalike checks) against answers from a JSON fixture instead
of the network, so a run is offline, reproducible, and can mimic scam infrastructure that
does not exist (yet).

Fixture (see data/datasets/polished_eval_network.json):

    {"domains": {"new-scam.in": {"age_days": 3},           # registered 3 days before the run
                 "brand.com": {"registered": "1997-04-10"}, # a fixed date
                 "brand.io": {"rdap": false}},              # no RDAP record (404)
     "redirects": {"bit.ly/abc": "https://new-scam.in/x",   # host/path, no scheme
                   "bit.ly/gone": 404}}                     # the shortener's own status

Every hostname resolves to a public address. Reputation has no reports and Safe Browsing
is off (the caller clears SAFE_BROWSING_API_KEY): fresh scam infrastructure is usually on
neither list yet. Domains and links the fixture does not know are collected in `unknown`,
so a run can report what it had to guess (RDAP 404, a link that does not redirect).
"""

import json
import socket
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.enums import EntityType
from app.services import url_intel
from app.services.extractors import URL_SHORTENERS, registered_domain
from app.services.reputation import ReportedEntity

PUBLIC_IP = "93.184.215.14"
RDAP_HOST = urlsplit(url_intel.RDAP_URL).hostname


@dataclass
class MockNetwork:
    domains: dict[str, dict[str, Any]]
    redirects: dict[str, str | int]
    unknown: set[str] = field(default_factory=set)
    requests: int = 0

    @classmethod
    def load(cls, path: Path) -> "MockNetwork":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data.get("domains", {}), data.get("redirects", {}))

    def _rdap(self, domain: str) -> httpx.Response:
        entry = self.domains.get(domain)
        if entry is None:
            self.unknown.add(f"rdap:{domain}")
            return httpx.Response(404)
        if "age_days" in entry:
            registered = datetime.now(UTC).date() - timedelta(days=int(entry["age_days"]))
        elif entry.get("registered"):
            registered = datetime.fromisoformat(entry["registered"]).date()
        else:
            return httpx.Response(404)  # no RDAP service / no record
        event = {"eventAction": "registration", "eventDate": f"{registered.isoformat()}T00:00:00Z"}
        return httpx.Response(200, json={"events": [event]})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        url = request.url
        if url.host == RDAP_HOST and url.path.startswith("/domain/"):
            return self._rdap(url.path.removeprefix("/domain/").lower())
        key = f"{url.host}{url.path}".rstrip("/")
        answer = self.redirects.get(key)
        if answer is None:
            if registered_domain(url.host) in URL_SHORTENERS:
                self.unknown.add(f"link:{key}")
            return httpx.Response(200)
        if isinstance(answer, int):
            return httpx.Response(answer)
        return httpx.Response(301, headers={"Location": answer})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))


async def _public_getaddrinfo(host: str) -> list[tuple[Any, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 0))]


@contextmanager
def fake_dns() -> Iterator[None]:
    """Every hostname resolves to a public address (url_intel refuses private ones)."""
    real = url_intel._getaddrinfo
    url_intel._getaddrinfo = _public_getaddrinfo
    try:
        yield
    finally:
        url_intel._getaddrinfo = real


async def no_reports(keys: Sequence[tuple[EntityType, str]]) -> Sequence[ReportedEntity]:
    return []
