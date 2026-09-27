"""Extract URLs, UPI IDs, phones, amounts and credential requests from message text.

Pure functions: no I/O, no network. Handles English, Hindi (Devanagari) and Hinglish.
Every public function accepts raw text and cleans it itself (cleaning is idempotent).
"""

import re
import unicodedata
from collections.abc import Callable, Hashable
from typing import TypeVar
from urllib.parse import parse_qs, urlsplit

from app.schemas.entities import (
    ExtractedAmount,
    ExtractedEntities,
    ExtractedPhone,
    ExtractedUPI,
    ExtractedURL,
    SensitiveInfo,
    UPIPaymentURI,
)

# --------------------------------------------------------------------------- constants

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "bitly.ws", "bit.do", "tinyurl.com", "tiny.cc", "tiny.one", "cutt.ly",
        "cutt.us", "is.gd", "v.gd", "x.gd", "soo.gd", "rb.gy", "t.ly", "shorturl.at",
        "short.gy", "goo.gl", "ow.ly", "buff.ly", "t.co", "rebrand.ly", "bl.ink", "s.id",
        "shorte.st", "adf.ly", "ouo.io", "surl.li", "t2m.io", "u.to", "clck.ru", "qr.ae",
        "lnkd.in", "wa.link", "urlz.fr", "shrtco.de", "gg.gg", "dub.sh", "kutt.it",
        "shrinke.me",
    }
)  # fmt: skip

# Payment-app and bank VPA handles (the part after '@' in a UPI ID).
KNOWN_UPI_HANDLES = frozenset(
    {
        # PhonePe, Google Pay, Paytm, Amazon Pay, WhatsApp Pay, BHIM
        "ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici", "okbizaxis",
        "paytm", "pthdfc", "ptsbi", "ptyes", "ptaxis", "apl", "yapl", "rapl",
        "waicici", "wahdfcbank", "waaxis", "wasbi", "upi",
        # other apps
        "ikwik", "mbk", "freecharge", "axisb", "abfspay", "jupiteraxis", "fam", "slc",
        "sliceaxis", "naviaxis", "superyes", "timecosmos", "tapicici", "pingpay", "pockets",
        "airtel", "jio", "jiopay", "postbank", "ippb", "yesg", "kaypay", "ezeepay",
        # banks
        "sbi", "icici", "hdfcbank", "hdfc", "axisbank", "axis", "kotak", "kbl", "fbl",
        "federal", "idfcbank", "idfcfirst", "idfc", "yesbank", "yesbankltd", "barodampay",
        "boi", "pnb", "pnbpay", "unionbank", "unionbankofindia", "uboi", "cnrb", "canarabank",
        "cbin", "centralbank", "indianbank", "indbank", "iob", "kvb", "rbl", "sib", "dbs",
        "hsbc", "citi", "citigold", "sc", "aubank", "bandhan", "equitas", "idbi", "dlb",
        "dcb", "csbpay", "jkb", "karb", "uco", "ubi", "psb", "tjsb", "mahb", "indus",
        "cmsidfc", "purz",
    }
)  # fmt: skip

# Two-label public suffixes, so the registered domain of a.b.sbi.co.in is sbi.co.in.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.in", "gov.in", "org.in", "net.in", "bank.in", "fin.in", "ac.in", "edu.in",
        "res.in", "nic.in", "firm.in", "gen.in", "ind.in", "mil.in", "co.uk", "org.uk",
        "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au", "co.nz", "co.za", "co.jp", "com.sg", "com.my",
        "com.cn", "com.br", "com.pk", "com.bd", "com.np",
    }
)  # fmt: skip

# A bare "word.tld" (no http://, no www.) is only treated as a URL for these TLDs, so
# "Mr.Sharma" or "invoice.pdf" are not. Includes cheap TLDs popular with phishers.
BARE_DOMAIN_TLDS = frozenset(
    {
        "com", "in", "org", "net", "info", "biz", "co", "io", "me", "app", "ai", "tv",
        "gov", "edu", "mobi", "asia", "xyz", "top", "online", "site", "club", "live", "life",
        "shop", "store", "tech", "website", "space", "fun", "icu", "buzz", "cyou", "vip",
        "pw", "tk", "ml", "ga", "cf", "gq", "link", "click", "work", "support", "services",
        "help", "world", "today", "news", "digital", "cloud", "loan", "win", "bid", "money",
        "bank", "pro", "sbs", "cfd", "bond", "lol", "rest", "quest", "page", "one",
        # ccTLDs used by shorteners
        "ly", "gl", "gd", "at", "cc", "us", "uk", "cn", "ru", "id", "li", "fr", "de", "su",
        "ws", "sh", "gg", "do", "st", "ink",
    }
)  # fmt: skip

_DEVA = "ऀ-ॿ"


def _nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


def _deva(word: str) -> str:
    """Regex for a whole Devanagari word, in the same NFKC form as cleaned text."""
    return rf"(?<![{_DEVA}]){_nfkc(word)}(?![{_DEVA}])"


# Remote-access apps used in "screen share to get your refund" scams. Spaced spellings
# that are also ordinary English ("any desk", "quick support") need a following "app".
REMOTE_ACCESS_APPS: dict[str, str] = {
    "AnyDesk": rf"\bany-?desk\b|\bany\s+desk\s+app\b|{_deva('एनीडेस्क')}|{_deva('एनी डेस्क')}",
    "TeamViewer": rf"\bteam\s?viewer\b(?!\s?qs\b)|{_deva('टीमव्यूअर')}",
    "QuickSupport": r"\bquick-?support\b|\bteam\s?viewer\s?qs\b|\bquick\s+support\s+app\b",
    "RustDesk": r"\brust\s?desk\b",
    "AirDroid": r"\bair\s?droid\b",
    "UltraViewer": r"\bultra\s?viewer\b",
    "Splashtop": r"\bsplashtop\b",
}

# --------------------------------------------------------------------------- cleaning

# Zero-width / invisible / bidi-control characters scammers insert to dodge filters.
_INVISIBLE_RE = re.compile("[­͏؜ᅟᅠ᠎​-‏‪-‮⁠-⁤⁦-⁩ㅤ﻿ﾠ]")
_DEVANAGARI_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")
_WS_RE = re.compile(r"\s+")


def clean_text(text: str) -> str:
    """Remove invisible characters, NFKC-normalize, ASCII-fy Devanagari digits, collapse
    whitespace. Case is preserved (URL paths are case-sensitive).

    NFKC also folds look-alikes such as fullwidth "ＯＴＰ" or bold "𝟗𝟖𝟕" into ASCII.
    """
    text = _INVISIBLE_RE.sub("", text)
    text = _nfkc(text).translate(_DEVANAGARI_DIGITS)
    return _WS_RE.sub(" ", text).strip()


def normalize_text(text: str) -> str:
    return clean_text(text).lower()


T = TypeVar("T")


def _dedupe(items: list[T], key: Callable[[T], Hashable]) -> list[T]:
    """Drop repeats (by key), keeping first-seen order."""
    seen: set[Hashable] = set()
    out: list[T] = []
    for item in items:
        k = key(item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


# --------------------------------------------------------------------------- URLs

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = rf"(?:{_LABEL}\.)+(?:[a-z]{{2,24}}|xn--[a-z0-9-]{{1,59}})(?![a-z0-9@-])"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = rf"{_OCTET}(?:\.{_OCTET}){{3}}(?!\d)"
_IPV4_RE = re.compile(_IPV4)

_URL_RE = re.compile(
    rf"""
    (?<![\w@.\-/])                                  # not inside an email or another URL
    (?:
        (?P<scheme>https?://)(?P<host>{_HOST}|{_IPV4})
      | (?P<bare>{_HOST})
    )
    (?::\d{{2,5}})?                                 # port
    (?:[/?#][^\s<>"'`{_DEVA}]*)?                    # path / query / fragment
    """,
    re.IGNORECASE | re.VERBOSE,
)
_TRAILING_PUNCT = ".,;:!?*"
_BRACKETS = {")": "(", "]": "[", "}": "{"}


def _strip_trailing_punct(url: str) -> str:
    while url:
        ch = url[-1]
        if ch in _TRAILING_PUNCT or (ch in _BRACKETS and url.count(ch) > url.count(_BRACKETS[ch])):
            url = url[:-1]
        else:
            break
    return url


def registered_domain(host: str) -> str:
    """'secure.sbi.co.in' -> 'sbi.co.in', 'www.xyz.top' -> 'xyz.top'. IPs pass through."""
    host = host.lower().rstrip(".")
    if _IPV4_RE.fullmatch(host):
        return host
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 2
    return ".".join(labels[-n:])


def extract_urls(text: str) -> list[ExtractedURL]:
    text = clean_text(text)
    urls: list[ExtractedURL] = []
    for m in _URL_RE.finditer(text):
        scheme = m.group("scheme")
        host = (m.group("host") or m.group("bare")).lower()
        if not scheme and not host.startswith("www."):
            if host.rsplit(".", 1)[-1] not in BARE_DOMAIN_TLDS:
                continue
        raw = _strip_trailing_punct(m.group(0))
        rest = raw[len(scheme or "") + len(host) :]  # port + path, original case kept
        url = f"{(scheme or 'http://').lower()}{host}{rest}"
        domain = registered_domain(host)
        urls.append(
            ExtractedURL(
                raw=raw,
                url=url,
                host=host,
                registered_domain=domain,
                is_shortener=domain in URL_SHORTENERS or host in URL_SHORTENERS,
                is_ip=bool(_IPV4_RE.fullmatch(host)),
                is_apk=urlsplit(url).path.lower().endswith(".apk"),
            )
        )
    return _dedupe(urls, key=lambda u: u.url)


# --------------------------------------------------------------------------- UPI

_AT_ADDRESS_RE = re.compile(
    r"(?<![\w.@+-])(?P<local>[a-z0-9][a-z0-9._+-]{0,63})"
    r"@(?P<handle>[a-z][a-z0-9-]+(?:\.[a-z0-9-]+)*)(?![\w@-])",
    re.IGNORECASE,
)


def _at_addresses(text: str) -> tuple[list[ExtractedUPI], list[str]]:
    """Split name@handle tokens into UPI IDs (no dot in handle) and emails (dot in it)."""
    upis: list[ExtractedUPI] = []
    emails: list[str] = []
    for m in _AT_ADDRESS_RE.finditer(clean_text(text)):
        handle = m.group("handle").lower()
        value = f"{m.group('local').lower()}@{handle}"
        if "." in handle:
            emails.append(value)
        else:
            confidence = "high" if handle in KNOWN_UPI_HANDLES else "low"
            upis.append(ExtractedUPI(value=value, handle=handle, confidence=confidence))
    return _dedupe(upis, key=lambda u: u.value), _dedupe(emails, key=lambda e: e)


def extract_upi_ids(text: str) -> list[ExtractedUPI]:
    return _at_addresses(text)[0]


def extract_emails(text: str) -> list[str]:
    return _at_addresses(text)[1]


_UPI_URI_RE = re.compile(r"upi://[^\s<>\"'`]+", re.IGNORECASE)


def _to_float(value: str | None) -> float | None:
    try:
        return float(value.replace(",", "")) if value else None
    except ValueError:
        return None


def parse_upi_uri(uri: str) -> UPIPaymentURI | None:
    """Parse 'upi://pay?pa=x@ybl&pn=Name&am=10&...'. Returns None if not a upi:// URI."""
    uri = _strip_trailing_punct(uri.strip())
    parts = urlsplit(uri)
    if parts.scheme.lower() != "upi":
        return None
    params = {k.lower(): v[0].strip() for k, v in parse_qs(parts.query).items() if v}
    pa = params.get("pa")
    return UPIPaymentURI(
        raw=uri,
        pa=pa.lower() if pa else None,
        pn=params.get("pn"),
        am=_to_float(params.get("am")),
        tn=params.get("tn"),
        cu=params.get("cu"),
        mc=params.get("mc"),
    )


def extract_upi_uris(text: str) -> list[UPIPaymentURI]:
    parsed = [parse_upi_uri(m.group(0)) for m in _UPI_URI_RE.finditer(clean_text(text))]
    return _dedupe([p for p in parsed if p], key=lambda p: p.raw)


def _mask_links(text: str) -> str:
    """Blank out URLs and upi:// URIs so numbers inside them ('%20Rupee', '?id=98765...')
    aren't read as amounts or phones. Links are already captured by their own extractors."""
    return _URL_RE.sub(" ", _UPI_URI_RE.sub(" ", text))


# --------------------------------------------------------------------------- phones

_MOBILE_RE = re.compile(
    r"""
    (?<![\w/.=@])
    (?:(?:\+91|0091|91)[\s-]?|0)?
    (?P<num>
        [6-9]\d{9}                        # 9876543210
      | [6-9]\d{4}[\s-]\d{5}              # 98765 43210
      | [6-9]\d{2}[\s-]\d{3}[\s-]\d{4}    # 987-654-3210
      | [6-9]\d{3}[\s-]\d{3}[\s-]\d{3}    # 9876 543 210
    )
    (?![\w@]|\.\d)
    """,
    re.VERBOSE,
)
_TOLL_FREE_RE = re.compile(r"(?<![\w/.=@])1800(?:[\s-]?\d){4,7}(?![\w@]|\.\d)")

# A 10-digit number right after these words is an ID or an amount, not a phone.
_NOT_A_PHONE_BEFORE_RE = re.compile(
    r"""(?:
        (?:\b(?:order|txn|transaction|ref|reference|utr|rrn|a/c|acct|account|awb|tracking
            |invoice|pnr|booking|consignment|otp|code|id))
        (?:\s*(?:no|num|number|id))?\.?(?:\s+is)?\s*[:#-]?\s*
      | (?:₹|\brs\.?|\binr)\s*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def _preceded_by_id_or_currency(text: str, start: int) -> bool:
    return bool(_NOT_A_PHONE_BEFORE_RE.search(text[max(0, start - 30) : start]))


def extract_phones(text: str) -> list[ExtractedPhone]:
    text = _mask_links(clean_text(text))
    found: list[tuple[int, ExtractedPhone]] = []
    for m in _MOBILE_RE.finditer(text):
        if _preceded_by_id_or_currency(text, m.start()):
            continue
        digits = re.sub(r"\D", "", m.group("num"))
        found.append(
            (m.start(), ExtractedPhone(raw=m.group(0), number=f"+91{digits}", kind="mobile"))
        )
    for m in _TOLL_FREE_RE.finditer(text):
        if _preceded_by_id_or_currency(text, m.start()):
            continue
        digits = re.sub(r"\D", "", m.group(0))
        found.append((m.start(), ExtractedPhone(raw=m.group(0), number=digits, kind="toll_free")))
    found.sort(key=lambda pair: pair[0])
    return _dedupe([p for _, p in found], key=lambda p: p.number)


# --------------------------------------------------------------------------- amounts

_MULTIPLIERS = {
    _nfkc(word): factor
    for words, factor in (
        (("k", "thousand", "hazar", "hazaar", "हज़ार", "हजार"), 1e3),
        (("lakh", "lakhs", "lac", "lacs", "l", "लाख"), 1e5),
        (("crore", "crores", "cr", "करोड़", "करोड"), 1e7),
    )
    for word in words
}
# Without a currency marker only these multipliers make a bare number money ("50k",
# "2 lakh"). "5l" could be litres and "5 thousand" anything.
_STANDALONE_MULTIPLIERS = {_nfkc(w) for w in ("k", "lakh", "lakhs", "lac", "lacs", "लाख")} | {
    _nfkc(w) for w in ("crore", "crores", "cr", "करोड़", "करोड")
}

_AMOUNT_RE = re.compile(
    _nfkc(
        rf"""
        (?:
            (?<![a-z])(?P<pre>₹|rs\.?|inr|rupees?|रु\.?|रू\.?)\s*
          | (?<![\w.,])
        )
        (?P<num>\d{{1,3}}(?:,\d{{2,3}})+(?:\.\d+)?|\d+(?:\.\d+)?)
        (?:
            (?:\s?(?P<mult>lakhs?|lacs?|crores?|cr|k|thousand|hazaa?r|हज़ार|हजार|लाख|करोड़|करोड)
              | (?P<mult_l>l))
            (?![a-z{_DEVA}])                      # "5 km" is not 5k
        )?
        (?:\s*(?P<post>rupees?|rupaye|rupaiye|rupaiya|rupiya|rupya|rupay|rs\b\.?|/-
                        |रुपये|रुपए|रुपया|रु\.?)
            (?![a-z{_DEVA}])
            (?!\.?\s*\d)                          # not the "Rs" of the next amount
        )?
        """
    ),
    re.IGNORECASE | re.VERBOSE,
)


def extract_amounts(text: str) -> list[ExtractedAmount]:
    text = _mask_links(clean_text(text))
    amounts: list[ExtractedAmount] = []
    for m in _AMOUNT_RE.finditer(text):
        mult = (m.group("mult") or m.group("mult_l") or "").lower()
        has_currency = bool(m.group("pre") or m.group("post"))
        if not has_currency and mult not in _STANDALONE_MULTIPLIERS:
            continue
        value = _to_float(m.group("num"))
        if value is None:
            continue
        value *= _MULTIPLIERS.get(mult, 1)
        amounts.append(ExtractedAmount(raw=m.group(0).strip(), value=value))
    return _dedupe(amounts, key=lambda a: a.value)


# --------------------------------------------------------------------------- credentials

_SENSITIVE_PATTERNS: dict[SensitiveInfo, re.Pattern[str]] = {
    info: re.compile(pattern, re.IGNORECASE)
    for info, pattern in {
        SensitiveInfo.OTP: (
            r"\botps?\b|\bo\.\s?t\.\s?p\b|\bo t p\b|\bone[\s-]?time[\s-]?pass(?:word|code)"
            rf"|\bverification code\b|{_deva('ओटीपी')}|{_deva('ओ.टी.पी')}"
            rf"|{_deva('वन टाइम पासवर्ड')}"
        ),
        SensitiveInfo.UPI_PIN: rf"\bupi[\s-]?pin\b|{_deva('यूपीआई पिन')}|\bupi पिन",
        SensitiveInfo.MPIN: rf"\bm[\s-]?pin\b|{_deva('एमपिन')}|{_deva('एम पिन')}",
        SensitiveInfo.PIN: (
            r"(?<!\bupi )(?<!\bupi-)(?<!\bm )(?<!\bm-)\bpin\b(?![\s-]?code)"
            rf"|(?<!यूपीआई )(?<!upi )(?<!एम ){_deva('पिन')}"
        ),
        SensitiveInfo.CVV: rf"\bcvv2?\b|\bcvc2?\b|\bcard verification|{_deva('सीवीवी')}",
        SensitiveInfo.PASSWORD: (
            r"(?<!time )(?<!time-)\bpass\s?words?\b|\bpasscode\b|\bpwd\b"
            rf"|(?<!टाइम ){_deva('पासवर्ड')}"
        ),
        SensitiveInfo.AADHAAR: rf"\ba{{1,2}}dh?a{{1,2}}r\b|\buidai\b|{_deva('आधार')}",
        SensitiveInfo.PAN: (
            r"\bpan\s?(?:card|number|no\b|num|details?|kyc)"
            rf"|{_deva('पैन')}"
        ),
    }.items()
}
_PAN_UPPERCASE_RE = re.compile(r"\bPAN\b")  # "PAN" in caps is the card, "pan" may be a pan


def detect_sensitive_info(text: str) -> list[SensitiveInfo]:
    """Which credentials the text mentions, in SensitiveInfo declaration order."""
    cleaned = clean_text(text)
    lowered = cleaned.lower()
    found = {info for info, pattern in _SENSITIVE_PATTERNS.items() if pattern.search(lowered)}
    if _PAN_UPPERCASE_RE.search(cleaned):
        found.add(SensitiveInfo.PAN)
    return [info for info in SensitiveInfo if info in found]


# --------------------------------------------------------------------------- apps / APKs

_REMOTE_APP_RES = {name: re.compile(p, re.IGNORECASE) for name, p in REMOTE_ACCESS_APPS.items()}
_APK_FILE_RE = re.compile(r"(?<![\w.-])\w[\w.-]*\.apk(?!\w)", re.IGNORECASE)


def detect_remote_access_apps(text: str) -> list[str]:
    lowered = normalize_text(text)
    return [name for name, pattern in _REMOTE_APP_RES.items() if pattern.search(lowered)]


def extract_apk_files(text: str) -> list[str]:
    names = [m.group(0) for m in _APK_FILE_RE.finditer(clean_text(text))]
    return _dedupe(names, key=str.lower)


# --------------------------------------------------------------------------- all together


def extract_entities(text: str) -> ExtractedEntities:
    cleaned = clean_text(text)
    urls = extract_urls(cleaned)
    upi_ids, emails = _at_addresses(cleaned)
    upi_uris = extract_upi_uris(cleaned)

    # A payee address that only appears inside a (percent-encoded) upi:// URI.
    known = {u.value for u in upi_ids}
    for uri in upi_uris:
        if uri.pa and "@" in uri.pa and uri.pa not in known:
            handle = uri.pa.split("@", 1)[1]
            if "." not in handle:
                confidence = "high" if handle in KNOWN_UPI_HANDLES else "low"
                upi_ids.append(ExtractedUPI(value=uri.pa, handle=handle, confidence=confidence))
                known.add(uri.pa)

    return ExtractedEntities(
        normalized_text=cleaned.lower(),
        urls=urls,
        upi_ids=upi_ids,
        upi_uris=upi_uris,
        phones=extract_phones(cleaned),
        amounts=extract_amounts(cleaned),
        emails=emails,
        sensitive_info=detect_sensitive_info(cleaned),
        remote_access_apps=detect_remote_access_apps(cleaned),
        apk_links=[u.url for u in urls if u.is_apk],
        apk_files=extract_apk_files(cleaned),
    )
