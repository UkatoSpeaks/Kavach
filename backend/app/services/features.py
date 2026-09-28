"""Text preprocessing and n-gram analyzers of the scam classifier, shared by training
(ml/train_classifier.py, through ml/features.py) and inference (app/services/classifier.py).

It lives in app/ so that the deployed service always runs the same code the model was
trained with (Render does not rebuild on changes under ml/).

preprocess():
1. extractors.clean_text (invisible characters, NFKC, Devanagari digits);
2. leetspeak folding from normalize.fold ("N0W" -> "now"), never inside links, IDs,
   phone numbers or amounts;
3. entities masked with the extractors' own spans: links become <url> or a riskier kind
   (<url_short>, <url_riskytld>, <url_lookalike>, <url_ip>, <url_apk>, <url_msg>) or
   <url_official>; upi:// links <upi_link>; UPI IDs <upi>; emails <email>; phone numbers
   <phone> (1800 numbers <phone_tollfree>); amounts <amount>; any other number <num>;
4. lower case, whitespace collapsed, no space before punctuation ("blocked ." -> "blocked.").
   The last one is not cosmetic: removing IMC25's anonymization placeholders leaves
   "word ." in a third of its scam rows, a pattern the model would otherwise learn as a
   scam sign.

Changing anything here changes what the model sees: bump FEATURES_VERSION and retrain
(the classifier refuses a model built for another version).
"""

import re

from app.schemas.entities import ExtractedURL
from app.services import normalize
from app.services.extractors import clean_text, entity_spans
from app.services.rules import (
    BRAND_OFFICIAL_DOMAINS,
    MESSAGING_DOMAINS,
    RESTRICTED_SUFFIXES,
    SUSPICIOUS_TLDS,
    lookalike_brand,
)

FEATURES_VERSION = 2

CHAR_NGRAMS = (2, 5)
WORD_NGRAMS = (1, 2)

_OFFICIAL = frozenset().union(*BRAND_OFFICIAL_DOMAINS.values())
_MASK_RE = re.compile(r"<[a-z_]+>")
_NUM_RE = re.compile(r"\d+(?:[.,:/-]\d+)*")
_WS_RE = re.compile(r"\s+")
_SPACE_BEFORE_PUNCT_RE = re.compile(r"\s+([.,:;!?)])")
# Devanagari vowel signs are not \w, so the block is listed explicitly: "किया" stays one word.
_WORD_RE = re.compile(r"<[a-z_]+>|[\wऀ-ॿ]+")


def url_token(url: ExtractedURL) -> str:
    """The riskiest kind that applies, else <url_official> or plain <url>."""
    tld = url.host.rsplit(".", 1)[-1]
    if url.is_ip:
        return "<url_ip>"
    if url.is_apk:
        return "<url_apk>"
    if url.is_shortener:
        return "<url_short>"
    if url.registered_domain in MESSAGING_DOMAINS or url.host in MESSAGING_DOMAINS:
        return "<url_msg>"
    if lookalike_brand(url):
        return "<url_lookalike>"
    if tld in SUSPICIOUS_TLDS:
        return "<url_riskytld>"
    if url.registered_domain in _OFFICIAL or url.registered_domain.endswith(RESTRICTED_SUFFIXES):
        return "<url_official>"
    return "<url>"


def preprocess(text: str) -> str:
    cleaned = clean_text(text)
    spans = entity_spans(cleaned)
    folded = normalize.fold(cleaned, [(s.start, s.end) for s in spans]).texts[0]
    # fold() lines up with `cleaned` character by character, except for the rare text whose
    # lower case is longer; mask the unfolded text then.
    base = folded if len(folded) == len(cleaned) else cleaned
    for s in reversed(spans):
        if s.kind == "url" and s.url is not None:
            token = url_token(s.url)
        elif s.kind == "phone":
            token = "<phone_tollfree>" if cleaned[s.start : s.end].startswith("1800") else "<phone>"
        else:
            token = {"upi_uri": "<upi_link>", "upi": "<upi>", "email": "<email>",
                     "amount": "<amount>"}[s.kind]  # fmt: skip
        base = f"{base[: s.start]} {token} {base[s.end :]}"
    base = _NUM_RE.sub("<num>", base)
    base = _SPACE_BEFORE_PUNCT_RE.sub(r"\1", base)
    return _WS_RE.sub(" ", base.lower()).strip()


def words(pre: str) -> list[str]:
    """The words of preprocessed text (mask tokens included). Punctuation separates words."""
    return _WORD_RE.findall(pre)


def word_ngrams(pre: str) -> list[str]:
    """Word 1-2 grams of preprocessed text."""
    tokens = words(pre)
    lo, hi = WORD_NGRAMS
    out: list[str] = []
    for n in range(lo, hi + 1):
        out += [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]
    return out


def char_ngrams(pre: str) -> list[str]:
    """Character 2-5 grams inside space-padded words (like scikit-learn's "char_wb"), so
    no n-gram spans two words. A mask token is one feature, not cut into pieces."""
    lo, hi = CHAR_NGRAMS
    out: list[str] = []
    for word in pre.split():
        if _MASK_RE.fullmatch(word):
            out.append(word)
            continue
        w = f" {word} "
        for n in range(lo, hi + 1):
            if len(w) <= n:  # a short word counts once, not once per n
                out.append(w)
                break
            out += [w[i : i + n] for i in range(len(w) - n + 1)]
    return out
