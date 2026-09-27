"""Fetch the public SMS datasets into data/datasets/raw/ (gitignored).

- UCI SMS Spam Collection: downloaded from the official UCI archive.
- Mendeley "SMS Phishing Dataset" (Mishra & Soni): Mendeley needs a browser download, so
  this only checks whether the file is in place and prints where to put it if not.

Both are out-of-domain (mostly non-Indian) and are used for evaluation only; see
data/datasets/README.md.

    uv run python -m ml.download_public            # skips files that already exist
    uv run python -m ml.download_public --force    # download again
"""

import argparse
import hashlib
import io
import sys
import zipfile

import httpx

from ml.common import RAW_DIR

UCI_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
UCI_FILE = RAW_DIR / "uci_sms_spam" / "SMSSpamCollection"

MENDELEY_PAGE = "https://data.mendeley.com/datasets/f45bkkt8pr/1"
MENDELEY_DIR = RAW_DIR / "mendeley_sms_phishing"


def find_mendeley_file() -> str | None:
    """The Mendeley CSV if it has been put in place (any *.csv in MENDELEY_DIR)."""
    files = sorted(MENDELEY_DIR.glob("*.csv")) if MENDELEY_DIR.exists() else []
    return str(files[0]) if files else None


def download_uci(force: bool) -> None:
    if UCI_FILE.exists() and not force:
        print(f"UCI SMS Spam Collection: already present ({UCI_FILE})")
        return
    print(f"UCI SMS Spam Collection: downloading {UCI_URL}")
    resp = httpx.get(UCI_URL, timeout=60, follow_redirects=True)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        data = zf.read("SMSSpamCollection")
    UCI_FILE.parent.mkdir(parents=True, exist_ok=True)
    UCI_FILE.write_bytes(data)
    lines = data.decode("utf-8", errors="replace").splitlines()
    sha = hashlib.sha256(data).hexdigest()[:16]
    print(f"  saved {len(lines)} messages to {UCI_FILE} (sha256 {sha}...)")


def check_mendeley() -> None:
    found = find_mendeley_file()
    if found:
        print(f"Mendeley SMS Phishing Dataset: found {found}")
        return
    MENDELEY_DIR.mkdir(parents=True, exist_ok=True)
    print(
        "Mendeley SMS Phishing Dataset: not found, skipping (optional).\n"
        "  To add it:\n"
        f"  1. Open {MENDELEY_PAGE} in a browser.\n"
        "  2. Click 'Download All' and unzip; the data file is a CSV (e.g. Dataset_5971.csv)\n"
        "     with columns LABEL, TEXT, URL, EMAIL, PHONE.\n"
        f"  3. Put the CSV in {MENDELEY_DIR}\n"
        "  4. Re-run: uv run python -m ml.prepare_dataset"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="download again")
    args = parser.parse_args()
    try:
        download_uci(args.force)
    except (httpx.HTTPError, zipfile.BadZipFile, KeyError) as exc:
        print(f"UCI download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"  Download it by hand from {UCI_URL} and put SMSSpamCollection in "
              f"{UCI_FILE.parent}", file=sys.stderr)  # fmt: skip
        sys.exit(1)
    check_mendeley()


if __name__ == "__main__":
    main()
