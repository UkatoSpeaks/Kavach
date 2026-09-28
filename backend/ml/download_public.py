"""Fetch the public SMS datasets into data/datasets/raw/ (gitignored).

- UCI SMS Spam Collection: downloaded from the official UCI archive.
- India Spam SMS Classification (junioralive): real Indian SMS, downloaded from GitHub.
  Checked against INDIA_SPAM_SHA256: skipped when the file is present and matches.
- Mendeley "SMS Phishing Dataset" (Mishra & Soni): the zip from Mendeley Data's public API.
- Smishing Dataset IMC 2025 (Agarwal et al.): the CSV from GitHub, pinned to a commit.

Every file except UCI is checked against a sha256: a present file that matches is skipped,
and a download that doesn't match stops with an error instead of silently changing the data.
UCI is out-of-domain evaluation only; Mendeley and IMC25 (mostly non-Indian, is_indian=false)
may go into train/val. See data/datasets/README.md.

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

INDIA_SPAM_URL = (
    "https://raw.githubusercontent.com/junioralive/india-spam-sms-classification/"
    "main/dataset/spam_ham_india.csv"
)
INDIA_SPAM_FILE = RAW_DIR / "india_spam_sms" / "spam_ham_india.csv"
# sha256 of the file as downloaded. If upstream changes it, the download stops with an
# error instead of silently changing the data; check the new file, then update this.
INDIA_SPAM_SHA256 = "e6a28126d1c4ec9d805a10cd89f2de2bb63650532102e9f35ab05c909c3a79f3"

MENDELEY_PAGE = "https://data.mendeley.com/datasets/f45bkkt8pr/1"
# Listed by https://data.mendeley.com/public-api/datasets/f45bkkt8pr/files?folder_id=root&version=1
MENDELEY_ZIP_URL = (
    "https://data.mendeley.com/public-files/datasets/f45bkkt8pr/files/"
    "edb361de-918d-469f-9106-e84823830665/file_downloaded"
)
MENDELEY_ZIP_SHA256 = "9bbf3188fdad81495d8e82825648b9b63b53fc86841a3d26c02629990b233cc3"
MENDELEY_CSV = "Dataset_5971.csv"
MENDELEY_DIR = RAW_DIR / "mendeley_sms_phishing"

# Pinned to the commit of 2025-09-12 on branch main, so the file can't change under us.
IMC25_COMMIT = "a6175560b57387199871e51fbef6bc523d2516b4"
IMC25_URL = (
    "https://raw.githubusercontent.com/reportsmishing/Smishing-Dataset-IMC25/"
    f"{IMC25_COMMIT}/dataset/final_dataset_output.csv"
)
IMC25_SHA256 = "1bbd1e9e82c3ea023112207b80da268a5c4a07d2353c2b0898360ab037fa9a64"
IMC25_FILE = RAW_DIR / "imc25_smishing" / "final_dataset_output.csv"


def find_mendeley_file() -> str | None:
    """The Mendeley CSV if it is in place (any *.csv in MENDELEY_DIR)."""
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


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_india_spam(force: bool) -> None:
    name = "India Spam SMS Classification"
    if INDIA_SPAM_FILE.exists() and not force:
        if sha256_of(INDIA_SPAM_FILE.read_bytes()) == INDIA_SPAM_SHA256:
            print(f"{name}: already present, checksum OK ({INDIA_SPAM_FILE})")
            return
        print(f"{name}: present but the checksum differs; downloading again")
    print(f"{name}: downloading {INDIA_SPAM_URL}")
    resp = httpx.get(INDIA_SPAM_URL, timeout=60, follow_redirects=True)
    resp.raise_for_status()
    sha = sha256_of(resp.content)
    if sha != INDIA_SPAM_SHA256:
        raise ValueError(
            f"checksum mismatch: got {sha}, expected {INDIA_SPAM_SHA256}. The upstream file "
            "changed; review it, then update INDIA_SPAM_SHA256 in ml/download_public.py"
        )
    INDIA_SPAM_FILE.parent.mkdir(parents=True, exist_ok=True)
    INDIA_SPAM_FILE.write_bytes(resp.content)
    print(f"  saved {len(resp.content):,} bytes to {INDIA_SPAM_FILE} (sha256 {sha[:16]}...)")


def _fetch_checked(name: str, url: str, expected_sha256: str) -> bytes:
    print(f"{name}: downloading {url}")
    resp = httpx.get(url, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    sha = sha256_of(resp.content)
    if sha != expected_sha256:
        raise ValueError(
            f"checksum mismatch: got {sha}, expected {expected_sha256}. The upstream file "
            "changed; review it, then update the checksum in ml/download_public.py"
        )
    return resp.content


def download_mendeley(force: bool) -> None:
    name = "Mendeley SMS Phishing Dataset"
    csv_file = MENDELEY_DIR / MENDELEY_CSV
    if csv_file.exists() and not force:
        print(f"{name}: already present ({csv_file})")
        return
    data = _fetch_checked(name, MENDELEY_ZIP_URL, MENDELEY_ZIP_SHA256)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        content = zf.read(MENDELEY_CSV)
    MENDELEY_DIR.mkdir(parents=True, exist_ok=True)
    csv_file.write_bytes(content)
    print(f"  saved {len(content):,} bytes to {csv_file} (zip sha256 checked)")


def download_imc25(force: bool) -> None:
    name = "Smishing Dataset IMC 2025"
    if IMC25_FILE.exists() and not force:
        if sha256_of(IMC25_FILE.read_bytes()) == IMC25_SHA256:
            print(f"{name}: already present, checksum OK ({IMC25_FILE})")
            return
        print(f"{name}: present but the checksum differs; downloading again")
    data = _fetch_checked(name, IMC25_URL, IMC25_SHA256)
    IMC25_FILE.parent.mkdir(parents=True, exist_ok=True)
    IMC25_FILE.write_bytes(data)
    print(f"  saved {len(data):,} bytes to {IMC25_FILE}")


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
    try:
        download_india_spam(args.force)
    except (httpx.HTTPError, ValueError) as exc:
        print(f"India Spam SMS download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"  Source: https://github.com/junioralive/india-spam-sms-classification; put "
              f"spam_ham_india.csv in {INDIA_SPAM_FILE.parent}", file=sys.stderr)  # fmt: skip
        sys.exit(1)
    for name, download, page in (
        ("Mendeley", download_mendeley, MENDELEY_PAGE),
        ("IMC25", download_imc25, "https://github.com/reportsmishing/Smishing-Dataset-IMC25"),
    ):
        try:
            download(args.force)
        except (httpx.HTTPError, ValueError, zipfile.BadZipFile, KeyError) as exc:
            print(f"{name} download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            print(f"  Source: {page}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
