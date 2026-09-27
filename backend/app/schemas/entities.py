"""Entities pulled out of a message by app.services.extractors.

Stored as-is in analyses.extracted_entities (JSONB) via model_dump(mode="json").
"""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class SensitiveInfo(StrEnum):
    """Credentials a message mentions. Genuine banks never ask for any of these."""

    OTP = "otp"
    PIN = "pin"
    UPI_PIN = "upi_pin"
    MPIN = "mpin"
    CVV = "cvv"
    PASSWORD = "password"
    AADHAAR = "aadhaar"
    PAN = "pan"


class ExtractedURL(BaseModel):
    raw: str = Field(description="As written in the message (trailing punctuation removed).")
    url: str = Field(description="With a scheme (http:// if none); scheme and host lower-cased.")
    host: str
    registered_domain: str = Field(description="e.g. 'sbi.co.in' for 'secure.sbi.co.in'.")
    is_shortener: bool = False
    is_ip: bool = False
    is_apk: bool = False


class ExtractedUPI(BaseModel):
    value: str = Field(description="Lower-cased VPA, e.g. 'rahul99@ybl'.")
    handle: str = Field(description="The part after '@'.")
    confidence: Literal["high", "low"] = Field(
        description="'high' for a known PSP/bank handle, 'low' for an unknown one."
    )


class UPIPaymentURI(BaseModel):
    """A parsed upi://pay?... deep link (as found in UPI QR codes)."""

    raw: str
    pa: str | None = Field(default=None, description="Payee address (VPA).")
    pn: str | None = Field(default=None, description="Payee name, URL-decoded.")
    am: float | None = Field(default=None, description="Amount.")
    tn: str | None = Field(default=None, description="Transaction note.")
    cu: str | None = Field(default=None, description="Currency, normally 'INR'.")
    mc: str | None = Field(default=None, description="Merchant category code.")


class ExtractedPhone(BaseModel):
    raw: str
    number: str = Field(description="'+91XXXXXXXXXX' for mobiles, digits only for toll-free.")
    kind: Literal["mobile", "toll_free"]


class ExtractedAmount(BaseModel):
    raw: str
    value: float
    currency: Literal["INR"] = "INR"


class ExtractedEntities(BaseModel):
    normalized_text: str = Field(
        description="NFKC, lower-cased, invisible characters removed, whitespace collapsed."
    )
    urls: list[ExtractedURL] = Field(default_factory=list)
    upi_ids: list[ExtractedUPI] = Field(default_factory=list)
    upi_uris: list[UPIPaymentURI] = Field(default_factory=list)
    phones: list[ExtractedPhone] = Field(default_factory=list)
    amounts: list[ExtractedAmount] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    sensitive_info: list[SensitiveInfo] = Field(default_factory=list)
    remote_access_apps: list[str] = Field(default_factory=list)
    apk_links: list[str] = Field(default_factory=list, description="URLs pointing at an .apk.")
    apk_files: list[str] = Field(default_factory=list, description="Any *.apk file names seen.")
