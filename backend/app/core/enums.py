"""Enumerations shared by the DB models and the API schemas."""

from enum import StrEnum


class InputType(StrEnum):
    TEXT = "text"
    UPI = "upi"
    URL = "url"
    QR = "qr"
    SCREENSHOT = "screenshot"


class Verdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    SCAM = "scam"


class EntityType(StrEnum):
    UPI = "upi"
    PHONE = "phone"
    URL = "url"
    DOMAIN = "domain"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
