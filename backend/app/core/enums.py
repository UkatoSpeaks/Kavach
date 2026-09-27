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


class ScamType(StrEnum):
    """v1 scam types. GENERIC covers signs (e.g. an OTP request) that fit any type."""

    UPI_RECEIVE_MONEY = "upi_receive_money"
    QR_CODE = "qr_code"
    SENT_BY_MISTAKE = "sent_by_mistake"
    PHISHING_LINK = "phishing_link"
    TASK_JOB = "task_job"
    FAKE_CUSTOMER_CARE = "fake_customer_care"
    GENERIC = "generic"


class PatternKind(StrEnum):
    """Knowledge-base docs: scam patterns, and genuine messages people mistake for scams."""

    SCAM = "scam"
    GENUINE = "genuine"
