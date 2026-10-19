"""Safety module for redacting sensitive customer data.
Redacts emails, phone numbers, and payment card numbers before display, speech, or posting.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)

# Standard and formatted card patterns (13 to 19 digits with optional hyphens or spaces)
CARD_PATTERN = re.compile(
    r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b"
)

# Phone number patterns (international and North American formats)
PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)


def redact_text(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Redact sensitive customer data from a string.
    
    Returns the sanitized text and a list of redactions made.
    """
    if not text:
        return "", []

    redactions = []

    # 1. Redact credit card numbers
    def replace_card(match: re.Match) -> str:
        val = match.group(0)
        digits_only = re.sub(r"\D", "", val)
        # Check if digits look like a realistic card length (13-19)
        if 13 <= len(digits_only) <= 19:
            redactions.append({"type": "CARD", "matched": val, "placeholder": "[REDACTED_CARD]"})
            return "[REDACTED_CARD]"
        return val

    sanitized = CARD_PATTERN.sub(replace_card, text)

    # 2. Redact emails
    def replace_email(match: re.Match) -> str:
        val = match.group(0)
        redactions.append({"type": "EMAIL", "matched": val, "placeholder": "[REDACTED_EMAIL]"})
        return "[REDACTED_EMAIL]"

    sanitized = EMAIL_PATTERN.sub(replace_email, sanitized)

    # 3. Redact phone numbers
    def replace_phone(match: re.Match) -> str:
        val = match.group(0)
        # Avoid matching strings that are already redacted or pure timestamps/dates like 2026-10-19
        if "[REDACTED" in val or re.match(r"^\d{4}-\d{2}-\d{2}", val):
            return val
        redactions.append({"type": "PHONE", "matched": val, "placeholder": "[REDACTED_PHONE]"})
        return "[REDACTED_PHONE]"

    sanitized = PHONE_PATTERN.sub(replace_phone, sanitized)

    return sanitized, redactions


def redact_data_structure(data: Any) -> Any:
    """Recursively sanitize dicts, lists, and strings."""
    if isinstance(data, str):
        sanitized, _ = redact_text(data)
        return sanitized
    elif isinstance(data, dict):
        return {k: redact_data_structure(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_data_structure(item) for item in data]
    return data


def scan_for_unredacted_pii(text: str) -> List[Dict[str, str]]:
    """Scan text to see if any unredacted PII is present.
    Used by the Verification module.
    """
    findings = []
    # Test for raw emails
    for match in EMAIL_PATTERN.finditer(text):
        findings.append({"type": "UNREDACTED_EMAIL", "value": match.group(0)})

    # Test for raw credit cards (ignoring redacted tokens)
    clean_for_cards = text.replace("[REDACTED_CARD]", "")
    for match in CARD_PATTERN.finditer(clean_for_cards):
        val = match.group(0)
        digits_only = re.sub(r"\D", "", val)
        if 13 <= len(digits_only) <= 19:
            findings.append({"type": "UNREDACTED_CARD", "value": val})

    # Test for raw phone numbers
    clean_for_phones = text.replace("[REDACTED_PHONE]", "")
    for match in PHONE_PATTERN.finditer(clean_for_phones):
        val = match.group(0)
        if not re.match(r"^\d{4}-\d{2}-\d{2}", val):
            findings.append({"type": "UNREDACTED_PHONE", "value": val})

    return findings
