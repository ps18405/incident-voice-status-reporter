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
AUTH_HEADER_PATTERN = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*)(?:(bearer|basic|token)\s+)?([^\r\n,;]+)"
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b((?:x[-_])?api[-_ ]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|password)"
    r"(\s*[:=]\s*)[\"']?([^\s,;\"']+)"
)
TOKEN_PATTERN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|"
    r"github_pat_[A-Za-z0-9_]{12,}|AIza[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,})\b"
)
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)^(?:authorization|(?:x[-_])?api[-_ ]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|password)$"
)


def redact_text(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Redact sensitive customer data from a string.
    
    Returns the sanitized text and a list of redactions made.
    """
    if not text:
        return "", []

    redactions = []

    def replace_auth(match: re.Match) -> str:
        redactions.append({"type": "AUTH_HEADER", "placeholder": "[REDACTED_TOKEN]"})
        scheme = f"{match.group(2)} " if match.group(2) else ""
        return f"{match.group(1)}{scheme}[REDACTED_TOKEN]"

    sanitized = AUTH_HEADER_PATTERN.sub(replace_auth, text)

    def replace_assignment(match: re.Match) -> str:
        redactions.append({"type": "SECRET", "placeholder": "[REDACTED_TOKEN]"})
        return f"{match.group(1)}{match.group(2)}[REDACTED_TOKEN]"

    sanitized = SECRET_ASSIGNMENT_PATTERN.sub(replace_assignment, sanitized)

    def replace_token(match: re.Match) -> str:
        redactions.append({"type": "TOKEN", "placeholder": "[REDACTED_TOKEN]"})
        return "[REDACTED_TOKEN]"

    sanitized = TOKEN_PATTERN.sub(replace_token, sanitized)

    # 1. Redact credit card numbers
    def replace_card(match: re.Match) -> str:
        val = match.group(0)
        digits_only = re.sub(r"\D", "", val)
        # Check if digits look like a realistic card length (13-19)
        if 13 <= len(digits_only) <= 19:
            redactions.append({"type": "CARD", "placeholder": "[REDACTED_CARD]"})
            return "[REDACTED_CARD]"
        return val

    sanitized = CARD_PATTERN.sub(replace_card, sanitized)

    # 2. Redact emails
    def replace_email(match: re.Match) -> str:
        val = match.group(0)
        redactions.append({"type": "EMAIL", "placeholder": "[REDACTED_EMAIL]"})
        return "[REDACTED_EMAIL]"

    sanitized = EMAIL_PATTERN.sub(replace_email, sanitized)

    # 3. Redact phone numbers
    def replace_phone(match: re.Match) -> str:
        val = match.group(0)
        # Avoid matching strings that are already redacted or pure timestamps/dates like 2026-10-19
        if "[REDACTED" in val or re.match(r"^\d{4}-\d{2}-\d{2}", val):
            return val
        redactions.append({"type": "PHONE", "placeholder": "[REDACTED_PHONE]"})
        return "[REDACTED_PHONE]"

    sanitized = PHONE_PATTERN.sub(replace_phone, sanitized)

    return sanitized, redactions


def redact_data_structure(data: Any) -> Any:
    """Recursively sanitize dicts, lists, and strings."""
    if isinstance(data, str):
        sanitized, _ = redact_text(data)
        return sanitized
    elif isinstance(data, dict):
        return {
            k: "[REDACTED_TOKEN]" if isinstance(k, str) and SENSITIVE_KEY_PATTERN.fullmatch(k)
            else redact_data_structure(v)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_data_structure(item) for item in data]
    return data


def _is_redacted_token(value: str) -> bool:
    residual = value
    for placeholder in ("[REDACTED_TOKEN]", "[REDACTED_EMAIL]", "[REDACTED_PHONE]", "[REDACTED_CARD]"):
        residual = re.sub(re.escape(placeholder), "", residual, flags=re.IGNORECASE)
    return not residual.strip(" \t\r\n\"'.,:;)]}_")


def scan_for_unredacted_pii(text: str) -> List[Dict[str, str]]:
    """Scan text to see if any unredacted PII is present.
    Used by the Verification module.
    """
    findings = []
    if any(
        not _is_redacted_token(match.group(3))
        for match in AUTH_HEADER_PATTERN.finditer(text)
    ):
        findings.append({"type": "UNREDACTED_AUTH_HEADER"})
    if any(
        not _is_redacted_token(match.group(3))
        for match in SECRET_ASSIGNMENT_PATTERN.finditer(text)
    ) or TOKEN_PATTERN.search(text):
        findings.append({"type": "UNREDACTED_TOKEN"})
    # Test for raw emails
    for match in EMAIL_PATTERN.finditer(text):
        findings.append({"type": "UNREDACTED_EMAIL"})

    # Test for raw credit cards (ignoring redacted tokens)
    clean_for_cards = text.replace("[REDACTED_CARD]", "")
    for match in CARD_PATTERN.finditer(clean_for_cards):
        val = match.group(0)
        digits_only = re.sub(r"\D", "", val)
        if 13 <= len(digits_only) <= 19:
            findings.append({"type": "UNREDACTED_CARD"})

    # Test for raw phone numbers
    clean_for_phones = text.replace("[REDACTED_PHONE]", "")
    for match in PHONE_PATTERN.finditer(clean_for_phones):
        val = match.group(0)
        if not re.match(r"^\d{4}-\d{2}-\d{2}", val):
            findings.append({"type": "UNREDACTED_PHONE"})

    return findings
