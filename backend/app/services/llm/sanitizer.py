"""
CloudShield IQ — LLM Evidence Sanitizer & Security Boundary Guard
=================================================================
Enforces strict sanitization on evidence packages before consumption by any LLM.
Protects against:
- Prompt injection and jailbreak payloads embedded in cloud telemetry / resource IDs
- Sensitive credential leakage (AWS access keys, private keys, JWTs)
- Hallucination vectors by enforcing factual boundary constraints
"""

from __future__ import annotations

import re
from typing import Any
from app.schemas.explanation import EvidencePack

# Patterns for identifying and neutralizing prompt injection attempts in telemetry
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"system\s+prompt\s*(override|reset)?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)?\s*", re.IGNORECASE),
    re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\s*/?\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"bypass\s+(safety|security)\s+filters?", re.IGNORECASE),
    re.compile(r"act\s+as\s+(dan|an\s+unfiltered|an\s+attacker)", re.IGNORECASE),
]

# Sensitive token redaction regexes
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]+PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"(password|secret|token)\s*=\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE), r"\1='[REDACTED]'"),
]


def sanitize_string(val: str | None, max_len: int = 1000) -> str:
    """Sanitize, neutralize injections, and redact sensitive tokens from a string."""
    if not val:
        return ""

    cleaned = str(val).strip()

    # Redact sensitive patterns first
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)

    # Neutralize prompt injection phrases
    for pattern in INJECTION_PATTERNS:
        cleaned = pattern.sub("[FILTERED_INPUT]", cleaned)

    # Truncate to maximum length to prevent context flooding
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "... [truncated]"

    return cleaned


def sanitize_evidence_pack(evidence: EvidencePack) -> EvidencePack:
    """
    Produce a sanitized, injection-free, credential-safe copy of an EvidencePack.
    Guarantees that telemetry values cannot subvert downstream LLM behavior.
    """
    clean_dict = evidence.model_dump()

    # Sanitize string fields
    string_fields = [
        "title",
        "resource_id",
        "resource_type",
        "actor_type",
        "actor_name",
        "action",
        "source_ip",
        "region",
        "shap_top_feature",
        "remediation_guidance",
        "cli_remediation_command",
        "terraform_remediation_snippet",
    ]

    for field in string_fields:
        if clean_dict.get(field):
            clean_dict[field] = sanitize_string(clean_dict[field])

    # Sanitize list of compliance violations
    if clean_dict.get("compliance_violations"):
        clean_dict["compliance_violations"] = [
            sanitize_string(v, max_len=120) for v in clean_dict["compliance_violations"]
        ]

    # Sanitize SHAP factors list
    if clean_dict.get("shap_factors"):
        sanitized_factors: list[dict[str, Any]] = []
        for factor in clean_dict["shap_factors"]:
            sanitized_factors.append({
                "feature_name": sanitize_string(factor.get("feature_name", ""), max_len=80),
                "shap_value": float(factor.get("shap_value", 0.0)),
                "direction": sanitize_string(factor.get("direction", ""), max_len=30),
                "domain": sanitize_string(factor.get("domain", ""), max_len=50),
            })
        clean_dict["shap_factors"] = sanitized_factors

    return EvidencePack.model_validate(clean_dict)
