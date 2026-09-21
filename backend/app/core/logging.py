"""
CloudShield IQ — Structured Logging
====================================
Security events, authentication events, and assessment history
are always logged. Sensitive fields are explicitly redacted.

Uses structlog for structured, machine-parseable JSON output
in production and human-readable console output in development.
"""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

from app.core.config import get_settings

# Fields that must never appear in logs
_REDACTED_FIELDS = frozenset(
    {
        "password",
        "password_hash",
        "secret_key",
        "jwt_secret",
        "api_key",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "aws_secret_access_key",
        "azure_client_secret",
        "gcp_credentials",
        "credit_card",
        "ssn",
    }
)


def _redact_sensitive(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """
    Processor that redacts known-sensitive fields from log events.

    This runs on every log call. It must never raise — if it fails,
    it returns the event dict as-is rather than crashing the app.
    """
    try:
        for key in list(event_dict.keys()):
            if key.lower() in _REDACTED_FIELDS:
                event_dict[key] = "[REDACTED]"
    except Exception:  # noqa: BLE001
        pass
    return event_dict


def _add_app_context(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Add application-level context to every log event."""
    settings = get_settings()
    event_dict.setdefault("app", settings.APP_NAME)
    event_dict.setdefault("env", settings.APP_ENV)
    return event_dict


def configure_logging() -> None:
    """
    Configure structlog for the application.

    Call once at application startup (in main.py lifespan).
    Development: colored console output.
    Production: JSON output suitable for log aggregation.
    """
    settings = get_settings()

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        _add_app_context,
        _redact_sensitive,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if settings.LOG_FORMAT == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.LOG_LEVEL)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging so third-party libraries
    # (SQLAlchemy, uvicorn, etc.) go through the same pipeline
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.LOG_LEVEL),
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a bound logger for the given module name."""
    return structlog.get_logger(name)
