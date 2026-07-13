from __future__ import annotations

from typing import Any

from .config import Settings


DEV_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$"


def cors_middleware_options(settings: Settings) -> dict[str, Any]:
    dev_origin_regex = (
        DEV_ORIGIN_REGEX
        if settings.runtime_environment in {"development", "test"}
        else None
    )
    return {
        "allow_origins": settings.allowed_origins(),
        "allow_origin_regex": dev_origin_regex,
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": [
            "Accept",
            "Authorization",
            "Content-Type",
            "Origin",
            "X-Requested-With",
        ],
    }
