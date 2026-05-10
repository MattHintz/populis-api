from __future__ import annotations

from typing import Any

from .config import Settings


DEV_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$"


def cors_middleware_options(settings: Settings) -> dict[str, Any]:
    return {
        "allow_origins": settings.allowed_origins(),
        "allow_origin_regex": DEV_ORIGIN_REGEX,
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["*"],
    }
