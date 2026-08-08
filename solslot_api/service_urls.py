"""Validation for authenticated internal service URLs."""

from __future__ import annotations

from urllib.parse import urlsplit


def valid_internal_service_url(value: str) -> bool:
    """Allow TLS services or cleartext traffic that cannot leave loopback."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1"}


def valid_launch_rehearsal_service_url(value: str) -> bool:
    """Keep the rehearsal client away from the Key of Solomon listener."""

    if not valid_internal_service_url(value):
        return False
    parsed = urlsplit(value)
    return parsed.port != 8793


__all__ = ["valid_internal_service_url", "valid_launch_rehearsal_service_url"]
