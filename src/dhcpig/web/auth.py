"""Auth + same-origin checks for the local control plane. Stdlib only."""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import parse_qs, urlparse

SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # all assets are local -> forbid remote origins entirely
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'"
    ),
}


def new_token() -> str:
    return secrets.token_urlsafe(24)


def token_from_request(headers, path: str) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip()
    qs = parse_qs(urlparse(path).query)
    vals = qs.get("token")
    return vals[0] if vals else None


def token_ok(expected: str, provided: str | None) -> bool:
    if not provided:
        return False
    return hmac.compare_digest(expected, provided)


def same_origin_ok(headers, host: str) -> bool:
    """Reject cross-origin requests. If Origin is absent (curl, EventSource GET), allow."""
    origin = headers.get("Origin")
    if origin is None:
        return True
    return urlparse(origin).netloc == host
