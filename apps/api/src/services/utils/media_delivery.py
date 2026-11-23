"""Browser delivery policy, independent of the object-storage provider."""
import os
from urllib.parse import urlsplit

PRIVATE_MEDIA_HEADERS = {
    "Cache-Control": "private, no-store",
    "Vary": "Authorization, Cookie",
    "X-Content-Type-Options": "nosniff",
}
DEFAULT_SIGNED_URL_TTL = 300
MAX_SIGNED_URL_TTL = 900


def direct_delivery_allowed(endpoint: str | None) -> bool:
    """Direct delivery is an explicit operator choice, never implied by S3."""
    if os.getenv("LEARNHOUSE_S3_DIRECT_DELIVERY", "false").lower() != "true":
        return False
    # Empty endpoint uses the SDK's public AWS endpoint. Custom endpoints must
    # use TLS; private endpoints are kept behind the API by deployment policy.
    if not endpoint:
        return True
    parts = urlsplit(endpoint)
    return bool(parts.scheme == "https" and parts.hostname
                and not parts.username and not parts.password
                and not parts.query and not parts.fragment)


def signed_url_ttl(requested: int) -> int:
    """Bound the time a capability URL can outlive an authorization change."""
    return min(MAX_SIGNED_URL_TTL, max(1, requested))

def content_headers(mime_type: str) -> dict:
    """Prevent active uploaded documents from executing in the app origin."""
    headers = dict(PRIVATE_MEDIA_HEADERS)
    if mime_type in {"text/html", "application/javascript", "text/css",
                     "application/xml", "text/xml", "image/svg+xml"}:
        headers.update({
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "Content-Disposition": "attachment",
        })
    return headers
