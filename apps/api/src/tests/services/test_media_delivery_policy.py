"""Private endpoints never become browser redirects without explicit policy."""
import pytest
from src.services.utils.media_delivery import (
    PRIVATE_MEDIA_HEADERS, direct_delivery_allowed, signed_url_ttl,
)

@pytest.mark.parametrize("endpoint", [None, "", "https://s3.example.test", "http://object-storage:9000"])
def test_default_uses_authorized_api(monkeypatch, endpoint):
    monkeypatch.delenv("LEARNHOUSE_S3_DIRECT_DELIVERY", raising=False)
    assert not direct_delivery_allowed(endpoint)

@pytest.mark.parametrize("endpoint,allowed", [
    (None, True), ("", True), ("https://media.example.test", True),
    ("http://object-storage:9000", False), ("https://user:pass@example.test", False),
    ("https://example.test?token=x", False), ("https://example.test#fragment", False),
    ("https://", False),
])
def test_explicit_direct_delivery_requires_tls(monkeypatch, endpoint, allowed):
    monkeypatch.setenv("LEARNHOUSE_S3_DIRECT_DELIVERY", "true")
    assert direct_delivery_allowed(endpoint) is allowed

@pytest.mark.parametrize("requested,expected", [(-1, 1), (0, 1), (300, 300), (900, 900), (86400, 900)])
def test_capability_lifetime_is_bounded(requested, expected):
    assert signed_url_ttl(requested) == expected

def test_private_responses_are_not_reused_after_logout():
    assert PRIVATE_MEDIA_HEADERS["Cache-Control"] == "private, no-store"
    assert PRIVATE_MEDIA_HEADERS["Vary"] == "Authorization, Cookie"
    assert PRIVATE_MEDIA_HEADERS["X-Content-Type-Options"] == "nosniff"

def test_uploaded_active_content_is_sandboxed_and_downloaded():
    from src.services.utils.media_delivery import content_headers
    for mime in ["text/html", "application/javascript", "image/svg+xml"]:
        headers = content_headers(mime)
        assert headers["Content-Disposition"] == "attachment"
        assert headers["Content-Security-Policy"] == "sandbox; default-src 'none'"
        assert headers["Cache-Control"] == "private, no-store"
    assert "Content-Disposition" not in content_headers("image/png")
