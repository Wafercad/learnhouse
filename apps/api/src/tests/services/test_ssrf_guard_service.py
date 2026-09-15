import ipaddress
import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.services.utils.ssrf_guard import (
    SSRFBlockedError,
    _is_ip_blocked,
    _normalize,
    assert_connected_peer_allowed,
    resolve_and_validate_url,
)


def _response_with_peer(peer_value):
    return SimpleNamespace(
        extensions={
            "network_stream": SimpleNamespace(
                get_extra_info=lambda name: peer_value if name == "server_addr" else None
            )
        }
    )


def test_normalize_unwraps_ipv4_mapped_ipv6():
    mapped = ipaddress.ip_address("::ffff:192.0.2.10")

    normalized = _normalize(mapped)

    assert str(normalized) == "192.0.2.10"


def test_is_ip_blocked_matches_private_and_public_ranges():
    assert _is_ip_blocked(ipaddress.ip_address("10.1.2.3"))
    assert not _is_ip_blocked(ipaddress.ip_address("203.0.113.10"))


def test_resolve_and_validate_url_rejects_disallowed_scheme():
    with pytest.raises(SSRFBlockedError, match="URL scheme not allowed"):
        resolve_and_validate_url("ftp://example.com")


def test_resolve_and_validate_url_rejects_missing_hostname():
    with pytest.raises(SSRFBlockedError, match="URL has no hostname"):
        resolve_and_validate_url("http:///no-host")


@pytest.mark.parametrize(
    "hostname",
    ["localhost", "LOCALHOST", "metadata.google.internal"],
)
def test_resolve_and_validate_url_rejects_blocked_hostnames(hostname):
    with pytest.raises(SSRFBlockedError, match="Blocked hostname"):
        resolve_and_validate_url(f"https://{hostname}/page")


def test_resolve_and_validate_url_wraps_dns_errors():
    with patch(
        "src.services.utils.ssrf_guard.socket.getaddrinfo",
        side_effect=socket.gaierror("boom"),
    ):
        with pytest.raises(SSRFBlockedError, match="Could not resolve hostname"):
            resolve_and_validate_url("https://example.com")


def test_resolve_and_validate_url_rejects_blocked_ip_ranges():
    addr_info = [
        (None, None, None, None, ("10.0.0.4", 443)),
    ]

    with patch(
        "src.services.utils.ssrf_guard.socket.getaddrinfo",
        return_value=addr_info,
    ):
        with pytest.raises(SSRFBlockedError, match="blocked address range"):
            resolve_and_validate_url("https://example.com")


def test_resolve_and_validate_url_rejects_empty_resolution():
    with patch(
        "src.services.utils.ssrf_guard.socket.getaddrinfo",
        return_value=[],
    ):
        with pytest.raises(SSRFBlockedError, match="No addresses resolved"):
            resolve_and_validate_url("https://example.com")


def test_resolve_and_validate_url_returns_normalized_address_set():
    addr_info = [
        (None, None, None, None, ("93.184.216.34", 443)),
        (None, None, None, None, ("93.184.216.34", 443)),
    ]

    with patch(
        "src.services.utils.ssrf_guard.socket.getaddrinfo",
        return_value=addr_info,
    ):
        validated = resolve_and_validate_url("https://example.com")

    assert validated == {"93.184.216.34"}


def test_assert_connected_peer_allowed_requires_network_stream():
    response = SimpleNamespace(extensions={})

    with pytest.raises(SSRFBlockedError, match="Cannot determine peer address"):
        assert_connected_peer_allowed(response, {"93.184.216.34"})


def test_assert_connected_peer_allowed_wraps_stream_errors():
    response = SimpleNamespace(
        extensions={
            "network_stream": SimpleNamespace(
                get_extra_info=lambda name: (_ for _ in ()).throw(RuntimeError("bad stream"))
            )
        }
    )

    with pytest.raises(SSRFBlockedError, match="Failed to read peer address"):
        assert_connected_peer_allowed(response, {"93.184.216.34"})


def test_assert_connected_peer_allowed_requires_peer_address():
    response = _response_with_peer(None)

    with pytest.raises(SSRFBlockedError, match="Peer address unavailable"):
        assert_connected_peer_allowed(response, {"93.184.216.34"})


def test_assert_connected_peer_allowed_rejects_unparseable_peer():
    response = _response_with_peer(("not-an-ip", 443))

    with pytest.raises(SSRFBlockedError, match="Could not parse peer address"):
        assert_connected_peer_allowed(response, {"93.184.216.34"})


def test_assert_connected_peer_allowed_rejects_blocked_peer_ip():
    response = _response_with_peer(("127.0.0.1", 443))

    with pytest.raises(SSRFBlockedError, match="Connected to blocked peer IP"):
        assert_connected_peer_allowed(response, {"127.0.0.1"})


def test_assert_connected_peer_allowed_rejects_rebinding():
    response = _response_with_peer(("93.184.216.35", 443))

    with pytest.raises(SSRFBlockedError, match="DNS rebinding detected"):
        assert_connected_peer_allowed(response, {"93.184.216.34"})


def test_assert_connected_peer_allowed_accepts_ipv4_mapped_peer():
    response = _response_with_peer(("::ffff:93.184.216.34", 443))

    assert_connected_peer_allowed(response, {"93.184.216.34"})


# ---------------------------------------------------------------------------
# allow_hosts — the narrow opt-in for an internal webhook destination.
# ---------------------------------------------------------------------------


def _resolving_to(address):
    return patch(
        "src.services.utils.ssrf_guard.socket.getaddrinfo",
        return_value=[(None, None, None, None, (address, 443))],
    )


def test_allow_hosts_permits_a_named_private_destination():
    with _resolving_to("172.18.0.7"):
        validated = resolve_and_validate_url(
            "http://campus_service:8010/hook",
            allow_hosts=frozenset({"campus_service"}),
        )

    assert validated == {"172.18.0.7"}


def test_an_allowlisted_private_peer_is_accepted_at_connect_time():
    """The exemption has to hold at BOTH ends: without it the peer check refuses
    the very address the allowlist just approved, and delivery fails AFTER the
    request instead of before it."""
    with _resolving_to("172.18.0.7"):
        validated = resolve_and_validate_url(
            "http://campus_service:8010/hook",
            allow_hosts=frozenset({"campus_service"}),
        )

    assert_connected_peer_allowed(
        _response_with_peer(("172.18.0.7", 8010)),
        validated,
        allow_private=True,
    )


def test_rebinding_is_still_caught_for_an_allowlisted_host():
    """`allow_private` relaxes the RANGE check only — membership in the
    validated set is still the guarantee, so a host that resolves somewhere else
    between validation and connect is refused."""
    with _resolving_to("172.18.0.7"):
        validated = resolve_and_validate_url(
            "http://campus_service:8010/hook",
            allow_hosts=frozenset({"campus_service"}),
        )

    with pytest.raises(SSRFBlockedError, match="DNS rebinding detected"):
        assert_connected_peer_allowed(
            _response_with_peer(("172.18.0.99", 8010)),
            validated,
            allow_private=True,
        )


def test_a_private_peer_is_still_refused_without_the_opt_in():
    with pytest.raises(SSRFBlockedError, match="blocked peer IP"):
        assert_connected_peer_allowed(
            _response_with_peer(("172.18.0.7", 8010)),
            {"172.18.0.7"},
        )


def test_allow_hosts_does_not_exempt_a_host_it_does_not_name():
    with _resolving_to("10.0.0.4"):
        with pytest.raises(SSRFBlockedError, match="blocked address range"):
            resolve_and_validate_url(
                "http://other-service:8010/hook",
                allow_hosts=frozenset({"campus_service"}),
            )


def test_allow_hosts_can_exempt_localhost():
    with _resolving_to("127.0.0.1"):
        validated = resolve_and_validate_url(
            "http://localhost:8010/hook",
            allow_hosts=frozenset({"localhost"}),
        )

    assert validated == {"127.0.0.1"}


def test_allow_hosts_can_never_exempt_cloud_metadata():
    """The one host an operator must not be able to talk themselves into."""
    with pytest.raises(SSRFBlockedError, match="Blocked hostname"):
        resolve_and_validate_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            allow_hosts=frozenset({"metadata.google.internal"}),
        )


def test_allow_hosts_matching_is_case_insensitive():
    with _resolving_to("172.18.0.7"):
        validated = resolve_and_validate_url(
            "http://Campus_Service:8010/hook",
            allow_hosts=frozenset({"CAMPUS_SERVICE"}),
        )

    assert validated == {"172.18.0.7"}


def test_the_default_is_unchanged_behaviour():
    """Every existing caller passes no allowlist and must keep refusing private
    addresses — this is what makes the change safe for link previews."""
    with _resolving_to("192.168.1.10"):
        with pytest.raises(SSRFBlockedError, match="blocked address range"):
            resolve_and_validate_url("http://internal.example.com/x")
