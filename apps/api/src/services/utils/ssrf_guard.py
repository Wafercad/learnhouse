"""
SSRF guard for outbound HTTP calls where the URL is user-influenced
(webhook endpoints, link previews, etc.).

The guard has two steps:

1. ``resolve_and_validate_url`` resolves the hostname once and rejects the
   request if any resolved address falls in a private/reserved range — unless
   the caller opted that specific hostname in via ``allow_hosts``. It
   returns the set of validated IPs.
2. ``assert_connected_peer_allowed`` runs after the httpx request completes
   and verifies the TCP peer httpx actually connected to was one of the
   IPs we validated. This closes the DNS-rebinding window between step 1
   and the actual socket connect.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import httpx


_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}

#: Hostnames no allowlist may ever exempt. Cloud metadata is the single most
#: valuable SSRF target there is — it hands instance credentials to anything that
#: can make the server issue a request — so "the operator asked for it" is not a
#: good enough reason. ``localhost`` is deliberately NOT here: pointing a webhook
#: at a service on the same host is an ordinary self-hosted setup.
_NEVER_ALLOWLISTABLE = frozenset({"metadata.google.internal"})


class SSRFBlockedError(Exception):
    """Raised when a URL or its resolved peer is not permitted."""


def _normalize(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _is_ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    ip = _normalize(ip)
    return any(ip in net for net in _BLOCKED_NETWORKS)


def resolve_and_validate_url(
    url: str,
    *,
    allow_http: bool = True,
    allow_hosts: frozenset[str] = frozenset(),
) -> set[str]:
    """
    Resolve the hostname in ``url`` and verify every returned IP is public.

    Returns the set of validated peer-IP strings that the subsequent httpx
    request is allowed to connect to. Raises :class:`SSRFBlockedError` on
    any validation failure.

    ``allow_hosts`` names hostnames permitted to resolve to a private or
    reserved address. It exists for one case: a deployment whose webhook
    receiver is a sibling service on an internal network, which describes every
    self-hosted install and every local development stack. Three properties keep
    it from widening the guard:

    * **Opt-in per call site.** The default is empty, so every existing caller
      behaves exactly as before. Only the webhook dispatcher passes it — the
      link-preview fetcher and the custom-domain checker take arbitrary
      user-supplied URLs and must keep refusing private addresses, which they do
      by simply not opting in.
    * **It names HOSTS, not networks.** An operator exempts the one destination
      they run, not a whole RFC1918 range, and that destination is one they had
      to configure and register as a webhook endpoint first.
    * **DNS-rebinding protection is unaffected.** An allowlisted host is still
      resolved and its addresses are still returned, so
      :func:`assert_connected_peer_allowed` still verifies that the peer httpx
      actually connected to was one of them.

    Hostnames in :data:`_NEVER_ALLOWLISTABLE` are refused regardless.
    """
    parsed = urlparse(url)

    allowed_schemes = {"http", "https"} if allow_http else {"https"}
    if parsed.scheme not in allowed_schemes:
        raise SSRFBlockedError(f"URL scheme not allowed: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname")

    host_key = hostname.lower()
    if host_key in _NEVER_ALLOWLISTABLE:
        raise SSRFBlockedError(f"Blocked hostname: {hostname}")

    exempt = host_key in {allowed.lower() for allowed in allow_hosts}
    if host_key in _BLOCKED_HOSTNAMES and not exempt:
        raise SSRFBlockedError(f"Blocked hostname: {hostname}")

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Could not resolve hostname: {hostname}") from exc

    validated: set[str] = set()
    for _, _, _, _, sockaddr in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if _is_ip_blocked(ip) and not exempt:
            raise SSRFBlockedError(
                f"URL {url} resolves to blocked address range ({ip})"
            )
        validated.add(str(_normalize(ip)))

    if not validated:
        raise SSRFBlockedError(f"No addresses resolved for hostname: {hostname}")

    return validated


def assert_connected_peer_allowed(
    response: httpx.Response,
    validated_ips: set[str],
    *,
    allow_private: bool = False,
) -> None:
    """
    After an httpx request, confirm the peer httpx actually connected to was
    one of the IPs approved by :func:`resolve_and_validate_url`.

    Defeats DNS rebinding: even if DNS flipped between validation and connect,
    the peer IP is observable on the response's network_stream extension.

    ``allow_private`` must be set when the destination was exempted via
    ``resolve_and_validate_url(..., allow_hosts=...)``, because this function
    independently refuses a private peer and would otherwise reject the very
    address the allowlist just approved — the exemption has to hold at BOTH ends
    or it does nothing. It relaxes only the range check; membership in
    ``validated_ips`` is still required, so rebinding is still caught.

    Raises :class:`SSRFBlockedError` on mismatch; callers must discard any
    response body already read in that case.
    """
    stream = response.extensions.get("network_stream")
    if stream is None:
        raise SSRFBlockedError("Cannot determine peer address — fail closed")

    try:
        peer = stream.get_extra_info("server_addr")
    except Exception as exc:  # httpcore / transport idiosyncrasies
        raise SSRFBlockedError(f"Failed to read peer address: {exc}") from exc

    if not peer:
        raise SSRFBlockedError("Peer address unavailable — fail closed")

    peer_host = peer[0] if isinstance(peer, tuple) else str(peer)
    try:
        peer_ip = ipaddress.ip_address(peer_host)
    except ValueError as exc:
        raise SSRFBlockedError(f"Could not parse peer address: {peer_host!r}") from exc

    # Defense in depth: peer must not itself land in a blocked range — except
    # where the caller deliberately allowlisted a private destination, in which
    # case the membership check below is the whole guarantee.
    if _is_ip_blocked(peer_ip) and not allow_private:
        raise SSRFBlockedError(f"Connected to blocked peer IP: {peer_ip}")

    peer_key = str(_normalize(peer_ip))
    if peer_key not in validated_ips:
        raise SSRFBlockedError(
            f"DNS rebinding detected: connected to {peer_key}, "
            f"validated addresses were {sorted(validated_ips)}"
        )
