"""Bogon and special-use address detection using stdlib ipaddress."""

import ipaddress

from ipsak.models import BogonResult


# AIDEV-NOTE: This covers all IANA special-purpose address registries.
# See RFC 6890 for the master list. Checked instantly with no network calls.
_SPECIAL_RANGES_V4: list[tuple[str, str, str]] = [
    ("0.0.0.0/8", "This Host", "RFC 1122"),
    ("10.0.0.0/8", "Private (Class A)", "RFC 1918"),
    ("100.64.0.0/10", "Shared Address (CGNAT)", "RFC 6598"),
    ("127.0.0.0/8", "Loopback", "RFC 1122"),
    ("169.254.0.0/16", "Link-Local", "RFC 3927"),
    ("172.16.0.0/12", "Private (Class B)", "RFC 1918"),
    ("192.0.0.0/24", "IETF Protocol Assignments", "RFC 6890"),
    ("192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC 5737"),
    ("192.88.99.0/24", "6to4 Relay Anycast", "RFC 7526"),
    ("192.168.0.0/16", "Private (Class C)", "RFC 1918"),
    ("198.18.0.0/15", "Benchmarking", "RFC 2544"),
    ("198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC 5737"),
    ("203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC 5737"),
    ("224.0.0.0/4", "Multicast", "RFC 5771"),
    ("240.0.0.0/4", "Reserved (Class E)", "RFC 1112"),
    ("255.255.255.255/32", "Limited Broadcast", "RFC 919"),
]

_SPECIAL_RANGES_V6: list[tuple[str, str, str]] = [
    ("::/128", "Unspecified", "RFC 4291"),
    ("::1/128", "Loopback", "RFC 4291"),
    ("::ffff:0:0/96", "IPv4-Mapped", "RFC 4291"),
    ("64:ff9b::/96", "IPv4/IPv6 Translation", "RFC 6052"),
    ("100::/64", "Discard-Only", "RFC 6666"),
    ("2001:db8::/32", "Documentation", "RFC 3849"),
    ("2001::/32", "Teredo", "RFC 4380"),
    ("2002::/16", "6to4", "RFC 3056"),
    ("fc00::/7", "Unique Local (ULA)", "RFC 4193"),
    ("fe80::/10", "Link-Local", "RFC 4291"),
    ("ff00::/8", "Multicast", "RFC 4291"),
]


def check_bogon(ip: str) -> BogonResult:
    """Check if an IP is a bogon or special-use address. Instant, no network."""
    addr = ipaddress.ip_address(ip)

    ranges = _SPECIAL_RANGES_V4 if addr.version == 4 else _SPECIAL_RANGES_V6
    for cidr, desc, rfc in ranges:
        if addr in ipaddress.ip_network(cidr):
            return BogonResult(
                is_bogon=True,
                ip_type=desc,
                description=f"{desc} address range",
                rfc=rfc,
            )

    # Check global unicast
    if addr.is_global:
        return BogonResult(is_bogon=False, ip_type="Public")

    return BogonResult(is_bogon=True, ip_type="Reserved", description="Reserved address")
