"""Input type detection and normalization for ipsak."""

import ipaddress
import re
from urllib.parse import urlparse


def detect_target(target: str) -> tuple[str, str]:
    """Detect the type of the target and normalize it.

    Returns:
        (target_type, normalized_target) where target_type is one of:
        'ipv4', 'ipv6', 'cidr4', 'cidr6', 'domain', 'unknown'
    """
    cleaned = _clean_input(target)

    # Try as IP address
    try:
        addr = ipaddress.ip_address(cleaned)
        return (f"ipv{addr.version}", str(addr))
    except ValueError:
        pass

    # Try as CIDR network
    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        return (f"cidr{net.version}", str(net))
    except ValueError:
        pass

    # Try as domain
    if _is_valid_domain(cleaned):
        return ("domain", cleaned.lower().rstrip("."))

    return ("unknown", cleaned)


def _clean_input(target: str) -> str:
    """Strip URLs, ports, and whitespace from input."""
    target = target.strip()

    # Handle URLs: http://1.2.3.4/path → 1.2.3.4
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or target

    # Handle host:port (but not IPv6 with colons)
    if target.count(":") == 1 and not target.startswith("["):
        host, _, port = target.partition(":")
        if port.isdigit():
            target = host

    # Handle [IPv6]:port
    if target.startswith("[") and "]" in target:
        target = target[1 : target.index("]")]

    return target


# AIDEV-NOTE: Intentionally permissive domain regex. Validates structure, not existence.
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}\.?$"
)


def _is_valid_domain(s: str) -> bool:
    """Check if string looks like a valid domain name."""
    if len(s) > 253:
        return False
    return bool(_DOMAIN_RE.match(s))
