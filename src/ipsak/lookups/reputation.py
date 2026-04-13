"""DNSBL reputation checking via DNS queries."""

import asyncio

import dns.asyncresolver
import dns.exception

from ipsak.models import ReputationResult

# AIDEV-NOTE: Curated list of reliable, fast DNSBLs.
# Spamhaus zen combines SBL+XBL+PBL. All support standard DNSBL protocol.
_DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "all.s5h.net",
    "dnsbl.sorbs.net",
]


async def check_dnsbl(ip: str, *, timeout: float = 10.0) -> ReputationResult:
    """Check an IP against common DNS blacklists."""
    # Reverse IP for DNSBL query format
    reversed_ip = ".".join(reversed(ip.split(".")))

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    async def _check_one(bl: str) -> tuple[str, bool]:
        query = f"{reversed_ip}.{bl}"
        try:
            await resolver.resolve(query, "A")
            return (bl, True)  # Listed
        except (dns.exception.DNSException, ValueError):
            return (bl, False)  # Not listed

    results = await asyncio.gather(
        *[_check_one(bl) for bl in _DNSBL_SERVERS],
        return_exceptions=True,
    )

    listed: list[str] = []
    clean: list[str] = []
    checked = 0

    for r in results:
        if isinstance(r, BaseException):
            continue
        bl_name, is_listed = r
        checked += 1
        if is_listed:
            listed.append(bl_name)
        else:
            clean.append(bl_name)

    return ReputationResult(listed_on=listed, clean_on=clean, checked=checked)
