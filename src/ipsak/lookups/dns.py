"""DNS lookup functions (forward and reverse)."""

import asyncio

import dns.asyncresolver
import dns.exception
import dns.reversename


async def lookup_ptr(ip: str, *, timeout: float = 10.0) -> str | None:
    """Reverse DNS (PTR) lookup for an IP address."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    rev_name = dns.reversename.from_address(ip)
    try:
        answer = await resolver.resolve(rev_name, "PTR")
        return str(answer[0]).rstrip(".")
    except (dns.exception.DNSException, ValueError):
        return None


# AIDEV-NOTE: Record types are queried concurrently for speed.
# CNAME and SOA often return NXDOMAIN/NoAnswer; that's expected.
_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


async def lookup_dns_records(domain: str, *, timeout: float = 10.0) -> dict[str, list[str] | str]:
    """Look up all common DNS record types for a domain."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    async def _query_type(rtype: str) -> tuple[str, list[str] | str | None]:
        try:
            answer = await resolver.resolve(domain, rtype)
            records = [str(r) for r in answer]
            if rtype == "SOA":
                return (rtype.lower(), records[0] if records else None)
            return (rtype.lower(), records)
        except dns.exception.DNSException:
            return (rtype.lower(), [] if rtype != "SOA" else None)

    tasks = [_query_type(rt) for rt in _RECORD_TYPES]
    results = await asyncio.gather(*tasks)

    out: dict[str, list[str] | str] = {}
    for key, val in results:
        if val:  # Skip empty lists and None
            out[key] = val  # type: ignore[assignment]
    return out
