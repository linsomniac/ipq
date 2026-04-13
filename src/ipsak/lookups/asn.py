"""ASN lookup via Team Cymru DNS service."""

import ipaddress

import dns.asyncresolver
import dns.exception

from ipsak.models import ASNResult


async def lookup_asn_cymru(ip: str, *, timeout: float = 10.0) -> ASNResult:
    """Look up ASN information via Team Cymru's DNS service.

    Fast (~50-200ms) since it's just DNS queries.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    addr = ipaddress.ip_address(ip)
    origin_query = _build_origin_query(addr)

    # Query origin: returns "ASN | Prefix | CC | Registry | Allocated"
    answer = await resolver.resolve(origin_query, "TXT")
    txt = str(answer[0]).strip('"')
    fields = [f.strip() for f in txt.split("|")]

    asn_num = int(fields[0]) if fields[0].strip() else None
    prefix = fields[1] if len(fields) > 1 else None
    country = fields[2] if len(fields) > 2 else None
    registry = fields[3] if len(fields) > 3 else None
    allocated = fields[4] if len(fields) > 4 else None

    # Look up ASN name
    name = None
    if asn_num:
        try:
            name_answer = await resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
            name_txt = str(name_answer[0]).strip('"')
            name_fields = [f.strip() for f in name_txt.split("|")]
            name = name_fields[4] if len(name_fields) > 4 else None
        except dns.exception.DNSException:
            pass

    return ASNResult(
        asn=asn_num,
        name=name,
        prefix=prefix,
        country=country,
        registry=registry,
        allocated=allocated,
    )


def _build_origin_query(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Build the Team Cymru origin DNS query for an IP."""
    if addr.version == 4:
        octets = str(addr).split(".")
        return ".".join(reversed(octets)) + ".origin.asn.cymru.com"
    else:
        # IPv6: expand to full form, reverse each nibble
        expanded = addr.exploded.replace(":", "")
        nibbles = list(reversed(expanded))
        return ".".join(nibbles) + ".origin6.asn.cymru.com"
