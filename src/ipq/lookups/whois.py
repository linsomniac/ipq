"""WHOIS/RDAP lookup via ipwhois library."""

import asyncio
from typing import Any

from ipq.models import WhoisResult


async def lookup_whois(ip: str, *, timeout: float = 15.0) -> WhoisResult:
    """Look up WHOIS/RDAP information for an IP address.

    Runs synchronous ipwhois in a thread executor.
    """
    loop = asyncio.get_running_loop()
    try:
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_rdap_lookup, ip),
            timeout=timeout,
        )
    except TimeoutError:
        raise TimeoutError(f"WHOIS lookup timed out after {timeout}s")

    return _parse_rdap(raw)


def _sync_rdap_lookup(ip: str) -> dict[str, Any]:
    """Synchronous RDAP lookup (runs in executor)."""
    from ipwhois import IPWhois

    obj = IPWhois(ip)
    return obj.lookup_rdap(depth=1)  # type: ignore[no-any-return]


def _parse_rdap(raw: dict[str, Any]) -> WhoisResult:
    """Extract useful fields from ipwhois RDAP response."""
    network = raw.get("network", {}) or {}

    # Build net range from start/end addresses
    start = network.get("start_address")
    end = network.get("end_address")
    net_range = f"{start} - {end}" if start and end else None

    # Extract org name and abuse email from objects
    org_name = None
    abuse_email = None
    objects = raw.get("objects", {}) or {}
    for obj_data in objects.values():
        contact = obj_data.get("contact", {}) or {}
        role = contact.get("role")
        name = contact.get("name")

        if role == "abuse" or (
            not abuse_email and obj_data.get("roles") and "abuse" in (obj_data.get("roles") or [])
        ):
            emails = contact.get("email", []) or []
            if emails:
                email_val = emails[0].get("value") if isinstance(emails[0], dict) else emails[0]
                abuse_email = email_val

        if role == "registrant" or (not org_name and name):
            org_name = name

    # Extract dates from network events
    created = None
    updated = None
    for event in network.get("events", []) or []:
        action = event.get("action")
        ts = event.get("timestamp", "")
        date_str = ts[:10] if ts else None
        if action == "registration" and date_str:
            created = date_str
        elif action == "last changed" and date_str:
            updated = date_str

    return WhoisResult(
        net_range=net_range,
        net_name=network.get("name"),
        net_cidr=raw.get("asn_cidr"),
        org=org_name or raw.get("asn_description"),
        abuse_email=abuse_email,
        created=created,
        updated=updated,
        description=raw.get("asn_description"),
        country=raw.get("asn_country_code") or network.get("country"),
    )
