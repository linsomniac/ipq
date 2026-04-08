"""RPKI route origin validation via RIPE RIPEstat API."""

import httpx

from ipq.models import RPKIResult

# AIDEV-NOTE: Uses RIPE's RIPEstat API for RPKI validation. No auth required.
# Cloudflare's API returns 404 for the path-based prefix format.
_RPKI_API = "https://stat.ripe.net/data/rpki-validation/data.json"


async def lookup_rpki(asn: int, prefix: str, client: httpx.AsyncClient) -> RPKIResult:
    """Check RPKI validation status for an ASN + prefix pair."""
    resp = await client.get(
        _RPKI_API,
        params={"resource": f"AS{asn}", "prefix": prefix},
    )
    resp.raise_for_status()
    data = resp.json()

    ripe_data = data.get("data", {})
    state = ripe_data.get("status", "unknown")

    state_map = {
        "valid": "Valid",
        "invalid": "Invalid",
        "unknown": "Not Found",
    }
    status = state_map.get(state.lower(), state.title())

    description = None
    roas = ripe_data.get("validating_roas", [])
    if roas:
        roa = roas[0]
        description = f"ROA: AS{roa['origin']} {roa['prefix']} (max /{roa['max_length']})"

    return RPKIResult(
        status=status,
        description=description,
    )
