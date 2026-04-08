"""GeoIP lookup via ip-api.com free API."""

import httpx

from ipq.models import GeoResult


# AIDEV-NOTE: ip-api.com free tier: 45 req/min, HTTP only (HTTPS is paid).
# Fine for interactive CLI use. Will get 429 if scripted heavily.
_FIELDS = "status,message,country,countryCode,regionName,city," "lat,lon,timezone,isp,org,as,query"


async def lookup_geo(ip: str, client: httpx.AsyncClient) -> GeoResult:
    """Look up geolocation information for an IP via ip-api.com."""
    resp = await client.get(f"http://ip-api.com/json/{ip}?fields={_FIELDS}")
    resp.raise_for_status()
    data = resp.json()

    if data.get("status") != "success":
        msg = data.get("message", "GeoIP lookup failed")
        raise RuntimeError(f"GeoIP: {msg}")

    return GeoResult(
        country=data.get("country"),
        country_code=data.get("countryCode"),
        region=data.get("regionName"),
        city=data.get("city"),
        lat=data.get("lat"),
        lon=data.get("lon"),
        timezone=data.get("timezone"),
        isp=data.get("isp"),
        org=data.get("org"),
    )
