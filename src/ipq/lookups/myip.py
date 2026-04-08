"""Discover public and local IP addresses."""

import ipaddress
import socket
import subprocess
from dataclasses import dataclass, field

import httpx


@dataclass
class LocalInterface:
    name: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)


@dataclass
class MyIPResult:
    public_ip: str | None = None
    public_source: str | None = None
    local_interfaces: list[LocalInterface] = field(default_factory=list)
    hostname: str | None = None


# AIDEV-NOTE: Multiple public IP services for redundancy. All return plain text.
# These are fast, reliable, and don't require API keys.
_PUBLIC_IP_SERVICES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


async def discover_public_ip(client: httpx.AsyncClient) -> tuple[str, str]:
    """Discover public IP using external services. Returns (ip, service_used)."""
    for url in _PUBLIC_IP_SERVICES:
        try:
            resp = await client.get(url, follow_redirects=True)
            resp.raise_for_status()
            ip = resp.text.strip()
            # Validate it's actually an IP
            ipaddress.ip_address(ip)
            return (ip, url)
        except Exception:
            continue
    raise RuntimeError("Could not determine public IP from any service")


def discover_local_interfaces() -> list[LocalInterface]:
    """Discover local network interfaces and their IP addresses.

    Uses socket/stdlib approach that works cross-platform without extra deps.
    """
    interfaces: dict[str, LocalInterface] = {}

    try:
        result = subprocess.run(
            ["ip", "-brief", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[0]
                state = parts[1]
                if state == "DOWN":
                    continue
                iface = interfaces.setdefault(name, LocalInterface(name=name))
                for addr_str in parts[2:]:
                    # Format: "192.168.1.5/24" or "fe80::1/64"
                    ip_part = addr_str.split("/")[0]
                    try:
                        addr = ipaddress.ip_address(ip_part)
                        if addr.version == 4:
                            iface.ipv4.append(addr_str)
                        else:
                            iface.ipv6.append(addr_str)
                    except ValueError:
                        continue
            return list(interfaces.values())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: use socket to get the primary local IP
    fallback = LocalInterface(name="default")
    try:
        # Connect to a public IP (doesn't actually send data) to find default route IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            fallback.ipv4.append(s.getsockname()[0])
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860::8888", 80))
            fallback.ipv6.append(s.getsockname()[0])
    except Exception:
        pass

    if fallback.ipv4 or fallback.ipv6:
        return [fallback]
    return []


def get_hostname() -> str | None:
    """Get the system hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return None
