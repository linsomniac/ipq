"""Traceroute functionality (opt-in, may require privileges)."""

import asyncio
import re
import shutil

from ipq.models import TraceHop


async def run_traceroute(target: str, *, timeout: float = 30.0) -> list[TraceHop]:
    """Run traceroute to target, trying multiple methods.

    Tries in order:
    1. icmplib (if installed, needs root/capabilities)
    2. System traceroute command (fallback)
    """
    # Try icmplib first
    try:
        return await _traceroute_icmplib(target, timeout=timeout)
    except (ImportError, PermissionError):
        pass

    # Fall back to system traceroute
    return await _traceroute_system(target, timeout=timeout)


async def _traceroute_icmplib(target: str, *, timeout: float = 30.0) -> list[TraceHop]:
    """Traceroute using icmplib (needs icmplib installed + root/cap_net_raw)."""
    import icmplib  # type: ignore[import-untyped]

    loop = asyncio.get_running_loop()
    result = await asyncio.wait_for(
        loop.run_in_executor(
            None,
            lambda: icmplib.traceroute(target, max_hops=30, count=1, timeout=2),
        ),
        timeout=timeout,
    )

    hops: list[TraceHop] = []
    for hop in result:
        hops.append(
            TraceHop(
                hop=hop.distance,
                ip=hop.address if hop.address != "*" else None,
                rtt_ms=hop.avg_rtt if hop.avg_rtt > 0 else None,
                loss_pct=hop.packet_loss * 100,
            )
        )
    return hops


# AIDEV-NOTE: Parses standard traceroute output format:
#   " 1  gateway (10.0.0.1)  1.234 ms  1.456 ms  1.789 ms"
#   " 2  * * *"
_TRACE_LINE_RE = re.compile(
    r"^\s*(\d+)\s+" r"(?:(\S+)\s+\(([^)]+)\)|(\*)).*?" r"(?:(\d+\.?\d*)\s*ms)?",
)


async def _traceroute_system(target: str, *, timeout: float = 30.0) -> list[TraceHop]:
    """Traceroute using system traceroute/tracepath command."""
    cmd = None
    for prog in ("traceroute", "tracepath"):
        if shutil.which(prog):
            cmd = prog
            break

    if cmd is None:
        raise RuntimeError("No traceroute tool available (install traceroute or icmplib)")

    if cmd == "traceroute":
        args = [cmd, "-m", "30", "-w", "2", "-q", "1", target]
    else:
        args = [cmd, "-m", "30", target]

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise

    hops: list[TraceHop] = []
    for line in stdout.decode(errors="replace").splitlines():
        m = _TRACE_LINE_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        hostname = m.group(2)
        ip = m.group(3)
        is_star = m.group(4) == "*"
        rtt = float(m.group(5)) if m.group(5) else None

        if is_star:
            hops.append(TraceHop(hop=hop_num))
        else:
            hops.append(
                TraceHop(
                    hop=hop_num,
                    ip=ip or hostname,
                    hostname=hostname if hostname != ip else None,
                    rtt_ms=rtt,
                )
            )

    return hops
