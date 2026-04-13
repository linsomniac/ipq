"""IP subnet calculator using stdlib ipaddress."""

import ipaddress

from ipsak.models import SubnetResult


def calculate_subnet(cidr: str) -> SubnetResult:
    """Calculate subnet information for a CIDR notation network."""
    net = ipaddress.ip_network(cidr, strict=False)

    if net.version == 4:
        netmask = str(net.netmask)
        wildcard = str(net.hostmask)
        broadcast = str(net.broadcast_address)
    else:
        netmask = str(net.netmask)
        wildcard = str(net.hostmask)
        broadcast = str(net.broadcast_address)

    hosts = list(net.hosts())
    first_host = str(hosts[0]) if hosts else str(net.network_address)
    last_host = str(hosts[-1]) if hosts else str(net.network_address)

    return SubnetResult(
        network=str(net.network_address),
        broadcast=broadcast,
        netmask=netmask,
        wildcard=wildcard,
        first_host=first_host,
        last_host=last_host,
        num_addresses=net.num_addresses,
        num_hosts=max(0, net.num_addresses - 2)
        if net.version == 4 and net.prefixlen < 31
        else net.num_addresses,
        prefix_len=net.prefixlen,
        ip_version=net.version,
    )
