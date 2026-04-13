# ipsak

The IP Swiss Army Knife -- fast IP, CIDR, and domain information queries for network operations.

One command gives you ASN, geolocation, WHOIS, DNS, RPKI validation, DNSBL reputation, subnet math, and traceroute -- all in parallel.

## Quickstart

```bash
uvx ipsak 8.8.8.8
```

## Demo

```
$ ipsak 8.8.8.8

  8.8.8.8 · dns.google · AS15169 GOOGLE - Google LLC, US · Ashburn, US · Public

                Network                              Location
  ASN         AS15169                    Country     United States (US)
  Org         GOOGLE - Google LLC, US    Region      Virginia
  Prefix      8.8.8.0/24                City        Ashburn
  RIR         ARIN                      ISP         Google LLC
  RPKI        ✓ Valid                    Org         Google Public DNS
                 WHOIS                   TZ          America/New_York
  Range       8.8.8.0 - 8.8.8.255       Coords      39.0300, -77.5000
  Name        GOGL
  Org         Google LLC                      Reputation
  Abuse       network-abuse@google.com   DNSBL    Clean (6 lists checked)
  Country     US
  Created     2023-12-28
  Updated     2023-12-28
```

```
$ ipsak dns google.com

  google.com DNS
  A         142.251.35.142
  AAAA      2607:f8b0:400f:801::200e
  MX        10 smtp.google.com.
  NS        ns1.google.com.
            ns4.google.com.
            ns2.google.com.
            ns3.google.com.
  TXT       "v=spf1 include:_spf.google.com ~all"
            ...
  SOA       ns1.google.com. dns-admin.google.com. ...
```

```
$ ipsak calc 10.0.0.0/24

  10.0.0.0/24 Subnet
  Network         10.0.0.0
  Broadcast       10.0.0.255
  Netmask         255.255.255.0
  Wildcard        0.0.0.255
  Prefix          /24
  First Host      10.0.0.1
  Last Host       10.0.0.254
  Addresses       256
  Usable          254
  IP Version      IPv4
```

## Install

Requires Python 3.11+.

### Run without installing

```bash
uvx ipsak 8.8.8.8
```

### Install with uv

```bash
uv tool install ipsak
ipsak 8.8.8.8
```

### Install with pipx or pip

```bash
pipx install ipsak
# or
pip install ipsak
```

### Install from source

```bash
git clone https://github.com/linsomniac/ipsak.git
cd ipsak
uv tool install .
```

## Usage

```
ipsak <target>              # Full info (ASN, geo, WHOIS, DNS, RPKI, reputation)
ipsak dns <domain|ip>       # DNS records or reverse DNS
ipsak whois <target>        # WHOIS/RDAP lookup
ipsak calc <cidr>           # Subnet calculator
ipsak trace <target>        # Traceroute (fast parallel ICMP; needs root for raw sockets)
ipsak myip                  # Show public and local IP addresses
```

The target can be an IPv4/IPv6 address, a CIDR block, or a domain name. When no subcommand is given, `ipsak` defaults to `info`.

### Options

| Flag | Description |
|------|-------------|
| `--json` / `-j` | Output as JSON |
| `--trace` / `-t` | Include traceroute in info output |
| `--timeout` / `-T` | Lookup timeout in seconds (default: 10) |
| `--version` / `-V` | Show version |

### Traceroute

`ipsak trace` uses a fast parallel raw-ICMP engine when it has the privileges to
open raw sockets (root, `sudo`, or `CAP_NET_RAW`). If it doesn't, it falls back
to the system `traceroute` or `tracepath` binary.

```bash
sudo ipsak trace 8.8.8.8
# or grant the capability once:
sudo setcap cap_net_raw+ep "$(readlink -f "$(which ipsak)")"
ipsak trace 8.8.8.8
```

## What it queries

All lookups run concurrently for fast results:

- **ASN** -- Team Cymru DNS mapping
- **Geolocation** -- ip-api.com
- **WHOIS/RDAP** -- via ipwhois library
- **DNS** -- forward (A, AAAA, CNAME, MX, NS, TXT, SOA) and reverse (PTR)
- **RPKI** -- Cloudflare RPKI validator
- **Reputation** -- DNSBL checks (Spamhaus, Barracuda, SORBS, etc.)
- **Bogon detection** -- RFC 1918, RFC 5737, loopback, link-local, etc.
- **Subnet calculator** -- network/broadcast/host range math

## License

CC0 1.0 Universal -- public domain. See [LICENSE](LICENSE).
