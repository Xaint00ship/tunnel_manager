"""Collapse adjacent IP networks into the smallest equivalent set.

`ipaddress.collapse_addresses` merges contiguous /N blocks into bigger
prefixes (e.g. four adjacent /24s → one /22). On a typical curated VPN
list this trims 700 routes down to ~200, cutting both routing-table
pressure and the time the OS needs to apply each individual route.
"""

from __future__ import annotations

import ipaddress

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _to_network(entry: str) -> _Network | None:
    try:
        if "/" in entry:
            return ipaddress.ip_network(entry, strict=False)
        addr = ipaddress.ip_address(entry)
        return ipaddress.ip_network(addr)  # /32 or /128
    except ValueError:
        return None


def collapse_routes(entries: list[str]) -> list[str]:
    """Aggregate adjacent CIDRs per address family.

    Output entries are always in CIDR form (`/32` for single IPv4 hosts,
    `/128` for IPv6 hosts). Invalid inputs are silently dropped — the
    caller has already validated through the parser.
    """
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for e in entries:
        net = _to_network(e)
        if isinstance(net, ipaddress.IPv4Network):
            v4.append(net)
        elif isinstance(net, ipaddress.IPv6Network):
            v6.append(net)

    out: list[str] = []
    out.extend(str(n) for n in ipaddress.collapse_addresses(v4))
    out.extend(str(n) for n in ipaddress.collapse_addresses(v6))
    return out
