"""Route list parser.

Accepts plain IPv4/IPv6 addresses, CIDR blocks, and Windows
`ROUTE ADD ... MASK ...` syntax. Groups entries by section headers; any
non-empty line that doesn't contain a valid address becomes the section
name (leading `#`/`##` is stripped). `//`-prefixed lines are dropped.
"""

from __future__ import annotations

import ipaddress
import re

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
# Loose IPv6 candidate — at least two colon-separated groups (handles `::1`,
# `fe80::1`, `2001:db8::/32`). Anything that survives this regex but isn't a
# real address is rejected by `_is_valid` below.
IPV6_RE = re.compile(r"(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F]*(?:/\d{1,3})?")
ROUTE_ADD_RE = re.compile(
    r"route\s+ADD\s+(\d[\d.]+)\s*MASK\s+(\d[\d.]+)", re.IGNORECASE
)
HEADER_PREFIX_RE = re.compile(r"^#+\s*")


def _mask_to_prefix(mask: str) -> int:
    return sum(bin(int(b)).count("1") for b in mask.split("."))


def _clean_header(s: str) -> str:
    return HEADER_PREFIX_RE.sub("", s).strip() or "Other"


def _is_valid(entry: str) -> bool:
    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False


def address_family(entry: str) -> int:
    """Return 4 or 6 for the address family of an IP/CIDR entry."""
    if "/" in entry:
        return ipaddress.ip_network(entry, strict=False).version
    return ipaddress.ip_address(entry).version


def parse_route_list(text: str) -> dict[str, list[str]]:
    """Return {section_name: [ip_or_cidr, ...]}, deduplicated globally."""
    sections: dict[str, list[str]] = {}
    seen: set[str] = set()
    current = "Other"

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        m = ROUTE_ADD_RE.search(line)
        if m:
            cidr = f"{m.group(1)}/{_mask_to_prefix(m.group(2))}"
            if _is_valid(cidr) and cidr not in seen:
                seen.add(cidr)
                sections.setdefault(current, []).append(cidr)
            continue

        candidates = IPV4_RE.findall(line) + IPV6_RE.findall(line)
        valid = [c for c in candidates if _is_valid(c)]
        if not valid:
            current = _clean_header(line)
            continue

        for entry in valid:
            if entry not in seen:
                seen.add(entry)
                sections.setdefault(current, []).append(entry)

    return sections
