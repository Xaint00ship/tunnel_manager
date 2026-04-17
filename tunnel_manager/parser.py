"""Route list parser.

Accepts plain IPs, CIDR blocks, and Windows `ROUTE ADD ... MASK ...` syntax.
Groups entries by section headers. Any non-empty line that doesn't contain
an IP is treated as a section header (leading `#`/`##` markers are stripped).
Lines starting with `//` are dropped as comments.
"""

from __future__ import annotations

import re

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")
ROUTE_ADD_RE = re.compile(
    r"route\s+ADD\s+(\d[\d.]+)\s*MASK\s+(\d[\d.]+)", re.IGNORECASE
)
HEADER_PREFIX_RE = re.compile(r"^#+\s*")


def _mask_to_prefix(mask: str) -> int:
    return sum(bin(int(b)).count("1") for b in mask.split("."))


def _clean_header(s: str) -> str:
    return HEADER_PREFIX_RE.sub("", s).strip() or "Other"


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
            if cidr not in seen:
                seen.add(cidr)
                sections.setdefault(current, []).append(cidr)
            continue

        matches = IP_RE.findall(line)
        if not matches:
            current = _clean_header(line)
            continue

        for entry in matches:
            if entry not in seen:
                seen.add(entry)
                sections.setdefault(current, []).append(entry)

    return sections
