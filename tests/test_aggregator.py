from tunnel_manager.aggregator import collapse_routes


def test_empty():
    assert collapse_routes([]) == []


def test_single_entries_become_host_routes():
    assert sorted(collapse_routes(["1.2.3.4", "5.6.7.8"])) == [
        "1.2.3.4/32", "5.6.7.8/32"
    ]


def test_collapse_four_adjacent_24_to_22():
    entries = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    assert collapse_routes(entries) == ["10.0.0.0/22"]


def test_keeps_non_adjacent():
    entries = ["10.0.0.0/24", "192.168.0.0/24"]
    out = sorted(collapse_routes(entries))
    assert out == ["10.0.0.0/24", "192.168.0.0/24"]


def test_dedupes_overlapping():
    entries = ["10.0.0.0/24", "10.0.0.0/25", "10.0.0.0/24"]
    assert collapse_routes(entries) == ["10.0.0.0/24"]


def test_ipv4_and_ipv6_split_correctly():
    entries = ["10.0.0.0/24", "10.0.1.0/24", "2001:db8::/33", "2001:db8:8000::/33"]
    out = collapse_routes(entries)
    assert "10.0.0.0/23" in out
    assert "2001:db8::/32" in out
    assert len(out) == 2


def test_invalid_entries_dropped():
    entries = ["1.2.3.4", "garbage", "9999.9.9.9", "::1"]
    out = collapse_routes(entries)
    assert "1.2.3.4/32" in out
    assert "::1/128" in out
    assert "garbage" not in str(out)


def test_real_world_compression_ratio():
    # 256 contiguous /24s should collapse to one /16
    entries = [f"10.0.{i}.0/24" for i in range(256)]
    assert collapse_routes(entries) == ["10.0.0.0/16"]
