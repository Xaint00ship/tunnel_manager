from tunnel_manager.parser import parse_route_list


def test_empty():
    assert parse_route_list("") == {}


def test_plain_ips_with_header():
    text = "Meta\n1.2.3.4\n5.6.7.8\n"
    assert parse_route_list(text) == {"Meta": ["1.2.3.4", "5.6.7.8"]}


def test_cidr():
    assert parse_route_list("Twitter\n10.0.0.0/8\n") == {"Twitter": ["10.0.0.0/8"]}


def test_windows_route_add_converts_to_cidr():
    text = "Other\nROUTE ADD 1.2.3.0 MASK 255.255.255.0 0.0.0.0\n"
    assert parse_route_list(text) == {"Other": ["1.2.3.0/24"]}


def test_slashslash_comment_skipped():
    text = "Section\n// commented\n1.2.3.4\n"
    assert parse_route_list(text) == {"Section": ["1.2.3.4"]}


def test_hash_prefix_stripped_from_header():
    text = "## Kino.pub\n1.2.3.4\n"
    assert parse_route_list(text) == {"Kino.pub": ["1.2.3.4"]}


def test_global_dedup():
    text = "S1\n1.1.1.1\n1.1.1.1\nS2\n1.1.1.1\n2.2.2.2\n"
    # Duplicate IPs are removed globally (first occurrence wins on section)
    assert parse_route_list(text) == {"S1": ["1.1.1.1"], "S2": ["2.2.2.2"]}


def test_multiple_ips_one_line():
    text = "S\n1.1.1.1, 2.2.2.2, 3.3.3.3\n"
    assert parse_route_list(text) == {"S": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}


def test_default_section_when_no_header():
    text = "1.1.1.1\n"
    assert parse_route_list(text) == {"Other": ["1.1.1.1"]}


def test_mixed_real_world_snippet():
    text = (
        "Meta (Instagram, Facebook)\n"
        "// Узлы\n"
        "157.240.253.174, 157.240.253.172\n"
        "\n"
        "// Подсети\n"
        "213.102.128.0/24\n"
        "# Discord\n"
        "162.159.128.233\n"
        "ROUTE ADD 104.18.124.0 MASK 255.255.255.0 0.0.0.0\n"
    )
    r = parse_route_list(text)
    assert r["Meta (Instagram, Facebook)"] == [
        "157.240.253.174", "157.240.253.172", "213.102.128.0/24"
    ]
    assert r["Discord"] == ["162.159.128.233", "104.18.124.0/24"]
