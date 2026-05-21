from tunnel_manager.backends.base import VPNInfo
from tunnel_manager.backends.linux import LinuxBackend
from tunnel_manager.backends.macos import MacOSBackend


def test_linux_parse_default_routes_scores_vpn_and_isp():
    out = (
        "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        "default dev wg0 proto static metric 50\n"
    )

    vpn, isp_gw, isp_if = LinuxBackend()._parse_default_routes(out)

    assert vpn == VPNInfo(
        interface="wg0", gateway=None, local_gateway="192.168.1.1", local_interface="eth0"
    )
    assert isp_gw == "192.168.1.1"
    assert isp_if == "eth0"


def test_linux_vpn_from_links_uses_up_vpn_like_interface():
    links = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n7: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1420\n"

    vpn = LinuxBackend()._vpn_from_links(links, "192.168.1.1", "eth0")

    assert vpn == VPNInfo(
        interface="tun0", gateway=None, local_gateway="192.168.1.1", local_interface="eth0"
    )


def test_macos_parse_netstat_defaults_scores_vpn_and_isp():
    out = (
        "Destination        Gateway            Flags        Netif\n"
        "default            192.168.1.1        UGScg        en0\n"
        "default            link#20            UCS          utun4\n"
    )

    vpn = MacOSBackend()._parse_netstat_defaults(out)

    assert vpn == VPNInfo(
        interface="utun4", gateway=None, local_gateway="192.168.1.1", local_interface="en0"
    )


def test_macos_routes_from_netstat_filters_iface_and_defaults():
    out = (
        "Destination        Gateway            Flags        Netif\n"
        "default            link#20            UCS          utun4\n"
        "10.0.0.0/24        link#20            UCS          utun4\n"
        "192.168.0.0/24     link#4             UCS          en0\n"
        "2001:db8::/32      link#20            UCS          utun4\n"
    )

    assert MacOSBackend._routes_from_netstat(out, "utun4") == [
        "10.0.0.0/24",
        "2001:db8::/32",
    ]
