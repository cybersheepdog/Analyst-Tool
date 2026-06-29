import time
import analyst_tool_utilities as u


def test_parse_collapses_and_skips_v6():
    ranges = u._parse_vpn_ranges("172.16.0.0/16\n172.16.5.0/24\n2001:db8::/32\n# comment\n\n")
    # overlapping /24 collapsed into the /16; IPv6 + comment + blank skipped
    assert len(ranges) == 1


def test_is_vpn_ip_boundaries():
    u._vpn_ranges = u._parse_vpn_ranges("10.0.0.0/24\n10.0.2.0/24\n192.168.5.0/30\n")
    u._vpn_loaded_at = time.time()
    assert u.is_vpn_ip("10.0.0.0")      # network address
    assert u.is_vpn_ip("10.0.0.255")    # broadcast
    assert u.is_vpn_ip("10.0.0.5")
    assert not u.is_vpn_ip("10.0.1.5")  # gap
    assert u.is_vpn_ip("10.0.2.10")
    assert u.is_vpn_ip("192.168.5.2")
    assert not u.is_vpn_ip("192.168.5.4")  # outside /30
    assert not u.is_vpn_ip("8.8.8.8")
    assert not u.is_vpn_ip("not-an-ip")
    assert not u.is_vpn_ip("2001:db8::1")  # IPv6 -> no v4 match


def test_is_datacenter_ip():
    u._datacenter_ranges = u._parse_vpn_ranges("203.0.113.0/24\n")
    u._datacenter_loaded_at = time.time()
    assert u.is_datacenter_ip("203.0.113.50")
    assert not u.is_datacenter_ip("8.8.8.8")


def test_vpn_provider_from_text():
    # catches list-missed VPNs by WhoIs org / ASN name
    assert u.vpn_provider_from_text("TEFINCOMSA, PA") == "NordVPN"
    assert u.vpn_provider_from_text("Mullvad VPN AB") == "Mullvad"   # specific beats generic
    assert u.vpn_provider_from_text("Proton AG") == "Proton VPN"
    assert u.vpn_provider_from_text("Some VPN Services LLC") == "VPN provider"
    # generic hosters are NOT VPN-flagged (the datacenter check covers those)
    assert u.vpn_provider_from_text("M247 Europe SRL") is None
    assert u.vpn_provider_from_text("Datacamp Limited") is None
    assert u.vpn_provider_from_text("Google LLC") is None
    assert u.vpn_provider_from_text(None) is None
