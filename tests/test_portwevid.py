import io
import sys
import analyst_tool_portwevid as P

SAMPLE = ("Service Name,Port Number,Transport Protocol,Description\n"
          "https,443,tcp,HTTP over TLS\n"
          "ssh,22,tcp,The Secure Shell (SSH)\n"
          "domain,53,udp,Domain Name Server\n"
          "rangey,8000-8002,tcp,a range we skip\n")


def test_iana_parse_skips_ranges():
    d = P._parse_iana_csv(SAMPLE)
    assert (443, "tcp") in d and (22, "tcp") in d and (53, "udp") in d
    assert all("-" not in str(port) for port, _ in d)   # ranges skipped


def test_lookup_port_and_notable():
    P._iana = P._parse_iana_csv(SAMPLE)
    assert "https" in P.lookup_port(443)["service"]
    notable = P.lookup_port(4444)
    assert notable["notable"]["malicious"] is True
    assert "Metasploit" in notable["notable"]["use"]


def test_lookup_event():
    assert P.lookup_event(4625)["name"].startswith("An account failed")
    assert P.lookup_event("1")["log"] == "Sysmon"
    assert P.lookup_event(99999) is None


def test_print_port_and_wevid_output():
    P._iana = P._parse_iana_csv(SAMPLE)

    def grab(n):
        buf = io.StringIO(); real = sys.stdout; sys.stdout = buf
        try:
            P.print_port_and_wevid(n)
        finally:
            sys.stdout = real
        return buf.getvalue()

    out = grab("4444")
    assert "Metasploit" in out and "port.php?port=4444" in out
    out2 = grab("4625")
    assert "failed to log on" in out2 and "ultimatewindowssecurity" in out2
