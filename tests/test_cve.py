import json
import re
import analyst_tool_cve as C


KEV = {"vulnerabilities": [{
    "cveID": "CVE-2021-44228",
    "vulnerabilityName": "Log4Shell",
    "dateAdded": "2021-12-10",
    "requiredAction": "Apply updates",
    "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
}]}

NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "AV:N/AC:L"}}]},
    "published": "2021-12-10T10:15:00",
    "references": [{"url": "https://example/a"}, {"url": "https://example/b"}],
}}]}


def test_cve_regex():
    assert re.match(C.cve_regex, "CVE-2021-44228", re.I)
    assert re.match(C.cve_regex, "cve-1999-0001", re.I)
    assert not re.match(C.cve_regex, "CVE-21-1")
    assert not re.match(C.cve_regex, "notacve")


def test_parse_kev():
    d = C._parse_kev(json.dumps(KEV))
    assert "CVE-2021-44228" in d
    assert d["CVE-2021-44228"]["vulnerabilityName"] == "Log4Shell"
    assert C._parse_kev("not json") == {}


def test_parse_nvd():
    p = C.parse_nvd(NVD)
    assert p["cvss"] == 10.0
    assert p["severity"] == "CRITICAL"
    assert "Log4j2" in p["description"]
    assert p["references"] == ["https://example/a", "https://example/b"]
    assert p["published"].startswith("2021-12-10")


def test_parse_nvd_empty():
    assert C.parse_nvd({"vulnerabilities": []}) is None
    assert C.parse_nvd(None) is None
