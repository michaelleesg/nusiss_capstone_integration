from ner.regex_patterns import CVE_PATTERN, DOMAIN_PATTERN


def test_expected():
    assert CVE_PATTERN.search("CVE-2025-12345")
    assert not CVE_PATTERN.search("CVE-9999-XXXX")
    assert DOMAIN_PATTERN.search("example.com")
    assert not DOMAIN_PATTERN.search("bad..com")
