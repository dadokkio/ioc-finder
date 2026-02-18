from ioc_finder import find_iocs


def test_include_positions_domains():
    text = "example.com"
    results = find_iocs(text, include_positions=True)
    assert results["domains"] == [{"value": "example.com", "positions": [(0, 11)]}]


def test_include_positions_ipv4s():
    text = "test test 22.11 1.1.1.1"
    results = find_iocs(text, include_positions=True)
    assert results["ipv4s"] == [{"value": "1.1.1.1", "positions": [(16, 23)]}]


def test_include_positions_multiple_same_ioc():
    text = "example.com xxx example.com"
    results = find_iocs(text, include_positions=True)
    assert results["domains"] == [{"value": "example.com", "positions": [(0, 11), (16, 27)]}]


def test_include_positions_multiple_different_iocs():
    text = "example.com 1.1.1.1"
    results = find_iocs(text, include_positions=True)
    assert results["domains"] == [{"value": "example.com", "positions": [(0, 11)]}]
    assert results["ipv4s"] == [{"value": "1.1.1.1", "positions": [(12, 19)]}]


def test_include_positions_urls():
    text = "https://example.com"
    results = find_iocs(text, include_positions=True)
    assert results["urls"] == [{"value": "https://example.com", "positions": [(0, 19)]}]


def test_include_positions_email():
    text = "test@example.com"
    results = find_iocs(text, include_positions=True)
    assert results["email_addresses"] == [{"value": "test@example.com", "positions": [(0, 16)]}]


def test_include_positions_registry_keys():
    text = r"HKLM\SOFTWARE\Microsoft\Windows"
    results = find_iocs(text, include_positions=True)
    assert results["registry_key_paths"] == [{"value": r"HKLM\SOFTWARE\Microsoft\Windows", "positions": [(0, 31)]}]


def test_include_positions_hashes():
    text = "a" * 32
    results = find_iocs(text, include_positions=True)
    assert results["md5s"] == [{"value": "a" * 32, "positions": [(0, 32)]}]


def test_include_positions_attack_mitigations():
    text = "M1036"
    results = find_iocs(text, include_positions=True)
    assert results["attack_mitigations"]["enterprise"] == [{"value": "M1036", "positions": [(0, 5)]}]


def test_include_positions_cves():
    text = "CVE-2020-1234"
    results = find_iocs(text, include_positions=True)
    assert results["cves"] == [{"value": "CVE-2020-1234", "positions": [(0, 13)]}]


def test_include_positions_imphashes():
    text = "imphash 18ddf28a71089acdbab5038f58044c0a"
    results = find_iocs(text, include_positions=True)
    assert results["imphashes"] == [{"value": "18ddf28a71089acdbab5038f58044c0a", "positions": [(8, 40)]}]


def test_include_positions_authentihashes():
    text = "authentihash 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4"
    results = find_iocs(text, include_positions=True)
    assert results["authentihashes"] == [{"value": "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4", "positions": [(13, 77)]}]


def test_include_positions_ipv6s():
    text = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    results = find_iocs(text, include_positions=True)
    assert results["ipv6s"] == [{"value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "positions": [(0, 39)]}]


def test_include_positions_cidrs():
    text = "192.168.1.0/24"
    results = find_iocs(text, include_positions=True)
    assert results["ipv4_cidrs"] == [{"value": "192.168.1.0/24", "positions": [(0, 14)]}]


def test_include_positions_bitcoin():
    text = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    results = find_iocs(text, include_positions=True)
    assert results["bitcoin_addresses"] == [{"value": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "positions": [(0, 34)]}]


def test_include_positions_monero():
    text = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjRPDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    results = find_iocs(text, include_positions=True)
    assert results["monero_addresses"] == [{"value": "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjRPDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "positions": [(0, 95)]}]


def test_include_positions_mac_addresses():
    text = "00:00:5e:00:53:af"
    results = find_iocs(text, include_positions=True)
    assert results["mac_addresses"] == [{"value": "00:00:5e:00:53:af", "positions": [(0, 17)]}]


def test_include_positions_ssdeep():
    text = "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"
    results = find_iocs(text, include_positions=True)
    assert results["ssdeeps"] == [{"value": "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U", "positions": [(0, 75)]}]


def test_include_positions_xmpp():
    text = "foo@swissjabber.de"
    results = find_iocs(text, include_positions=True)
    assert results["xmpp_addresses"] == [{"value": "foo@swissjabber.de", "positions": [(0, 18)]}]


def test_include_positions_google_ids():
    text = "pub-1234567890123456 UA-123456-1"
    results = find_iocs(text, include_positions=True)
    assert results["google_adsense_publisher_ids"] == [{"value": "pub-1234567890123456", "positions": [(0, 20)]}]
    assert results["google_analytics_tracker_ids"] == [{"value": "UA-123456-1", "positions": [(21, 32)]}]


def test_include_positions_user_agents():
    text = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    results = find_iocs(text, include_positions=True)
    assert results["user_agents"] == [{"value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "positions": [(0, 41)]}]


def test_include_positions_tlp():
    text = "TLP:WHITE"
    results = find_iocs(text, include_positions=True)
    assert results["tlp_labels"] == [{"value": "TLP:WHITE", "positions": [(0, 9)]}]


def test_include_positions_mixed_complex():
    text = "Check 1.1.1.1 and example.com inside text."
    results = find_iocs(text, include_positions=True)
    assert results["ipv4s"] == [{"value": "1.1.1.1", "positions": [(6, 13)]}]
    assert results["domains"] == [{"value": "example.com", "positions": [(18, 29)]}]


def test_include_positions_urls_complex():
    text = "Visit https://example.com/path?query=1 for info."
    results = find_iocs(text, include_positions=True)
    assert results["urls"] == [{"value": "https://example.com/path?query=1", "positions": [(6, 38)]}]


def test_include_positions_multiple_mixed_iocs_extended():
    text = "IP: 1.1.1.1, Domain: example.com, Email: test@test.com, URL: http://foo.bar"
    results = find_iocs(text, include_positions=True)
    assert results["ipv4s"] == [{"value": "1.1.1.1", "positions": [(4, 11)]}]

    # Check domains - example.com should be present with correct position
    # We filter for example.com because foo.bar might also be present due to URL parsing
    example_domain = [d for d in results["domains"] if d["value"] == "example.com"][0]
    assert example_domain == {"value": "example.com", "positions": [(21, 32)]}

    assert results["email_addresses"] == [{"value": "test@test.com", "positions": [(41, 54)]}]
    assert results["urls"] == [{"value": "http://foo.bar", "positions": [(61, 75)]}]


def test_include_positions_multiple_occurrences_mixed():
    text = "1.1.1.1 example.com 1.1.1.1 example.com"
    results = find_iocs(text, include_positions=True)
    assert results["ipv4s"] == [{"value": "1.1.1.1", "positions": [(0, 7), (20, 27)]}]
    assert results["domains"] == [{"value": "example.com", "positions": [(8, 19), (28, 39)]}]


def test_include_positions_defanged_and_encoded():
    # Defanged URL
    text = "hxxp://example.com"
    results = find_iocs(text, include_positions=True)
    # "hxxp" is replaced by "http" in prepare_text.
    # The text being parsed is "http://example.com".
    # The match is "http://example.com" at 0.
    # Length is 18.
    assert results["urls"] == [{"value": "http://example.com", "positions": [(0, 18)]}]

    # Encoded URL
    text = "http://example.com/foo%20bar"
    results = find_iocs(text, include_positions=True)
    # Length is 28.
    assert results["urls"] == [{"value": "http://example.com/foo%20bar", "positions": [(0, 28)]}]

    # URL with trailing char removed by clean
    text = "http://example.com)"
    results = find_iocs(text, include_positions=True)
    # "http://example.com)" length 19.
    # Cleaned: "http://example.com" length 18.
    # Position should be (0, 18).
    assert results["urls"] == [{"value": "http://example.com", "positions": [(0, 18)]}]