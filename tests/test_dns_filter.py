BLOCK = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adnxs.com", "adsrvr.org", "applovin.com", "unityads.unity3d.com",
    "ironsrc.com", "vungle.com", "mintegral.com", "inmobi.com",
    "amazon-adsystem.com", "criteo.com", "taboola.com", "outbrain.com",
}

def is_blocked(host):
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in BLOCK)

def test_known_ad_domains_blocked():
    assert is_blocked("doubleclick.net")
    assert is_blocked("pagead.googlesyndication.com")
    assert is_blocked("sdk.applovin.com")

def test_parent_domain_not_overblocked():
    assert not is_blocked("notdoubleclick.net")
    assert not is_blocked("example.com")

def test_non_ad_service_not_blocked():
    assert not is_blocked("api.example.com")
    assert not is_blocked("google.com")

if __name__ == "__main__":
    test_known_ad_domains_blocked()
    test_parent_domain_not_overblocked()
    test_non_ad_service_not_blocked()
    print("3 host-side policy tests passed")
