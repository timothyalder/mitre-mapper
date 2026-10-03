from mitre_mapper.search import search


def test_technique_search_finds_location_tracking(mobile_store):
    hits = search(mobile_store, "technique", "track device location gps", k=5)
    assert "T1430" in [h.attack_id for h in hits]
    assert hits == sorted(hits, key=lambda h: h.score, reverse=True)
    assert all(h.score > 0 and h.stix_id.startswith("attack-pattern--") for h in hits)


def test_software_search_matches_alias_and_name(mobile_store):
    hits = search(mobile_store, "software", "Pegasus for iOS", k=3)
    assert hits[0].attack_id == "S0289"


def test_group_search_uses_aliases(mobile_store):
    group = next(g for g in mobile_store.objects("intrusion-set") if g.get("aliases", [])[1:])
    alias = group["aliases"][-1]
    ids = [h.attack_id for h in search(mobile_store, "group", alias, k=5)]
    assert mobile_store.attack_id(group) in ids


def test_nonsense_and_empty_queries_return_nothing(mobile_store):
    assert search(mobile_store, "technique", "zzqxv qqwwjj") == []
    assert search(mobile_store, "technique", "   ") == []


def test_k_limits_and_inactive_excluded(mobile_store):
    hits = search(mobile_store, "technique", "keychain", k=2)
    assert len(hits) <= 2
    for h in hits:
        assert not mobile_store.get_by_stix_id(h.stix_id).get("revoked")
    # T1579 (revoked Keychain) never appears; its live successor may
    assert "T1579" not in [h.attack_id for h in search(mobile_store, "technique", "keychain", k=20)]
