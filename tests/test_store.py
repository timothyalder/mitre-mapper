import pytest

from mitre_mapper.store import AttackStore, get_store, is_inactive

PEGASUS_GOLD = {
    "T1636.002", "T1421", "T1644", "T1456", "T1404", "T1645", "T1426", "T1636.003",
    "T1636.004", "T1660", "T1430", "T1664", "T1409", "T1429", "T1658",
}


def test_is_inactive():
    assert is_inactive({"revoked": True})
    assert is_inactive({"x_mitre_deprecated": True})
    assert not is_inactive({"revoked": False, "x_mitre_deprecated": False})
    assert not is_inactive({})


def test_lookup_live_technique(mobile_store):
    result = mobile_store.lookup("T1430", "attack-pattern")
    assert result.obj["name"] == "Location Tracking"
    assert result.redirected_from is None and not result.inactive


def test_lookup_returns_copies(mobile_store):
    first = mobile_store.lookup("T1430", "attack-pattern").obj
    first["name"] = "mutated"
    assert mobile_store.lookup("T1430", "attack-pattern").obj["name"] == "Location Tracking"


def test_revoked_redirects_to_successor(mobile_store):
    result = mobile_store.lookup("T1579", "attack-pattern")
    assert mobile_store.attack_id(result.obj) == "T1634.001"
    assert result.obj["name"] == "Keychain"
    assert result.redirected_from == "T1579"


def test_include_inactive_returns_revoked_object(mobile_store):
    result = mobile_store.lookup("T1579", "attack-pattern", include_inactive=True)
    assert result.obj["revoked"] is True and result.inactive
    assert result.redirected_from is None


def test_deprecated_not_revoked_has_no_successor_and_is_hidden(mobile_store):
    dead = [
        o for o in mobile_store.objects("attack-pattern", include_inactive=True)
        if o.get("x_mitre_deprecated") and not o.get("revoked")
    ]
    assert dead  # 13 such mobile techniques (deprecated, `revoked` false)
    attack_id = mobile_store.attack_id(dead[0])
    assert mobile_store.lookup(attack_id, "attack-pattern").obj is None


def test_unknown_and_cross_domain_ids_are_none(mobile_store):
    assert mobile_store.lookup("T9999", "attack-pattern").obj is None
    assert mobile_store.lookup("T1059.001", "attack-pattern").obj is None  # enterprise id


def test_lookup_is_type_scoped(mobile_store):
    assert mobile_store.lookup("S0289", "attack-pattern").obj is None
    assert mobile_store.lookup("S0289", "malware").obj["name"] == "Pegasus for iOS"


def test_objects_exclude_inactive_by_default(mobile_store):
    live = mobile_store.objects("attack-pattern")
    everything = mobile_store.objects("attack-pattern", include_inactive=True)
    assert 0 < len(live) < len(everything)
    assert not any(is_inactive(o) for o in live)


def test_get_by_stix_id(mobile_store):
    obj = mobile_store.lookup("S0289", "malware").obj
    assert mobile_store.get_by_stix_id(obj["id"])["name"] == "Pegasus for iOS"
    assert mobile_store.get_by_stix_id("malware--00000000-0000-4000-8000-000000000000") is None


def test_software_techniques_matches_pegasus_gold(mobile_store):
    assert set(mobile_store.software_techniques("S0289")) == PEGASUS_GOLD
    assert mobile_store.software_techniques("S9999") == []


def test_attack_id_matches_ics_source_name(attack_store):
    ics = attack_store.domain("ics-attack")
    odd = [
        o for t in ("malware", "tool")
        for o in ics.objects(t, include_inactive=True)
        if o["external_references"][0]["source_name"] == "mitre-ics-attack"
    ]
    assert odd and ics.attack_id(odd[0]).startswith("S")


def test_domain_store_is_cached_and_missing_dataset_raises(attack_store, tmp_path):
    assert attack_store.domain("mobile-attack") is attack_store.domain("mobile-attack")
    with pytest.raises(FileNotFoundError):
        AttackStore(tmp_path).domain("mobile-attack")


def test_get_store_caches_per_directory(datasets_dir):
    assert get_store(datasets_dir) is get_store(datasets_dir)


@pytest.mark.slow
def test_enterprise_powershell_revoked_redirect(datasets_dir):
    import time

    store = AttackStore(datasets_dir)
    start = time.perf_counter()
    enterprise = store.domain("enterprise-attack")
    print(f"enterprise load: {time.perf_counter() - start:.1f}s")
    result = enterprise.lookup("T1086", "attack-pattern")
    assert enterprise.attack_id(result.obj) == "T1059.001"
    assert result.redirected_from == "T1086"
    # ids are not unique within a bundle: T1212 is a live technique + deprecated course-of-action
    assert enterprise.lookup("T1212", "attack-pattern").obj["type"] == "attack-pattern"
