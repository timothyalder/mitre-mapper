import json
import threading

from mitre_mapper.allocations import Allocations


def test_peek_never_writes_and_allocate_is_sequential(tmp_path):
    path = tmp_path / "allocations.json"
    alloc = Allocations(path)
    assert alloc.peek("software", "malware--a") == "SX0001"
    assert not path.exists()
    assert alloc.allocate("software", "malware--a", "A", "run1") == "SX0001"
    assert alloc.allocate("software", "tool--b", "B", "run2") == "SX0002"
    assert alloc.allocate("group", "intrusion-set--g", "G", "run2") == "GX0001"
    assert alloc.peek("software", "tool--c") == "SX0003"


def test_allocate_is_idempotent_per_stix_id(tmp_path):
    alloc = Allocations(tmp_path / "a.json")
    first = alloc.allocate("software", "malware--a", "A", "run1")
    assert alloc.allocate("software", "malware--a", "A renamed", "run9") == first
    assert alloc.peek("software", "malware--a") == first
    assert alloc.lookup(first) == {"stix_id": "malware--a", "name": "A", "first_run": "run1"}


def test_ids_are_never_reused_and_lookup_misses(tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "software": {"SX0007": {"stix_id": "malware--x", "name": "X", "first_run": "r"}},
        "groups": {},
    }))
    alloc = Allocations(path)
    assert alloc.peek("software", "malware--new") == "SX0008"
    assert alloc.lookup("SX0001") is None and alloc.lookup("GX0001") is None


def test_write_is_atomic_json_and_leaves_no_temp_files(tmp_path):
    alloc = Allocations(tmp_path / "a.json")
    alloc.allocate("software", "malware--a", "A", "r")
    data = json.loads((tmp_path / "a.json").read_text())
    assert data["schema_version"] == 1 and "SX0001" in data["software"]
    assert [p.name for p in tmp_path.glob("*.tmp")] == []


def test_concurrent_allocations_get_distinct_ids(tmp_path):
    alloc = Allocations(tmp_path / "a.json")
    ids: list[str] = []
    threads = [
        threading.Thread(target=lambda i=i: ids.append(alloc.allocate("software", f"malware--{i}", "n", "r")))
        for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(ids) == [f"SX{n:04d}" for n in range(1, 9)]


def test_peek_many_hands_out_consecutive_ids_without_writing(tmp_path):
    path = tmp_path / "a.json"
    alloc = Allocations(path)
    alloc.allocate("group", "intrusion-set--a", "A", "r")
    out = alloc.peek_many("group", ["intrusion-set--b", "intrusion-set--a", "intrusion-set--c"])
    assert out == {
        "intrusion-set--a": "GX0001",
        "intrusion-set--b": "GX0002",
        "intrusion-set--c": "GX0003",
    }
    assert alloc.peek("group", "intrusion-set--b") == "GX0002"
    assert "GX0002" not in path.read_text()


def test_definition_sha256_is_stored_once_and_optional(tmp_path):
    alloc = Allocations(tmp_path / "a.json")
    alloc.allocate("group", "intrusion-set--g", "G", "run1", definition_sha256="abc")
    alloc.allocate("group", "intrusion-set--g", "G", "run2", definition_sha256="def")
    rec = alloc.record_for("group", "intrusion-set--g")
    assert rec == {
        "attack_id": "GX0001", "stix_id": "intrusion-set--g", "name": "G",
        "first_run": "run1", "definition_sha256": "abc",
    }
    alloc.allocate("software", "malware--a", "A", "r")
    assert "definition_sha256" not in alloc.lookup("SX0001")
    assert alloc.record_for("group", "intrusion-set--zzz") is None
