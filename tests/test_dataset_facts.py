"""Pin the PLAN.md §2 dataset facts that later code relies on."""

import hashlib
import json
from pathlib import Path

import pytest
from mitreattack.stix20 import MitreAttackData

DATASETS = Path(__file__).resolve().parents[1] / "datasets"
MANIFEST = json.loads((DATASETS / "MANIFEST.json").read_text())

PEGASUS_GOLD = {
    "T1636.002", "T1421", "T1644", "T1456", "T1404", "T1645", "T1426", "T1636.003",
    "T1636.004", "T1660", "T1430", "T1664", "T1409", "T1429", "T1658",
}


@pytest.fixture(scope="session")
def mobile() -> MitreAttackData:
    return MitreAttackData(str(DATASETS / "mobile-attack.json"))


@pytest.mark.parametrize("domain", sorted(MANIFEST["domains"]))
def test_manifest_sha256_matches_local_bundle(domain):
    digest = hashlib.sha256((DATASETS / f"{domain}.json").read_bytes()).hexdigest()
    assert digest == MANIFEST["domains"][domain]["sha256"]


def test_pegasus_gold_techniques(mobile):
    software = mobile.get_object_by_attack_id("S0289", "malware")
    used = mobile.get_techniques_used_by_software(software.id)
    ids = {mobile.get_attack_id(u["object"].id) for u in used}
    assert ids == PEGASUS_GOLD


@pytest.mark.slow
def test_attack_ids_are_not_unique_so_lookups_are_type_scoped():
    enterprise = MitreAttackData(str(DATASETS / "enterprise-attack.json"))
    claimants = [
        o for o in json.loads((DATASETS / "enterprise-attack.json").read_text())["objects"]
        if any(r.get("external_id") == "T1212" for r in o.get("external_references", []))
    ]
    assert {o["type"] for o in claimants} == {"attack-pattern", "course-of-action"}
    technique = enterprise.get_object_by_attack_id("T1212", "attack-pattern")
    assert technique.type == "attack-pattern"
