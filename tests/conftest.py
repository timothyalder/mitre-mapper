"""Session-scoped dataset fixtures. Enterprise loads in ~12 s, so use it only in slow tests."""

from pathlib import Path

import pytest

from mitre_mapper.store import AttackStore, DomainStore


@pytest.fixture(scope="session")
def datasets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets"


@pytest.fixture(scope="session")
def attack_store(datasets_dir) -> AttackStore:
    return AttackStore(datasets_dir)


@pytest.fixture(scope="session")
def mobile_store(attack_store) -> DomainStore:
    return attack_store.domain("mobile-attack")
