"""Construct minted STIX objects (PLAN §3.4, D14).

Everything is built with ``stix2.v20`` classes (``allow_custom=True`` for the
``x_mitre_*`` properties) and serialized with ``json.loads(obj.serialize())``;
no STIX dict is written by hand. Ids are deterministic and v4-shaped because
stix2 rejects uuid5 for STIX 2.0.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import stix2.v20 as stix

from .allocations import Allocations
from .intake import INTAKE_SOURCE
from .models import ExternalReference, IntakeSpec, MappingProposal, TechniqueMapping
from .store import AttackStore

MITRE_IDENTITY = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
MITRE_MARKING = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
ATTACK_SPEC_VERSION = "3.3.0"
SITE = "https://attack.mitre.org"

_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def deterministic_uuid4(*parts: str, namespace: str = "mitre-mapper") -> uuid.UUID:
    digest = hashlib.sha256((namespace + ":" + ":".join(parts)).encode()).digest()[:16]
    return uuid.UUID(bytes=digest, version=4)


def _normalize(name: str) -> str:
    return " ".join(name.lower().split())


def software_stix_id(name: str, type: str) -> str:
    """Keyed on normalized name + type."""
    return f"{type}--{deterministic_uuid4(_normalize(name), type)}"


def relationship_stix_id(rel_type: str, source_ref: str, target_ref: str) -> str:
    return f"relationship--{deterministic_uuid4(rel_type, source_ref, target_ref)}"


def _ref_dict(ref: ExternalReference) -> dict[str, str]:
    return ref.model_dump(exclude_none=True)


def _serialize(obj: Any) -> dict[str, Any]:
    return json.loads(obj.serialize())


def _check_timestamp(created: str) -> None:
    if not _TIMESTAMP.match(created):
        raise ValueError(f"timestamp must be YYYY-MM-DDTHH:MM:SS.sssZ, got {created!r}")


def mint_software(
    spec: IntakeSpec, attack_id: str, domains: list[str], created: str
) -> dict[str, Any]:
    """Build the malware/tool SDO for ``spec`` with MITRE conventions."""
    _check_timestamp(created)
    aliases = [spec.name, *(a for a in spec.aliases if a != spec.name)]
    custom: dict[str, Any] = {
        "x_mitre_modified_by_ref": MITRE_IDENTITY,
        "x_mitre_deprecated": False,
        "x_mitre_domains": sorted(set(domains)),
        "x_mitre_version": "1.0",
        "x_mitre_attack_spec_version": ATTACK_SPEC_VERSION,
        "x_mitre_aliases": aliases,
    }
    if spec.platforms:
        custom["x_mitre_platforms"] = list(spec.platforms)
    cls = stix.Malware if spec.type == "malware" else stix.Tool
    obj = cls(
        id=software_stix_id(spec.name, spec.type),
        created=created,
        modified=created,
        created_by_ref=MITRE_IDENTITY,
        object_marking_refs=[MITRE_MARKING],
        name=spec.name,
        description=spec.body or f"{spec.name} is a {spec.type}.",
        labels=[spec.type],
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": f"{SITE}/software/{attack_id}",
            },
            *(_ref_dict(r) for r in spec.references),
        ],
        allow_custom=True,
        **custom,
    )
    return _serialize(obj)


def mint_technique_relationship(
    software: dict[str, Any],
    technique: dict[str, Any],
    mapping: TechniqueMapping,
    references: list[ExternalReference],
    created: str,
) -> dict[str, Any]:
    """``software uses technique``; description = rationale + a citation per matched source.

    ``references`` is the pool to cite from; only those named by the mapping's
    evidence are attached. A user-asserted mapping with no evidence cites the whole pool.
    """
    _check_timestamp(created)
    sources = {e.source_name for e in mapping.evidence}
    cited = [r for r in references if r.source_name in sources]
    if mapping.user_asserted and not cited:
        cited = list(references)
    markers = "".join(f"(Citation: {r.source_name})" for r in cited)
    obj = stix.Relationship(
        id=relationship_stix_id("uses", software["id"], technique["id"]),
        created=created,
        modified=created,
        created_by_ref=MITRE_IDENTITY,
        object_marking_refs=[MITRE_MARKING],
        relationship_type="uses",
        source_ref=software["id"],
        target_ref=technique["id"],
        description=f"{mapping.rationale.strip()}{markers}",
        external_references=[_ref_dict(r) for r in cited],
        revoked=False,
        allow_custom=True,
        x_mitre_modified_by_ref=MITRE_IDENTITY,
        x_mitre_deprecated=False,
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
    )
    data = _serialize(obj)
    data.setdefault("revoked", False)  # stix2 drops a False default; real uses-rels all carry it
    return data


@dataclass
class MintResult:
    software: dict[str, Any]
    objects: list[dict[str, Any]]
    by_domain: dict[str, list[dict[str, Any]]]
    allocations: dict[str, str] = field(default_factory=dict)  # ATT&CK id -> stix id


def build_objects(
    spec: IntakeSpec,
    proposals: dict[str, MappingProposal],
    store: AttackStore,
    allocations: Allocations,
    created: str,
    *,
    commit: bool,
    run_id: str | None = None,
) -> MintResult:
    """Mint one software object plus its technique relationships, partitioned by domain.

    ``commit=False`` previews the SX id (``peek``); ``commit=True`` allocates it.
    Unresolvable techniques are skipped; lint E002 reports them.
    """
    if commit and not run_id:
        raise ValueError("commit=True requires run_id")
    stix_id = software_stix_id(spec.name, spec.type)
    if commit:
        assert run_id is not None
        attack_id = allocations.allocate("software", stix_id, spec.name, run_id)
    else:
        attack_id = allocations.peek("software", stix_id)

    accepted = [d for d, p in proposals.items() if not p.declined] or list(proposals)
    software = mint_software(spec, attack_id, sorted(accepted), created)
    pool = [
        *spec.references,
        ExternalReference(
            source_name=INTAKE_SOURCE,
            description=f"Asserted by the user in the intake file for {spec.name}.",
        ),
    ]

    by_domain: dict[str, list[dict[str, Any]]] = {}
    for domain, proposal in sorted(proposals.items()):
        objs = [software]
        if not proposal.declined:
            domain_store = store.domain(domain)
            for mapping in proposal.techniques:
                technique = domain_store.lookup(mapping.technique_id, "attack-pattern").obj
                if technique is None:
                    continue
                objs.append(
                    mint_technique_relationship(software, technique, mapping, pool, created)
                )
        by_domain[domain] = objs

    # Software is shared across domains; keep one copy of each object.
    objects = list({o["id"]: o for objs in by_domain.values() for o in objs}.values())
    return MintResult(software, objects, by_domain, {attack_id: software["id"]})
