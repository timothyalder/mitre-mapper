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
from .groups import definition_sha256
from .intake import INTAKE_SOURCE
from .models import (
    ExternalReference,
    GroupMapping,
    IntakeSpec,
    MappingProposal,
    NewGroup,
    TechniqueMapping,
)
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


def group_stix_id(name: str) -> str:
    """Keyed on normalized name only, so the same user-defined group in two intake
    files collapses to one intrusion-set when deltas are combined."""
    return f"intrusion-set--{deterministic_uuid4(_normalize(name), 'intrusion-set')}"


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

    ``references`` is the pool to cite from. Agent-proposed mappings cite only the pooled
    sources named by their evidence; one with none gets NO external reference, so lint E004
    fires and the agent is told to cite evidence (never paper over it by citing the pool).
    User-asserted mappings cite the intake reference.
    """
    _check_timestamp(created)
    if mapping.user_asserted:
        cited = [_intake_reference(references, "Asserted by the user in the intake file.")]
    else:
        sources = {e.source_name for e in mapping.evidence}
        cited = [r for r in references if r.source_name in sources]
    markers = "".join(f"(Citation: {r.source_name})" for r in cited)
    extra: dict[str, Any] = {"external_references": [_ref_dict(r) for r in cited]} if cited else {}
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
        revoked=False,
        allow_custom=True,
        x_mitre_modified_by_ref=MITRE_IDENTITY,
        x_mitre_deprecated=False,
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
        **extra,
    )
    data = _serialize(obj)
    data.setdefault("revoked", False)  # stix2 drops a False default; real uses-rels all carry it
    return data


def _intake_reference(references: list[ExternalReference], description: str) -> ExternalReference:
    """The ``mitre-mapper intake`` reference from the pool (or a fresh one)."""
    return next(
        (r for r in references if r.source_name == INTAKE_SOURCE),
        ExternalReference(source_name=INTAKE_SOURCE, description=description),
    )


def mint_group(
    new: NewGroup,
    attack_id: str,
    domains: list[str],
    created: str,
    references: list[ExternalReference],
) -> dict[str, Any]:
    """Build the user-defined ``intrusion-set`` with MITRE conventions.

    Measured on v19.2 intrusion-sets: ``aliases`` is always present, ``aliases[0]`` is the
    name and the name is always in it; there is no ``x_mitre_aliases``; each alias (all but
    the name) has an external reference whose ``source_name`` is the alias and whose
    description is a citation. ``references`` follow the ``mitre-attack`` reference; the
    intake reference is appended if absent, and the alias references cite it.
    """
    _check_timestamp(created)
    refs = list(references)
    intake_ref = _intake_reference(refs, f"Defined by the user in the intake file as group {new.name}.")
    if intake_ref not in refs:
        refs.append(intake_ref)
    aliases = [new.name, *dict.fromkeys(a for a in new.aliases if a != new.name)]
    have = {r.source_name for r in refs}
    alias_refs = [
        ExternalReference(source_name=a, description=f"(Citation: {intake_ref.source_name})")
        for a in aliases[1:]
        if a not in have
    ]
    obj = stix.IntrusionSet(
        id=group_stix_id(new.name),
        created=created,
        modified=created,
        created_by_ref=MITRE_IDENTITY,
        object_marking_refs=[MITRE_MARKING],
        name=new.name,
        description=new.description,
        aliases=aliases,
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": f"{SITE}/groups/{attack_id}",
            },
            *(_ref_dict(r) for r in [*alias_refs, *refs]),
        ],
        allow_custom=True,
        x_mitre_modified_by_ref=MITRE_IDENTITY,
        x_mitre_deprecated=False,
        x_mitre_domains=sorted(set(domains)),
        x_mitre_version="1.0",
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
    )
    data = _serialize(obj)
    data.setdefault("revoked", False)  # every real intrusion-set carries it
    return data


def _uses_relationship(
    source: dict[str, Any],
    target: dict[str, Any],
    description: str,
    cited: list[ExternalReference],
    created: str,
) -> dict[str, Any]:
    _check_timestamp(created)
    markers = "".join(f"(Citation: {r.source_name})" for r in cited)
    extra: dict[str, Any] = {"external_references": [_ref_dict(r) for r in cited]} if cited else {}
    obj = stix.Relationship(
        id=relationship_stix_id("uses", source["id"], target["id"]),
        created=created,
        modified=created,
        created_by_ref=MITRE_IDENTITY,
        object_marking_refs=[MITRE_MARKING],
        relationship_type="uses",
        source_ref=source["id"],
        target_ref=target["id"],
        description=f"{description.strip()}{markers}",
        revoked=False,
        allow_custom=True,
        x_mitre_modified_by_ref=MITRE_IDENTITY,
        x_mitre_deprecated=False,
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
        **extra,
    )
    data = _serialize(obj)
    data.setdefault("revoked", False)
    return data


def mint_group_software_relationship(
    group: dict[str, Any],
    software: dict[str, Any],
    mapping: GroupMapping | None,
    references: list[ExternalReference],
    created: str,
) -> dict[str, Any]:
    """``group uses software``.

    Agent-proposed (``mapping`` not user-asserted): the description is the verbatim quote
    followed by ``(Citation: <source_name>)`` and the external reference is that source from
    ``references`` (a bare reference if the pool lacks it; lint E011 flags that case).
    User-asserted (or ``mapping is None``): cites the intake reference.
    """
    if mapping is not None and not mapping.user_asserted:
        # A source outside the pool is NOT cited (an empty ExternalReference is invalid
        # STIX); the relationship is minted without it so E004/E011 report the problem.
        cited = [r for r in references if r.source_name == mapping.source_name][:1]
        description = mapping.quote
    else:
        cited = [
            _intake_reference(
                references,
                f"Asserted by the user in the intake file for {software.get('name', '')}.",
            )
        ]
        description = (
            f"{group.get('name', 'The group')} is asserted by the user in the intake file "
            f"to use {software.get('name', 'this software')}."
        )
    return _uses_relationship(group, software, description, cited, created)


def mint_group_technique_relationship(
    group: dict[str, Any],
    technique: dict[str, Any],
    references: list[ExternalReference],
    created: str,
) -> dict[str, Any]:
    """User-asserted ``group uses technique`` (new-group ``techniques``); cites the intake file."""
    cited = [
        _intake_reference(references, f"Asserted by the user in the intake file for {group.get('name', '')}.")
    ]
    description = (
        f"{group.get('name', 'The group')} is asserted by the user in the intake file "
        f"to use {technique.get('name', 'this technique')}."
    )
    return _uses_relationship(group, technique, description, cited, created)


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
    """Mint the software, its technique relationships, group links and user-defined groups.

    Per non-declined domain: software + technique rels; ``uses`` rels from existing groups
    in ``proposal.groups`` (the group object itself already exists); and every
    ``spec.groups[].new`` as a GX group (D15: never minted any other way) with its
    group -> software rel and user-asserted group -> technique rels (only techniques that
    resolve in that domain). Same new-group name => same stix id and GX id across runs.

    ``commit=False`` previews SX/GX ids (``peek``); ``commit=True`` allocates them.
    Unresolvable techniques/groups are skipped; lint E002/E008 report them.
    """
    if commit and not run_id:
        raise ValueError("commit=True requires run_id")
    stix_id = software_stix_id(spec.name, spec.type)
    if commit:
        assert run_id is not None
        attack_id = allocations.allocate("software", stix_id, spec.name, run_id)
    else:
        attack_id = allocations.peek("software", stix_id)

    new_groups: dict[str, NewGroup] = {}  # stix id -> definition (first one wins)
    for entry in spec.groups:
        if entry.new is not None:
            new_groups.setdefault(group_stix_id(entry.new.name), entry.new)
    if all(p.declined for p in proposals.values()):
        new_groups = {}  # nothing is minted for a fully declined run, so allocate nothing
    if commit:
        assert run_id is not None
        group_ids = {
            sid: allocations.allocate(
                "group", sid, g.name, run_id, definition_sha256=definition_sha256(g)
            )
            for sid, g in new_groups.items()
        }
    else:
        group_ids = allocations.peek_many("group", list(new_groups))

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
            for group_mapping in proposal.groups:
                group = domain_store.lookup(group_mapping.group_id, "intrusion-set").obj
                if group is None:
                    continue
                objs.append(
                    mint_group_software_relationship(group, software, group_mapping, pool, created)
                )
            for sid, new in new_groups.items():
                group = mint_group(
                    new, group_ids[sid], sorted(accepted), created, [*new.references]
                )
                objs.append(group)
                objs.append(mint_group_software_relationship(group, software, None, pool, created))
                for technique_id in dict.fromkeys(new.techniques):
                    technique = domain_store.lookup(technique_id, "attack-pattern").obj
                    if technique is not None:
                        objs.append(
                            mint_group_technique_relationship(group, technique, pool, created)
                        )
        by_domain[domain] = objs

    # Software is shared across domains; keep one copy of each object.
    objects = list({o["id"]: o for objs in by_domain.values() for o in objs}.values())
    minted = {attack_id: software["id"]}
    minted.update({gx: sid for sid, gx in group_ids.items()})
    return MintResult(software, objects, by_domain, minted)
