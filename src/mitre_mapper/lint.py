"""Lint rules over a proposal and its previewed minted objects (PLAN §3.5).

ERROR blocks mint, WARN is logged, INFO is a measured fact. Wave 2 rules:
E001, E002, E008, E009, E010.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import stix2.v20 as stix
from mitreattack.stix20 import MitreAttackData

from .allocations import Allocations
from .models import LintFinding, MappingProposal, Severity
from .store import DomainStore

_STIX_ID = re.compile(
    r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SOFTWARE_TYPES = {"malware", "tool"}
_ATTACK_ID_FORMAT = {
    "malware": ("software", re.compile(r"^SX\d{4}$")),
    "tool": ("software", re.compile(r"^SX\d{4}$")),
    "intrusion-set": ("group", re.compile(r"^GX\d{4}$")),
}


@dataclass
class LintContext:
    proposal: MappingProposal
    domain: str
    store: DomainStore
    objects: list[dict[str, Any]]  # preview MintResult.by_domain[domain]
    allocations: Allocations
    evidence: dict[str, str] = field(default_factory=dict)


@dataclass
class LintRule:
    id: str
    severity: Severity
    description: str
    check: Callable[[LintContext], list[LintFinding]]


def _finding(rule: LintRule, message: str, target: str | None = None, **details: Any) -> LintFinding:
    return LintFinding(
        rule_id=rule.id, severity=rule.severity, message=message, target=target, details=details
    )


def _e001(ctx: LintContext) -> list[LintFinding]:
    if ctx.proposal.declined or ctx.proposal.techniques:
        return []
    return [
        _finding(
            RULES["E001"],
            "proposal has no technique relationships; map at least one technique "
            "or decline with declined=true and a rationale",
            ctx.domain,
        )
    ]


def _e002(ctx: LintContext) -> list[LintFinding]:
    """Technique must exist in this domain (type-scoped) and be active.

    details: technique_id, domain, reason ("not_found" | "revoked" | "deprecated"),
    and for revoked ids successor_id / successor_name.
    """
    rule, findings = RULES["E002"], []
    for mapping in ctx.proposal.techniques:
        tid = mapping.technique_id
        found = ctx.store.lookup(tid, "attack-pattern")
        if found.obj is not None and found.redirected_from is None:
            continue
        if found.obj is not None:
            successor = ctx.store.attack_id(found.obj)
            findings.append(
                _finding(
                    rule,
                    f"{tid} is revoked in {ctx.domain}; use its successor {successor} "
                    f"({found.obj['name']}) instead",
                    tid,
                    technique_id=tid,
                    domain=ctx.domain,
                    reason="revoked",
                    successor_id=successor,
                    successor_name=found.obj["name"],
                )
            )
            continue
        dead = ctx.store.lookup(tid, "attack-pattern", include_inactive=True).obj
        reason = "deprecated" if dead else "not_found"
        findings.append(
            _finding(
                rule,
                f"{tid} is {'deprecated' if dead else 'not a technique'} in {ctx.domain}"
                + ("" if dead else " (it may belong to another domain)"),
                tid,
                technique_id=tid,
                domain=ctx.domain,
                reason=reason,
            )
        )
    return findings


def _e008(ctx: LintContext) -> list[LintFinding]:
    rule, findings = RULES["E008"], []
    local = {o["id"] for o in ctx.objects}
    for obj in ctx.objects:
        if not _STIX_ID.match(obj["id"]):
            findings.append(_finding(rule, f"invalid STIX id {obj['id']!r}", obj["id"]))
        for key in ("source_ref", "target_ref"):
            ref = obj.get(key)
            if ref is None:
                continue
            if not _STIX_ID.match(ref):
                findings.append(_finding(rule, f"{key} {ref!r} is not a valid STIX id", obj["id"]))
            elif ref not in local and ctx.store.get_by_stix_id(ref) is None:
                findings.append(
                    _finding(rule, f"{key} {ref} does not resolve in the store or delta", obj["id"])
                )
    return findings


def _e009(ctx: LintContext) -> list[LintFinding]:
    rule, findings = RULES["E009"], []
    for obj in ctx.objects:
        if obj["type"] not in _ATTACK_ID_FORMAT:
            continue
        kind, pattern = _ATTACK_ID_FORMAT[obj["type"]]
        refs = obj.get("external_references") or [{}]
        first = refs[0]
        external_id = first.get("external_id", "")
        if first.get("source_name") != "mitre-attack" or not pattern.match(external_id):
            findings.append(
                _finding(
                    rule,
                    f"external_references[0] must be source_name 'mitre-attack' with id "
                    f"matching {pattern.pattern}",
                    obj["id"],
                    first=first,
                )
            )
        elif ctx.allocations.peek(kind, obj["id"]) != external_id:  # type: ignore[arg-type]
            findings.append(
                _finding(
                    rule,
                    f"{external_id} is not the id allocations.json assigns to {obj['id']}",
                    obj["id"],
                    external_id=external_id,
                    expected=ctx.allocations.peek(kind, obj["id"]),  # type: ignore[arg-type]
                )
            )
    return findings


def _e010(ctx: LintContext) -> list[LintFinding]:
    """Round-trip: write a bundle of the minted objects plus the techniques they
    target, reload it through ``MitreAttackData`` and resolve the software.

    A reduced bundle keeps this fast (the enterprise bundle takes ~12 s to load);
    collisions with existing objects are checked against the full store instead.
    """
    rule = RULES["E010"]
    software = next((o for o in ctx.objects if o["type"] in _SOFTWARE_TYPES), None)
    if software is None:
        return [_finding(rule, "no malware/tool object to round-trip", ctx.domain)]
    attack_id = ctx.store.attack_id(software)
    problems: list[str] = []
    try:
        if ctx.store.get_by_stix_id(software["id"]) or (
            attack_id and ctx.store.lookup(attack_id, software["type"], True).obj
        ):
            problems.append(f"{attack_id} / {software['id']} already exists in {ctx.domain}")
        targets = {o["target_ref"] for o in ctx.objects if o["type"] == "relationship"}
        existing = [t for r in targets if (t := ctx.store.get_by_stix_id(r))]
        expected = {ctx.store.attack_id(t) for t in existing}
        bundle = stix.Bundle(objects=[*existing, *ctx.objects], allow_custom=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            path.write_text(bundle.serialize(), encoding="utf-8")
            data = MitreAttackData(str(path))
            found = data.get_object_by_attack_id(attack_id or "", software["type"])
            if found is None or found["id"] != software["id"]:
                problems.append(f"get_object_by_attack_id({attack_id!r}) did not resolve")
            else:
                used = data.get_techniques_used_by_software(software["id"])
                got = {data.get_attack_id(u["object"]["id"]) for u in used}
                if got != expected:
                    problems.append(
                        f"get_techniques_used_by_software returned {sorted(map(str, got))}, "
                        f"expected {sorted(map(str, expected))}"
                    )
    except Exception as exc:  # any load failure is the finding
        problems.append(f"{type(exc).__name__}: {exc}")
    return [_finding(rule, p, software["id"]) for p in problems]


def _rule(id: str, severity: Severity, description: str, check: Callable[..., Any]) -> LintRule:
    return LintRule(id, severity, description, check)


RULES: dict[str, LintRule] = {
    r.id: r
    for r in [
        _rule("E001", Severity.ERROR, "at least one technique relationship unless declined", _e001),
        _rule("E002", Severity.ERROR, "technique exists in this domain and is active", _e002),
        _rule("E008", Severity.ERROR, "valid STIX ids; refs resolve in store or delta", _e008),
        _rule("E009", Severity.ERROR, "mitre-attack ref first, SX/GX id matches registry", _e009),
        _rule("E010", Severity.ERROR, "minted objects round-trip through MitreAttackData", _e010),
    ]
}


def lint(ctx: LintContext) -> list[LintFinding]:
    """Run every rule and return all findings."""
    return [f for rule in RULES.values() for f in rule.check(ctx)]


def has_errors(findings: list[LintFinding]) -> bool:
    return any(f.severity is Severity.ERROR for f in findings)
