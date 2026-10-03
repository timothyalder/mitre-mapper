"""Lint rules over a proposal and its previewed minted objects (PLAN §3.5).

ERROR blocks mint, WARN is logged, INFO is a measured fact. Rules that count
things are INFO, never ERROR. Finding ``details`` carry ids and expected-vs-actual
values because the caller (run.py) logs findings for a later diagnosing agent.

Rules: E001-E012, W001-W005, I001-I004. E011, E012 and W005 delegate to ``groups``.
"""

from __future__ import annotations

import re
import statistics
import tempfile
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import stix2.v20 as stix
from mitreattack.stix20 import MitreAttackData

from .allocations import Allocations
from .models import IntakeSpec, LintFinding, MappingProposal, Severity
from .store import DomainStore, is_inactive

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
    spec: IntakeSpec | None = None  # needed by E011, W002, W005, I004


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
        rels = [o for o in ctx.objects if o["type"] == "relationship"]
        # Existing objects the delta points at (techniques, existing groups) ride along.
        refs = {r for o in rels for r in (o["source_ref"], o["target_ref"])}
        existing = [t for r in sorted(refs) if (t := ctx.store.get_by_stix_id(r))]
        expected = {
            ctx.store.attack_id(t)
            for o in rels
            if o["source_ref"] == software["id"]
            and (t := ctx.store.get_by_stix_id(o["target_ref"]))
        }
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


# --------------------------------------------------------------------------- helpers

_CITATION = re.compile(r"\(Citation: ([^)]+)\)")
_PRESENCE_THRESHOLD = 0.95  # E006: required when present in >=95% of real objects


def _software_object(ctx: LintContext) -> dict[str, Any] | None:
    return next((o for o in ctx.objects if o["type"] in _SOFTWARE_TYPES), None)


def _stix_type(ref: str) -> str:
    return ref.split("--", 1)[0]


def _technique_ids(ctx: LintContext, mapping_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Resolve proposed technique ids (following revoked-by) to live objects; misses omitted."""
    found = {}
    for tid in mapping_ids:
        obj = ctx.store.lookup(tid, "attack-pattern").obj
        if obj is not None:
            found[tid] = obj
    return found


@dataclass
class Baseline:
    """Facts measured from one real domain bundle; computed once per process."""

    profiles: dict[str, frozenset[str]]  # profile key -> fields present in >=95% (E006)
    sample_sizes: dict[str, int]
    median_techniques: float  # per active software (I001)
    median_tactics: float  # I002
    median_groups: float  # I003
    n_software: int


_BASELINES: dict[str, Baseline] = {}


def _profile_key(obj: dict[str, Any]) -> str | None:
    kind = obj["type"]
    if kind in _SOFTWARE_TYPES:
        return f"software:{kind}"
    if kind == "intrusion-set":
        return "intrusion-set"
    if kind == "relationship":
        src, tgt = _stix_type(obj["source_ref"]), _stix_type(obj["target_ref"])
        src = "software" if src in _SOFTWARE_TYPES else src
        tgt = "software" if tgt in _SOFTWARE_TYPES else tgt
        return f"relationship:{obj['relationship_type']}:{src}->{tgt}"
    return None


def domain_baseline(store: DomainStore) -> Baseline:
    """Field profiles (E006) and medians (I001-I003) from the real, active objects."""
    key = store.cache_key  # a held-out store must not share (or poison) the plain store's baseline
    if key in _BASELINES:
        return _BASELINES[key]

    software = [*store.objects("malware"), *store.objects("tool")]
    groups = store.objects("intrusion-set")
    techniques = {o["id"]: o for o in store.objects("attack-pattern")}
    rels = store.objects("relationship")  # active only

    samples: dict[str, list[set[str]]] = defaultdict(list)
    for obj in [*software, *groups, *(r for r in rels if r["relationship_type"] == "uses")]:
        pkey = _profile_key(obj)
        if pkey:
            samples[pkey].append(set(obj))
            if obj["type"] in _SOFTWARE_TYPES:
                samples["software"].append(set(obj))  # pooled fallback (e.g. ICS has no tools)
    profiles = {}
    for pkey, sets in samples.items():
        counts = Counter(f for fields in sets for f in fields)
        profiles[pkey] = frozenset(
            f for f, n in counts.items() if n / len(sets) >= _PRESENCE_THRESHOLD
        )

    soft_ids = {o["id"] for o in software}
    group_ids = {o["id"] for o in groups}
    used: dict[str, set[str]] = defaultdict(set)
    linked: dict[str, set[str]] = defaultdict(set)
    for r in rels:
        if r["relationship_type"] != "uses":
            continue
        src, tgt = r["source_ref"], r["target_ref"]
        if src in soft_ids and tgt in techniques:
            used[src].add(tgt)
        elif src in group_ids and tgt in soft_ids:
            linked[tgt].add(src)
    n_tech = [len(used[i]) for i in soft_ids]
    n_tactics = [
        len({p["phase_name"] for t in used[i] for p in techniques[t].get("kill_chain_phases", [])})
        for i in soft_ids
    ]
    n_groups = [len(linked[i]) for i in soft_ids]
    med = statistics.median
    baseline = Baseline(
        profiles=profiles,
        sample_sizes={k: len(v) for k, v in samples.items()},
        median_techniques=med(n_tech) if n_tech else 0,
        median_tactics=med(n_tactics) if n_tactics else 0,
        median_groups=med(n_groups) if n_groups else 0,
        n_software=len(soft_ids),
    )
    _BASELINES[key] = baseline
    return baseline


# --------------------------------------------------------------------------- ERROR rules


def _e003(ctx: LintContext) -> list[LintFinding]:
    """No duplicate (relationship_type, source_ref, target_ref) among minted relationships."""
    rule = RULES["E003"]
    rels = [o for o in ctx.objects if o["type"] == "relationship"]
    counts = Counter((o["relationship_type"], o["source_ref"], o["target_ref"]) for o in rels)
    requested: dict[str, list[str]] = defaultdict(list)
    for mapping in ctx.proposal.techniques:
        obj = ctx.store.lookup(mapping.technique_id, "attack-pattern").obj
        if obj is not None:
            requested[obj["id"]].append(mapping.technique_id)
    findings = []
    for (rtype, src, tgt), n in counts.items():
        if n < 2:
            continue
        ids = requested.get(tgt, [])
        label = ctx.store.attack_id(ctx.store.get_by_stix_id(tgt) or {}) or tgt
        findings.append(
            _finding(
                rule,
                f"{n} identical '{rtype}' relationships to {label}"
                + (f" (proposed as {', '.join(ids)}; a revoked id redirects to its successor)"
                   if len(set(ids)) > 1 else "")
                + "; propose each technique once",
                tgt,
                relationship_type=rtype,
                source_ref=src,
                target_ref=tgt,
                target_attack_id=label,
                count=n,
                requested_ids=ids,
            )
        )
    return findings


def _e004(ctx: LintContext) -> list[LintFinding]:
    """Minted relationships need a non-empty description and >=1 external reference."""
    rule, findings = RULES["E004"], []
    for obj in ctx.objects:
        if obj["type"] != "relationship":
            continue
        no_desc = not (obj.get("description") or "").strip()
        no_refs = not obj.get("external_references")
        if no_desc or no_refs:
            findings.append(
                _finding(
                    rule,
                    f"relationship {obj['id']} lacks "
                    + " and ".join(
                        m for m, bad in (("a description", no_desc), ("an external reference", no_refs)) if bad
                    ),
                    obj["id"],
                    source_ref=obj["source_ref"],
                    target_ref=obj["target_ref"],
                    has_description=not no_desc,
                    n_external_references=len(obj.get("external_references") or []),
                )
            )
    return findings


def _e005(ctx: LintContext) -> list[LintFinding]:
    """Every ``(Citation: NAME)`` in a minted object's description resolves in its own refs."""
    rule, findings = RULES["E005"], []
    for obj in ctx.objects:
        sources = {r.get("source_name") for r in obj.get("external_references", [])}
        missing = [m for m in _CITATION.findall(obj.get("description") or "") if m not in sources]
        if missing:
            findings.append(
                _finding(
                    rule,
                    f"{obj['type']} {obj['id']} cites {sorted(set(missing))} with no matching "
                    f"external reference source_name",
                    obj["id"],
                    missing=sorted(set(missing)),
                    available=sorted(s for s in sources if s),
                )
            )
    return findings


def _e006(ctx: LintContext) -> list[LintFinding]:
    """Minted objects carry every field present in >=95% of real active objects (domain, type)."""
    rule, findings = RULES["E006"], []
    baseline = domain_baseline(ctx.store)
    for obj in ctx.objects:
        pkey = _profile_key(obj)
        if pkey is None:
            continue
        if pkey not in baseline.profiles and pkey.startswith("software:"):
            pkey = "software"  # no real objects of this type in the domain (ICS tools)
        required = baseline.profiles.get(pkey)
        if required is None:
            continue
        # stix2 drops `revoked: false` on SDOs (mint only restores it on relationships),
        # and its presence on real software varies by domain (0% mobile, 75% enterprise, 100% ICS).
        optional = {"revoked"} if obj["type"] != "relationship" else set()
        missing = sorted(required - optional - set(obj))
        if missing:
            findings.append(
                _finding(
                    rule,
                    f"{obj['type']} {obj['id']} is missing fields present in >=95% of real "
                    f"{ctx.domain} objects: {', '.join(missing)}",
                    obj["id"],
                    profile=pkey,
                    domain=ctx.domain,
                    missing=missing,
                    sample_size=baseline.sample_sizes.get(pkey, 0),
                    present=sorted(obj),
                )
            )
    return findings


def _e007(ctx: LintContext) -> list[LintFinding]:
    """The bundle's domain must be among a minted object's ``x_mitre_domains`` (subset)."""
    rule, findings = RULES["E007"], []
    for obj in ctx.objects:
        domains = obj.get("x_mitre_domains")
        if domains is not None and ctx.domain not in domains:
            findings.append(
                _finding(
                    rule,
                    f"{obj['type']} {obj['id']} is placed in {ctx.domain} but its "
                    f"x_mitre_domains is {domains}",
                    obj["id"],
                    domain=ctx.domain,
                    x_mitre_domains=list(domains),
                )
            )
    return findings


def _synth_spec(ctx: LintContext) -> IntakeSpec | None:
    """The intake spec, or a minimal one rebuilt from the minted software object."""
    if ctx.spec is not None:
        return ctx.spec
    software = _software_object(ctx)
    if software is None:
        return None
    aliases = [a for a in software.get("x_mitre_aliases", []) if a != software["name"]]
    return IntakeSpec(name=software["name"], type=software["type"], aliases=aliases)


def _e011(ctx: LintContext) -> list[LintFinding]:
    """Agent-proposed group links need a verbatim quote found in the evidence naming both sides."""
    rule, findings = RULES["E011"], []
    spec = _synth_spec(ctx)
    if spec is None or all(g.user_asserted for g in ctx.proposal.groups):
        return []
    from . import groups  # C's module; imported lazily
    for mapping in ctx.proposal.groups:
        if mapping.user_asserted:
            continue
        check = groups.check_group_quote(mapping, spec, ctx.store, ctx.evidence)
        if check.passed:
            continue
        findings.append(
            _finding(
                rule,
                f"group link {mapping.group_id} fails the quote check: {check.reason}",
                mapping.group_id,
                group_id=mapping.group_id,
                reason=check.reason,
                source_name=check.source_name,
                quote=mapping.quote,
                software_aliases_matched=list(check.software_aliases_matched),
                group_aliases_matched=list(check.group_aliases_matched),
                evidence_sources=sorted(ctx.evidence),
            )
        )
    return findings


def _e012(ctx: LintContext) -> list[LintFinding]:
    """Agent-proposed technique evidence quotes appear verbatim in the named source's text."""
    rule, findings = RULES["E012"], []
    from .groups import normalize_text
    from .intake import INTAKE_PROSE_SOURCE

    texts = dict(ctx.evidence)
    if ctx.spec is not None and ctx.spec.body.strip():
        texts.setdefault(INTAKE_PROSE_SOURCE, ctx.spec.body)
    normalized: dict[str, str] = {}
    for mapping in ctx.proposal.techniques:
        if mapping.user_asserted:
            continue
        for ev in mapping.evidence:
            if ev.source_name not in texts:
                reason = "source_missing"
            else:
                haystack = normalized.setdefault(ev.source_name, normalize_text(texts[ev.source_name]))
                quote = normalize_text(ev.quote)
                reason = None if quote and quote in haystack else "quote_not_found"
            if reason is None:
                continue
            prefix = " ".join(ev.quote.split())[:60]
            findings.append(
                _finding(
                    rule,
                    f"technique {mapping.technique_id} evidence quote fails the check ({reason}) "
                    f"for source {ev.source_name!r}: {prefix!r}",
                    mapping.technique_id,
                    technique_id=mapping.technique_id,
                    source_name=ev.source_name,
                    reason=reason,
                    quote_prefix=prefix,
                    evidence_sources=sorted(texts),
                )
            )
    return findings


# --------------------------------------------------------------------------- WARN rules


def _w001(ctx: LintContext) -> list[LintFinding]:
    """Software platforms should intersect each technique's platforms (skipped in ICS)."""
    rule, findings = RULES["W001"], []
    if ctx.domain == "ics-attack":
        return []
    software = _software_object(ctx)
    sw_platforms = software.get("x_mitre_platforms") if software else None
    if not sw_platforms and ctx.spec is not None:
        sw_platforms = ctx.spec.platforms
    if not sw_platforms:
        return []
    wanted = {p.lower() for p in sw_platforms}
    for tid, obj in _technique_ids(ctx, [m.technique_id for m in ctx.proposal.techniques]).items():
        tech_platforms = [p for p in obj.get("x_mitre_platforms", []) if p.lower() != "none"]
        if tech_platforms and not wanted & {p.lower() for p in tech_platforms}:
            findings.append(
                _finding(
                    rule,
                    f"{tid} ({obj['name']}) applies to {tech_platforms}, none of the "
                    f"software's platforms {list(sw_platforms)}",
                    tid,
                    technique_id=tid,
                    technique_name=obj["name"],
                    technique_platforms=tech_platforms,
                    software_platforms=list(sw_platforms),
                )
            )
    return findings


def _w002(ctx: LintContext) -> list[LintFinding]:
    """Name/alias collision (case-insensitive) with existing active software in this domain."""
    rule = RULES["W002"]
    spec = _synth_spec(ctx)
    if spec is None:
        return []
    ours = {n.lower(): n for n in [spec.name, *spec.aliases]}
    collisions = []
    for obj in [*ctx.store.objects("malware"), *ctx.store.objects("tool")]:
        theirs = [obj["name"], *obj.get("x_mitre_aliases", [])]
        matched = sorted({ours[t.lower()] for t in theirs if t.lower() in ours})
        if matched:
            collisions.append(
                {
                    "attack_id": ctx.store.attack_id(obj),
                    "name": obj["name"],
                    "type": obj["type"],
                    "matched_names": matched,
                }
            )
    return [
        _finding(
            rule,
            f"'{c['matched_names'][0]}' collides with existing {c['type']} {c['name']} "
            f"({c['attack_id']}) - this may be {c['attack_id']}; review before minting a duplicate",
            c["attack_id"],
            software_name=spec.name,
            domain=ctx.domain,
            **c,
        )
        for c in sorted(collisions, key=lambda c: str(c["attack_id"]))
    ] if collisions else []


def _w003(ctx: LintContext) -> list[LintFinding]:
    """Parent technique and one of its sub-techniques both proposed."""
    rule = RULES["W003"]
    proposed = [m.technique_id for m in ctx.proposal.techniques]
    findings = []
    for parent in sorted({t for t in proposed if "." not in t}):
        children = sorted({t for t in proposed if t.startswith(parent + ".")})
        if children:
            findings.append(
                _finding(
                    rule,
                    f"parent {parent} is proposed together with {', '.join(children)}; "
                    f"keep only the sub-technique(s) the evidence supports, or only the parent",
                    parent,
                    parent=parent,
                    children=children,
                )
            )
    return findings


def _w004(ctx: LintContext) -> list[LintFinding]:
    """A ``tool`` in ICS has zero precedent (the ICS bundle has no tool objects)."""
    software = _software_object(ctx)
    kind = software["type"] if software else (ctx.spec.type if ctx.spec else None)
    if ctx.domain == "ics-attack" and kind == "tool":
        return [
            _finding(
                RULES["W004"],
                "type 'tool' in ics-attack has no precedent (0 real ICS tools); "
                "confirm the type is not 'malware'",
                ctx.domain,
                domain=ctx.domain,
                type=kind,
            )
        ]
    return []


def _w005(ctx: LintContext) -> list[LintFinding]:
    """A user-defined group conflicts with a prior allocation or an existing ATT&CK group."""
    if ctx.spec is None or not any(g.new for g in ctx.spec.groups):
        return []
    from . import groups  # C's module; imported lazily

    conflicts = groups.check_new_group_conflicts(ctx.spec, ctx.allocations, ctx.store)
    return [
        _finding(
            RULES["W005"],
            str(c.get("message") or c.get("reason") or f"conflicting group definition: {c}"),
            str(c.get("name") or c.get("group") or "") or None,
            **{k: v for k, v in c.items() if k != "message"},
        )
        for c in conflicts
    ]


# --------------------------------------------------------------------------- INFO rules


def _i001(ctx: LintContext) -> list[LintFinding]:
    if ctx.proposal.declined:
        return []
    base = domain_baseline(ctx.store)
    n = len({m.technique_id for m in ctx.proposal.techniques})
    return [
        _finding(
            RULES["I001"],
            f"{n} techniques proposed; median for active {ctx.domain} software is "
            f"{base.median_techniques:g} (n={base.n_software}). Informational only.",
            ctx.domain,
            count=n,
            median=base.median_techniques,
            domain=ctx.domain,
            baseline_n=base.n_software,
        )
    ]


def _i002(ctx: LintContext) -> list[LintFinding]:
    if ctx.proposal.declined:
        return []
    base = domain_baseline(ctx.store)
    found = _technique_ids(ctx, [m.technique_id for m in ctx.proposal.techniques])
    tactics = sorted(
        {p["phase_name"] for o in found.values() for p in o.get("kill_chain_phases", [])}
    )
    return [
        _finding(
            RULES["I002"],
            f"{len(tactics)} tactics covered; median for active {ctx.domain} software is "
            f"{base.median_tactics:g}. Informational only.",
            ctx.domain,
            count=len(tactics),
            tactics=tactics,
            median=base.median_tactics,
            domain=ctx.domain,
        )
    ]


def _i003(ctx: LintContext) -> list[LintFinding]:
    if ctx.proposal.declined:
        return []
    base = domain_baseline(ctx.store)
    agent = [g.group_id for g in ctx.proposal.groups if not g.user_asserted]
    user = [g.group_id for g in ctx.proposal.groups if g.user_asserted]
    return [
        _finding(
            RULES["I003"],
            f"{len(agent) + len(user)} group links ({len(agent)} agent-proposed, "
            f"{len(user)} user-asserted); median for active {ctx.domain} software is "
            f"{base.median_groups:g}. Informational only.",
            ctx.domain,
            count=len(agent) + len(user),
            agent_proposed=agent,
            user_asserted=user,
            median=base.median_groups,
            domain=ctx.domain,
        )
    ]


def _i004(ctx: LintContext) -> list[LintFinding]:
    """User-asserted items present (count, by kind). Never gates."""
    p, spec = ctx.proposal, ctx.spec
    techniques = sorted({m.technique_id for m in p.techniques if m.user_asserted})
    group_refs = sorted({g.group_id for g in p.groups if g.user_asserted})
    new_groups = [g.new for g in spec.groups if g.new] if spec else []
    new_group_names = [g.name for g in new_groups]
    new_group_techniques = sorted({t for g in new_groups for t in g.techniques})
    kinds = {
        "techniques": techniques,
        "group_refs": group_refs,
        "new_groups": new_group_names,
        "new_group_techniques": new_group_techniques,
    }
    total = sum(len(v) for v in kinds.values())
    if not total:
        return []
    return [
        _finding(
            RULES["I004"],
            f"{total} user-asserted items (never sent to the judge, excluded from scoring): "
            + ", ".join(f"{len(v)} {k}" for k, v in kinds.items() if v),
            ctx.domain,
            total=total,
            counts={k: len(v) for k, v in kinds.items()},
            **kinds,
        )
    ]


def _rule(id: str, severity: Severity, description: str, check: Callable[..., Any]) -> LintRule:
    return LintRule(id, severity, description, check)


RULES: dict[str, LintRule] = {
    r.id: r
    for r in [
        _rule("E001", Severity.ERROR, "at least one technique relationship unless declined", _e001),
        _rule("E002", Severity.ERROR, "technique exists in this domain and is active", _e002),
        _rule("E003", Severity.ERROR, "no duplicate (type, source_ref, target_ref)", _e003),
        _rule("E004", Severity.ERROR, "minted relationships have description and references", _e004),
        _rule("E005", Severity.ERROR, "every (Citation: X) resolves in the object's refs", _e005),
        _rule("E006", Severity.ERROR, "minted objects carry all >=95%-present real fields", _e006),
        _rule("E007", Severity.ERROR, "bundle domain is in x_mitre_domains", _e007),
        _rule("E008", Severity.ERROR, "valid STIX ids; refs resolve in store or delta", _e008),
        _rule("E009", Severity.ERROR, "mitre-attack ref first, SX/GX id matches registry", _e009),
        _rule("E010", Severity.ERROR, "minted objects round-trip through MitreAttackData", _e010),
        _rule("E011", Severity.ERROR, "agent-proposed group link quote is grounded", _e011),
        _rule("E012", Severity.ERROR, "agent-proposed technique evidence quotes are verbatim", _e012),
        _rule("W001", Severity.WARN, "software and technique platforms intersect", _w001),
        _rule("W002", Severity.WARN, "name/alias collides with existing software", _w002),
        _rule("W003", Severity.WARN, "parent and child technique both proposed", _w003),
        _rule("W004", Severity.WARN, "tool in ics has no precedent", _w004),
        _rule("W005", Severity.WARN, "conflicting user-defined group definition", _w005),
        _rule("I001", Severity.INFO, "technique count vs domain median", _i001),
        _rule("I002", Severity.INFO, "tactic count vs domain median", _i002),
        _rule("I003", Severity.INFO, "group-link count vs domain median", _i003),
        _rule("I004", Severity.INFO, "user-asserted items present", _i004),
    ]
}


def lint(ctx: LintContext) -> list[LintFinding]:
    """Run every rule and return all findings."""
    return [f for rule in RULES.values() for f in rule.check(ctx)]


def has_errors(findings: list[LintFinding]) -> bool:
    return any(f.severity is Severity.ERROR for f in findings)
