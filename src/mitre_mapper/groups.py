"""Pure group helpers: E011 quote check, W005 conflict detection (PLAN §3.4/§3.5, D15).

No I/O beyond reading the allocations registry, no run-log events. Lint (E011/W005)
and ``run.py`` logging call these; groups are never minted agentically.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .allocations import Allocations
from .models import GroupMapping, IntakeSpec, NewGroup
from .store import DomainStore

_QUOTE_TRANSLATION = str.maketrans(
    {
        "‘": "'", "’": "'", "‚": "'", "‛": "'",
        "“": '"', "”": '"', "„": '"',
        "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-",
        " ": " ",
    }
)


def normalize_text(text: str) -> str:
    """Whitespace-collapsed, casefolded text with typographic quotes/dashes flattened."""
    text = unicodedata.normalize("NFKC", text).translate(_QUOTE_TRANSLATION)
    return " ".join(text.casefold().split())


_ELISION = re.compile(r"\.\.\.|…")
_NOT_ALNUM = re.compile(r"[\W_]+")


def quote_key(text: str) -> str:
    """Character sequence used to test whether a quote appears verbatim in evidence (E011, E012).

    Extracted text (PDFs especially) breaks words across lines, with a hyphen
    ("compro-\\nmise") or without one ("C\\nall logs" in pypdf bullet lists), and keeps
    list bullets. So "verbatim" means the same letters and digits in the same order:
    case, whitespace, punctuation and bullets are ignored. An elision ("..." or "…")
    never matches, since it marks text the quote left out.
    """
    text = unicodedata.normalize("NFKC", text).casefold()
    return "\x00".join(_NOT_ALNUM.sub("", part) for part in _ELISION.split(text))


def quote_in(quote: str, evidence_key: str) -> bool:
    """True if ``quote`` appears verbatim in evidence already reduced with :func:`quote_key`."""
    key = quote_key(quote)
    return bool(key.strip("\x00")) and key in evidence_key


def _matched(names: list[str], haystack: str) -> list[str]:
    """Names occurring in ``haystack`` as whole words (both already normalised)."""
    out = []
    for name in names:
        norm = normalize_text(name)
        if norm and re.search(rf"(?<!\w){re.escape(norm)}(?!\w)", haystack):
            out.append(name)
    return out


@dataclass
class QuoteCheck:
    group_id: str
    passed: bool
    reason: str
    source_name: str = ""
    software_aliases_matched: list[str] = field(default_factory=list)
    group_aliases_matched: list[str] = field(default_factory=list)


def check_group_quote(
    mapping: GroupMapping,
    spec: IntakeSpec,
    store: DomainStore,
    evidence: dict[str, str],
) -> QuoteCheck:
    """E011: the quote is in the cited evidence and names both the software and the group.

    ``evidence`` maps ``source_name`` to fetched text. Matching is whitespace- and
    case-insensitive; names must appear as whole words. User-asserted mappings are
    not evidence-checked and pass with reason ``user-asserted``.
    """
    base = QuoteCheck(mapping.group_id, False, "", mapping.source_name)
    if mapping.user_asserted:
        base.passed, base.reason = True, "user-asserted; not evidence-checked"
        return base
    group = store.lookup(mapping.group_id, "intrusion-set").obj
    if group is None:
        base.reason = f"group {mapping.group_id} is not an active group in {store.domain}"
        return base
    if mapping.source_name not in evidence:
        base.reason = f"source {mapping.source_name!r} has no fetched evidence"
        return base
    quote = normalize_text(mapping.quote)
    if not quote:
        base.reason = "empty quote"
        return base
    if not quote_in(mapping.quote, quote_key(evidence[mapping.source_name])):
        base.reason = f"quote does not appear verbatim in evidence {mapping.source_name!r}"
        return base
    base.software_aliases_matched = _matched([spec.name, *spec.aliases], quote)
    base.group_aliases_matched = _matched(store.group_names(group), quote)
    if not base.software_aliases_matched:
        base.reason = "quote does not contain the software name or an alias"
    elif not base.group_aliases_matched:
        base.reason = f"quote does not contain a name or alias of {group['name']} ({mapping.group_id})"
    else:
        base.passed, base.reason = True, "ok"
    return base


def definition_sha256(group: NewGroup) -> str:
    """Stable hash of a user-defined group's definition (order/whitespace/case-insensitive
    for names and lists; description whitespace-normalised)."""
    payload: dict[str, Any] = {
        "name": normalize_text(group.name),
        "aliases": sorted({normalize_text(a) for a in group.aliases} - {normalize_text(group.name)}),
        "description": " ".join(group.description.split()),
        "references": sorted(
            (r.source_name, r.url or "", " ".join((r.description or "").split()))
            for r in group.references
        ),
        "techniques": sorted(set(group.techniques)),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def check_new_group_conflicts(
    spec: IntakeSpec, allocations: Allocations, store: DomainStore | None
) -> list[dict[str, Any]]:
    """W005 input. One dict per problem, ``kind`` one of:

    * ``definition_conflict`` - same group name already allocated (earlier run) or
      defined earlier in this intake with a different definition; first-minted wins.
    * ``matches_existing_group`` - the name or an alias is an ATT&CK group; suggests ``ref:``.

    Each dict has ``name``, ``kind``, ``message``; plus ``attack_id``/``first_run`` (allocated),
    or ``existing_attack_id``/``existing_name``/``matched`` (existing group).
    """
    from .mint import group_stix_id  # local: mint imports this module

    out: list[dict[str, Any]] = []
    seen: dict[str, str] = {}  # stix id -> definition hash within this intake
    for entry in spec.groups:
        new = entry.new
        if new is None:
            continue
        stix_id = group_stix_id(new.name)
        digest = definition_sha256(new)
        if stix_id in seen and seen[stix_id] != digest:
            out.append(
                {
                    "name": new.name,
                    "kind": "definition_conflict",
                    "message": f"{new.name!r} is defined twice in this intake with different definitions; "
                    "the first one wins",
                }
            )
        seen.setdefault(stix_id, digest)
        record = allocations.record_for("group", stix_id)
        previous = record.get("definition_sha256") if record else None
        if record and previous and previous != digest:
            out.append(
                {
                    "name": new.name,
                    "kind": "definition_conflict",
                    "attack_id": record["attack_id"],
                    "first_run": record["first_run"],
                    "message": f"{record['attack_id']} ({new.name!r}) was already minted in run "
                    f"{record['first_run']} with a different definition; the first-minted definition wins "
                    "until the user reconciles them",
                }
            )
        if store is not None:
            for name in dict.fromkeys([new.name, *new.aliases]):
                existing = store.resolve_group(name)
                if existing is not None:
                    attack_id = store.attack_id(existing)
                    out.append(
                        {
                            "name": new.name,
                            "kind": "matches_existing_group",
                            "matched": name,
                            "existing_attack_id": attack_id,
                            "existing_name": existing["name"],
                            "message": f"{name!r} is already ATT&CK group {existing['name']} "
                            f"({attack_id}); use `ref: {attack_id}` instead of defining a new group",
                        }
                    )
                    break
    return out
