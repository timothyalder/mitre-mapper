# Linter rules

Every proposal is linted before it can be minted. **ERROR** blocks minting: fix it and re-submit.
**WARN** is logged and shown to the reviewer: fix it if the fix is obvious, otherwise leave it and
explain in the rationale. **INFO** is a measured fact about your proposal; it never blocks and is
not a target. Do not pad or trim a proposal to move an INFO number.

Each finding carries `rule_id`, `message`, `target` and `details` (ids, expected vs actual). Read
`details` first: it usually names the exact fix.

You fix a *proposal* (techniques, group links, quotes). You cannot edit the intake file, so a rule
that is really about the intake (E006 on platforms, W002, W005) is reported, not worked around.

## ERROR

| id | meaning | how to fix |
|---|---|---|
| E001 | No technique relationship, and the proposal is not declined. | Map at least one technique, or decline: `declined: true`, `techniques: []`, and a `decline_rationale` saying why the evidence supports no technique. |
| E002 | A technique id does not exist in **this domain**, or is inactive. `details.reason` is `not_found`, `revoked` or `deprecated`. Technique ids are disjoint across domains (a `T1059.001` is enterprise-only), so `not_found` often means the technique belongs to another domain. | `revoked`: use `details.successor_id` (e.g. `T1579` -> `T1634.001`). `deprecated`: there is no successor; drop it and search for a live replacement. `not_found`: search this domain for the technique by behaviour; never guess an id. |
| E003 | Two relationships share the same (type, source, target). `details.requested_ids` shows which proposed ids collapsed (a revoked id and its successor count as the same technique). | Propose each technique once; merge the rationales and evidence quotes into one entry. |
| E004 | A minted relationship has an empty description or no external reference. A technique relationship only gets references from the evidence `source_name`s you cite, and those must match a `source_name` in the intake references (or `mitre-mapper intake description`, the intake prose). | Give a non-empty rationale and cite at least one evidence quote whose `source_name` is exactly an intake reference's `source_name`, or `mitre-mapper intake description` when the quote comes from the intake prose. |
| E005 | A `(Citation: NAME)` marker in a description names a source that is not among that object's external references. `details.missing` / `details.available`. | Cite only sources from the intake reference list, spelled exactly. Remove any hand-written `(Citation: ...)` marker from rationales. |
| E006 | A minted object lacks a field that >=95% of real, active objects of the same domain and type carry. `details.missing`, `details.profile`, `details.sample_size`. Profiles are measured from the dataset (e.g. mobile malware: `x_mitre_aliases` is NOT required, 82%; enterprise malware requires `x_mitre_platforms`, 97%). `revoked` is exempt on software and groups. | Usually a relationship with no external reference (see E004). If the missing field is `x_mitre_platforms` the intake has no `platforms`: this cannot be fixed from the proposal, report it in the run summary. |
| E007 | The bundle's domain is not in the object's `x_mitre_domains` (a superset is fine). | Propose the technique set for the domain you were given; do not move objects between domains. |
| E008 | A STIX id is malformed, or a `source_ref`/`target_ref` resolves to nothing in the store or the delta. | Use ids returned by the tools; do not hand-write ids. A group link to an unknown group id lands here. |
| E009 | `external_references[0]` must be `mitre-attack` with an `SX####` / `GX####` id that matches `allocations.json`. | Not editable from a proposal. Report it. |
| E010 | The minted objects do not round-trip through `MitreAttackData`: the software must resolve by ATT&CK id, and its techniques must match, and its id must not already exist. `details`/message states which. | If the message says the id "already exists", the software is already in ATT&CK or already allocated: see W002. Otherwise report it; it is a tool bug, not a proposal error. |
| E011 | An agent-proposed group link failed the quote check. `details.reason` says which part: the source has no fetched evidence, the quote is not verbatim in the source, the quote lacks the software name/alias, or lacks the group name/alias (`details.software_aliases_matched`, `group_aliases_matched` list what did match). | Copy a **verbatim** sentence from the evidence (case, whitespace, punctuation and line-break hyphenation are ignored) that names BOTH the software (or an alias of it) and the group (or an alias; reports use vendor names such as CARBON SPIDER = FIN7). Set `source_name` to the evidence source that contains it (a fetched reference; the intake prose is not group evidence). If no single sentence names both, drop the link; do not paraphrase. If the evidence names an actor with no ATT&CK group, report it under `unmatched_actors`, never as a group link. |
| E012 | An evidence quote on an agent-proposed technique is not in the source it names. `details.reason` is `source_missing` (no fetched text for that `source_name`: you cannot have read it; the only non-reference source is `mitre-mapper intake description`, the intake prose) or `quote_not_found` (the quote is not verbatim in that source's text). `details.technique_id`, `source_name`, `quote_prefix`, `evidence_sources`. | Re-read the source with `get_evidence` and copy one contiguous span exactly (case, whitespace, punctuation, bullets and words broken across lines are ignored; the words themselves may not differ: no paraphrase, no `...`). Set `source_name` to the source that really contains it. If no source states it, drop the quote, and the technique if it has no other quote. |

User-asserted items (`user_asserted: true`) are exempt from E011 and E012.

## WARN

| id | meaning | how to fix |
|---|---|---|
| W001 | A proposed technique's platforms share nothing with the software's platforms (case-insensitive; techniques with platform `None` are ignored). Skipped in ICS, where platform data is mostly absent. | Check the technique is really something the software does on its platform; drop it if the evidence does not say otherwise. |
| W002 | The software's name or an alias matches (case-insensitive) existing active ATT&CK software, named in the message ("this may be S0605"). | You cannot change the intake. Check whether the intake software really is the existing one and say so in the run summary; do not map as if it were new without noting it. |
| W003 | A parent technique and one of its sub-techniques are both proposed (`details.parent`, `details.children`). | Keep the most specific sub-technique(s) the evidence supports; keep the parent only if the evidence describes behaviour no sub-technique covers. |
| W004 | `tool` in `ics-attack`; the ICS bundle contains no tools at all. | Confirm the intake type; nothing to change in the proposal. |
| W005 | A user-defined (new) group conflicts with a prior allocation of the same name, or its name/alias is already an ATT&CK group (`details.kind` = `definition_conflict` or `matches_existing_group`). | Not editable from the proposal. If an existing group matches and the evidence supports it, you may propose a link to that existing group (with a quote); report the overlap. |

## INFO (measured, never a gate)

| id | fact reported | domain medians for active software |
|---|---|---|
| I001 | Number of techniques proposed vs the domain median. | enterprise 11 (n=825) / mobile 11 (n=126) / ics 5 (n=23) |
| I002 | Number of distinct tactics covered vs the domain median. | enterprise 6 / mobile 5 / ics 4 |
| I003 | Number of group links (agent vs user-asserted) vs the domain median. | enterprise 1 (26.4% have none) / mobile 0 (87.3% have none) / ics 1 (43.5% have none) |
| I004 | User-asserted items present: pinned techniques, existing-group refs, new groups, new-group techniques. These are never sent to the judge and excluded from scoring. | n/a |

Real software often has few techniques, one tactic, or no group. A low count is not an error: map
what the evidence supports.

## What is deliberately NOT a rule

There is no minimum number of techniques, tactics or groups, and no rule that a sub-technique
must be chosen over its parent. Do not add techniques to "reach the median". Every technique and
every group link must be supported by quoted evidence.
