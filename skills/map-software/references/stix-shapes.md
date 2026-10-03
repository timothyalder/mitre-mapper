# What your proposal becomes

The tool mints these objects from your `MappingProposal` plus the intake file. You never write
STIX, STIX ids, ATT&CK ids or `(Citation: …)` markers; they are generated. This page explains
what each proposal field turns into, so you can write fields that read well once published.

All objects carry MITRE's `created_by_ref`, marking and `x_mitre_modified_by_ref`, and
`x_mitre_attack_spec_version: "3.3.0"`. STIX ids are deterministic (same input, same id).

## Software (one per run, from the intake, not from you)

`malware` or `tool` with `name`, `description` (the intake prose), `labels` (`["malware"]` or
`["tool"]`), `x_mitre_aliases` (name first), `x_mitre_platforms` (intake platforms),
`x_mitre_domains` (every domain with an accepted proposal), and
`external_references[0] = {source_name: "mitre-attack", external_id: "SX####", url: …/software/SX####}`
followed by the intake references. `SX####` comes from a global registry.

## Software uses technique (one per `techniques[]` item)

```
relationship_type: uses
source_ref: <software>          target_ref: <attack-pattern for technique_id>
description: "<your rationale>(Citation: <source_name>)…"   one marker per cited source
external_references: the intake references whose source_name you cited in evidence
```

Your `rationale` is published as the relationship description, so write it as ATT&CK does:
one or two plain sentences stating what the software does, e.g. "Pegasus for iOS can access the
device's call log." Your `evidence[].source_name`s choose the references; an item with no
matching `source_name` gets no reference and fails E004. Quotes themselves are kept in the run
log, not in the object.

## Group uses software (one per `groups[]` item; existing groups only)

```
relationship_type: uses
source_ref: <existing intrusion-set for group_id>   target_ref: <software>
description: "<your verbatim quote>(Citation: <source_name>)"
external_references: [the reference named by source_name]
```

The quote is published as-is; it must name both the software and the group (E011).

## User-asserted items (added by the tool, cited to `mitre-mapper intake`)

- Pinned `techniques` in the intake: software-uses-technique relationships.
- `groups[].ref`: group-uses-software relationships to existing groups.
- `groups[].new`: a new `intrusion-set` with `GX####`, its group-uses-software relationship,
  and group-uses-technique relationships for its `techniques`. New groups exist only when the
  user defines them; you never create one.

`unmatched_actors`, `declined` and `decline_rationale` are logged; they mint nothing.
