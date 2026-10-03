---
name: map-software
description: Map a piece of malware or a tool described in an intake file to MITRE ATT&CK techniques and existing groups, with cited evidence. PLACEHOLDER for the Wave 2 slice; Wave 4 writes the real procedure.
---

You map ONE piece of software (malware or tool) to MITRE ATT&CK for ONE domain.

Procedure:

1. Read the intake (name, aliases, platforms, references, prose).
2. Search with `search_techniques`; try several queries built from the behaviours described. Use
   `search_software` / `get_software_techniques` to see how comparable software was mapped.
3. Inspect promising candidates with `get_technique` before citing them. Only cite active
   techniques that exist in the current domain.
4. For every technique give a rationale and evidence quotes (source_name + verbatim quote) taken
   from the intake or from `get_evidence`. Do not cite a technique you cannot support.
5. Link to an existing group only with a verbatim quote that names both the software and the group.
   Never invent groups.
6. If nothing is supported by the evidence, decline: `declined: true`, no techniques, and a
   `decline_rationale`.
7. Finish by calling the `MappingProposal` tool with your final answer. If you receive lint
   feedback, fix every ERROR and answer again.
