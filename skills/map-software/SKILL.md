---
name: map-software
description: Map one piece of malware or a tool, described in a mitre-mapper intake file, to MITRE ATT&CK techniques and existing ATT&CK groups for one domain, citing verbatim evidence. Use when mapping software to ATT&CK with mitre-mapper, either as its LangChain agent or from Claude Code through the mitre-mapper MCP server.
---

# Map software to ATT&CK

You map ONE piece of software to ATT&CK for ONE domain, the one named in the task. Every item you
propose must be backed by text you have read in this session. A short mapping where every item is
supported beats a long one.

## Output: `MappingProposal`

- `domain`: the domain you were given.
- `techniques`: `[{technique_id, rationale, evidence: [{source_name, quote}]}]`
  - `technique_id`: `T####` or `T####.###`, verified active in this domain with `get_technique`.
  - `rationale`: one or two plain sentences saying what the software does, in ATT&CK's style
    ("X can read the device's call log."). It is published as the relationship description. Do not
    write `(Citation: …)` markers; they are added from your evidence.
  - `evidence`: at least one quote. `source_name` must be exactly a reference name from the task, or
    `mitre-mapper intake description` for a sentence from the intake prose. Never use
    `mitre-mapper intake` (that name is for the user's pinned items). The quote must be copied
    verbatim from the source you name, or lint E012 rejects it.
- `groups`: `[{group_id, quote, source_name}]`, linking existing ATT&CK groups (`G####`) only.
- `unmatched_actors`: `[{actor, quote, source_name}]`, for actors the evidence ties to the software
  that have no ATT&CK group.
- `declined`, `decline_rationale`: see Decline.
- Never set `user_asserted`. It is forced to false on everything you propose.

## Procedure

1. **Read the task.** Note the name, aliases, platforms, reference names, evidence sources, intake
   prose and anything the user pinned.
2. **Read all evidence.** `get_evidence(source_name)` returns one window of the text. While
   `next_offset` is not null, call it again with `offset=next_offset`. Read every source to the end.
   As you go, list each behaviour with the exact sentence that states it and that sentence's source.
3. **Search per behaviour.** `search_techniques(query, k)` is keyword search (BM25) over names,
   aliases and descriptions. It does not match meaning, so try several phrasings for each behaviour:
   the report's own words, ATT&CK vocabulary ("input capture", "exfiltration over C2 channel"),
   synonyms, and the thing acted on ("call log", "SMS messages", "keychain"). If a search returns
   nothing useful, rephrase it before you conclude that no technique fits.
4. **Look at comparable software.** Use `search_software` to find similar families, then
   `get_software_techniques(S####)` to see how ATT&CK mapped them. This only suggests candidates. Each
   one still needs evidence about this software.
5. **Verify every candidate** with `get_technique(id)`. Read the description, tactics and
   platforms. Keep the candidate only if the evidence describes this technique and the platforms fit
   the software. If the result has `redirected_from`, the id you looked up is revoked: use the
   returned `id`.
6. **Pick the most specific technique.** If the technique has sub-techniques, use the most specific
   sub-technique the evidence supports. To find them, search for the behaviour plus the parent's
   name, or call `get_technique` on `<parent>.001`, `.002`, and so on. Use the parent only when the
   evidence does not say which variant. Don't propose a parent together with its own sub-technique
   unless the evidence describes behaviour that no sub-technique covers.
7. **Cite.** Each quote is one contiguous span copied from a source you read. Case, whitespace,
   punctuation and words broken across lines may differ from the source; the words may not: no
   paraphrase, no `...`, no stitched fragments. If you cannot quote support for a technique, drop it.
8. **Groups.** Follow the Groups rules below.
9. **Submit** the proposal. In the LangChain agent, finish by calling the `MappingProposal` tool.
   In Claude Code, call `submit_proposal`.

## Groups (existing groups only)

- Propose a link only when one sentence in a fetched reference names both the software (its name or
  an alias) and the group (a name or alias that ATT&CK lists for it). Quote that sentence and give
  the reference as `source_name`. The intake prose does not count as evidence for a group link.
- Reports often use vendor names. Resolve them with `get_group("<name>")`, which matches names and
  aliases (for example "Carbon Spider" resolves to FIN7, G0046), or with `search_groups`. Then check
  the returned `aliases` against the words in your quote.
- If the evidence ties an actor to the software and that actor has no ATT&CK group, or its name in
  the report is not one of the group's ATT&CK aliases, report it under `unmatched_actors` with the
  quote. Do not add a group link for it.
- Never invent a group. Never link a group based on inference (same campaign, same country, similar
  tooling). New groups come only from the user's intake file.

## Decline

Decline when no evidence you read describes behaviour of this software that maps to a technique
in this domain. Examples: the subject is a vulnerability rather than software, every behaviour
belongs to another domain, or no readable evidence exists. To decline, set `declined: true`, leave
`techniques: []`, and write a `decline_rationale` that says what you read and why nothing maps.
Thin evidence is not a reason to decline: map what it supports.

## Feedback

- **Lint** findings each have `rule_id`, `target`, `message` and `details`. ERROR blocks the
  proposal. Fix each ERROR on the item it names, using `details` (`successor_id`, `reason`,
  `missing`, `*_aliases_matched`). `read_reference("linter-rules.md")` gives the fix for each rule.
  WARN does not block: fix it if the fix is obvious. INFO is a measurement. Never add or remove
  items to change an INFO count.
- **Reviewer** (LangChain only): "An independent reviewer rejected your proposal" lists failed
  items. Fix the problem each item names, using evidence: add a supported technique you missed,
  switch to a better-fitting or more specific technique, supply the missing quote, or remove an
  item the evidence does not support.
- Feedback in the task means a previous proposal of yours was rejected. It names only what was
  wrong. Everything it doesn't name was acceptable: keep those items, or rebuild them the same
  way from the same evidence, and change only what it names. Don't resubmit an unchanged proposal,
  and don't argue with the feedback.

## Domain discipline

- Technique ids are disjoint across domains. An enterprise id never exists in mobile or ICS. Use
  only ids that the tools returned in this domain, never ids you remember. For E002 `not_found`,
  search this domain by behaviour.
- A revoked technique has a successor: use `successor_id` from E002, or the `id` that
  `get_technique` returns after a redirect. A deprecated technique has no successor: find a live
  technique that fits, or drop the item.

## Never

- Repeat anything the user pinned: the techniques and groups listed in the task (or
  `pinned_by_user`). The tool adds them, and a duplicate fails the final lint.
- Cite text you have not read in this session, or quote one source under another's `source_name`.
- Pad the mapping with behaviour that is plausible, typical of the family, or present in comparable
  software but not stated in the evidence.
- Invent groups, or link a group without a quote that names both the software and the group.
- Write STIX objects, STIX ids, `SX`/`GX` ids or citation markers yourself.

## Claude Code via MCP

The mitre-mapper MCP server runs this same procedure, with the same logs as the LangChain agent.

1. `start_run(intake_path)` returns the task: `run_id`, `domains`, `evidence` (the sources you can
   read), `references_without_evidence` (these cannot be quoted), `intake` (with `prose`) and
   `pinned_by_user`.
2. Call the tools above, passing `run_id` every time. When `domains` has more than one entry, also
   pass `domain` to the search, get and proposal tools, and produce one proposal per domain.
3. `submit_proposal(run_id, proposal, domain)` counts one attempt against `max_attempts` and returns
   the lint findings. Fix the ERRORs and resubmit. `lint_proposal` gives a dry run that does not use
   an attempt. No reviewer runs in MCP mode, so check your own proposal against Procedure, Groups and
   Never before you submit.
4. Call `mint_delta(run_id)` once every domain's latest submission has no ERRORs. A declined
   proposal counts, and the tool still adds the user's pinned items. `mint_delta` refuses while any
   ERROR remains. To stop without a clean submission, call `end_run(run_id, reason)` with
   `terminal_state="declined"` (the default) or `"error"`. Always finish with one of these two calls.
