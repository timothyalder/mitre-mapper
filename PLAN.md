# mitre-mapper — Implementation Plan (v2, clean rebuild)

**Audience:** a fresh Claude Code session with no prior context. Read this file top to bottom before
writing code. Everything here is either a **user decision** (binding — do not re-litigate) or a **measured
fact** (verified against the real datasets / real library and website source in this planning session).
Where a fact matters, add a test that pins it.

This plan replaces an earlier one. A previous implementation exists at `../mitre-mapper`; the user was not
happy with it. **This is a clean rebuild.** Read the old repo only if absolutely necessary, never copy its
production code, and never treat its design as authoritative over this file.

---

## 0. What we are building

A Python library + CLI + MCP server that takes an **intake file** (markdown with YAML frontmatter)
describing a piece of software (malware or tool) and produces MITRE ATT&CK STIX objects:

- a `malware` or `tool` SDO with a synthetic ATT&CK ID `SX####`,
- `uses` relationships from it to ATT&CK **techniques** (`attack-pattern`),
- `uses` relationships from ATT&CK **groups** (`intrusion-set`) to it — existing groups proposed by the agent
  with quoted evidence, and/or groups asserted by the user in the intake file,
- user-defined **new groups** (`intrusion-set`, synthetic ID `GX####`) — only when the user defines them,

emitted as a **delta** that can be materialized into a patched copy of the ATT&CK STIX bundles. The patched
bundles must render on the **ATT&CK website** (`mitre-attack/attack-website`) and load in **ATT&CK
Navigator** (`mitre-attack/attack-navigator`).

**The paramount requirement is the improvement loop.** Every run must leave a structured log that a later
agent can read to answer *"what is this tool getting tripped up on?"*, and the repo must close the loop:
logs → report → GitHub issues → fix → re-eval → compare. If a trade-off pits a feature against logging,
logging wins.

Three surfaces, all sharing one deterministic core:

1. **Deterministic Python core** (`intake`, `store`, `search`, `fetch`, `mint`, `lint`, `delta`, `datasets`,
   `runlog`, `allocations`) — no LLM, no LangChain.
2. **MCP server** exposing the core, so Claude Code can drive a mapping with zero LangChain involvement.
3. **LangChain layer** (`agent`, `judge`, `run`) — thin `create_agent` wiring plus a short outer loop.

Design rule that resolves every ambiguity: **business logic and logging live in the deterministic core. The
LangChain layer only chooses what to call and in what order.** A lint rule, a STIX field, an ID policy, or a
log event defined inside `agent.py` is a bug.

---

## 1. Binding decisions

| # | Decision |
|---|---|
| D1 | Managed with **uv**. `uv` is **not installed** on this machine — install it first (`curl -LsSf https://astral.sh/uv/install.sh \| sh` or `brew install uv`). Python **>=3.11** (required by mitreattack-python). |
| D2 | **Provider-agnostic models** via `init_chat_model` strings or model instances. No hardcoded provider. The judge model must be **configurable separately** and should default to a different model than the mapper (self-preference bias). |
| D3 | **Agent-driven keyword search** (BM25) over the store. One concrete implementation, plain functions; no retriever abstraction until a second implementation exists. |
| D4 | `datasets/*-attack.json` are **read-only** to the tool except via `datasets update`. Run output goes to `runs/<run_id>/`. |
| D5 | Linter has **severity tiers**: ERROR blocks mint / fails the attempt; WARN is logged; INFO is a measured fact, never a gate. |
| D6 | **Judge is an outer loop, not LangChain middleware** (`after_model` fires per tool call, the obvious trigger predicate is a silent no-op, there is no run-level hook, and retries resend the whole transcript). |
| D7 | The tool **fetches external references** (http/https, file paths) as evidence. Fetch failures are **logged, never fatal**. |
| D8 | Minted ATT&CK IDs **never collide** with MITRE's, including after dataset upgrades: software `SX####`, groups `GX####`. |
| D9 | **Upgrading to newer upstream datasets is a first-class feature.** |
| D10 | Eval cases: **Pegasus for iOS (S0289)** rich, **Pegasus for iOS thin**, and **CrackMapExec (S0488)** for group links. Heartbleed is a vulnerability, not software — never reintroduce it. |
| D11 | Scored eval harness in-repo; scores land in the run log and index. |
| D12 | **Logging is the top priority** (see §0). Logging lives in the core so MCP-driven and LangChain-driven runs produce identical logs. |
| D13 | Objects follow **MITRE conventions**: MITRE `created_by_ref` and marking, `source_name: "mitre-attack"`. The `SX`/`GX` prefix is the only marker of synthetic origin. |
| D14 | **Use mitreattack-python** (`>=6.2.1`). Construct objects with mitreattack-python classes where the type exists there; otherwise `stix2.v20` classes with `allow_custom=True` (mitreattack-python's own dependency). **Never hand-roll STIX dicts.** Query through `MitreAttackData`. |
| D15 | **Groups are in scope.** The agent may link to **existing** ATT&CK groups only, with verbatim quoted evidence. **New groups are minted only when user-defined in the intake frontmatter** — never formed or minted agentically. |
| D16 | **Intake is markdown + YAML frontmatter** (§3.1). |
| D17 | **Eval evidence is frozen** — committed fixtures, no network during `eval`. Live fetching stays on for `map`. |
| D18 | **ATT&CK IDs are allocated sequentially from a committed global registry** (`datasets/allocations.json`); deltas will be combined. |
| D19 | Datasets are **pinned to a specific ATT&CK release** in `MANIFEST.json`. |
| D20 | Runs have a **budget** and always terminate with a logged `run_end`. |
| D21 | **Build a thin end-to-end slice first** (§5) and broaden only once it produces a valid run log. |
| D22 | Live-model tests are `@pytest.mark.live`, skipped by default. Default tests use a scripted fake chat model. |
| D23 | Issue tracker is **GitHub** (`docs/agents/issue-tracker.md`). Remote: `timothyalder/mitre-mapper` (created; default branch `main`). |

---

## 2. Verified facts

### 2.1 Datasets (`datasets/`)

- Present: `enterprise-attack.json` (26,085 objects, 48 MB), `mobile-attack.json` (2,634), `ics-attack.json`
  (2,172), `MANIFEST.json`. STIX **2.0** bundles; objects carry no `spec_version`. **No `x-mitre-collection`
  object** in any bundle.
- **Pinned at Wave 0: ATT&CK v19.2, STIX 2.0, from `mitre/cti` tag `ATT&CK-v19.2`** (sha256 byte-identical).
  `attack-stix-data` serves STIX 2.1 and is *not* the source. See `docs/adr/0001`.
- Object counts (enterprise / mobile / ics): attack-pattern 858 / 190 / 118 · malware 733 / 125 / 30 ·
  tool 95 / 2 / 0 · intrusion-set 191 / 22 / 16 · relationship 21,262 / 1,889 / 1,667.
- Relationship shapes: `(uses, malware|tool → attack-pattern)`, `(uses, intrusion-set → malware|tool)`,
  `(uses, campaign → malware|tool)`, `(uses, intrusion-set → attack-pattern)`, `(revoked-by, …)`.
- Constants across all bundles: `created_by_ref = identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5`;
  `object_marking_refs = ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"]`; software `labels` is
  exactly `["malware"]` or `["tool"]` (STIX 2.0 required). Timestamps `YYYY-MM-DDTHH:MM:SS.sssZ` with exactly
  3 fractional digits. Mint with `x_mitre_version: "1.0"`, `x_mitre_attack_spec_version: "3.3.0"`.
- Software canonical ref `source_name`: `mitre-attack` everywhere except **7 ICS objects using
  `mitre-ics-attack`**. When *reading*, match `startswith("mitre-") and endswith("-attack")`. When *minting*,
  always `mitre-attack`.
- **ATT&CK IDs are not unique within a bundle**: 224 enterprise IDs are claimed by two objects (95 are a live
  `attack-pattern` + deprecated `course-of-action`, e.g. T1212). ID lookups must be **type-scoped**
  (`get_object_by_attack_id(id, "attack-pattern")`).
- **Liveness:** use one `is_inactive(obj)` = `revoked or x_mitre_deprecated`. 13 mobile attack-patterns and the
  ICS duplicate software are deprecated **but not revoked** (`revoked: false`, no successor).
- **Revoked name-twins** (revoked technique sharing an exact name with a live one): enterprise 106/149, mobile
  11/53, ics 4/9 — e.g. `PowerShell` T1086→T1059.001, `Keychain` T1579→T1634.001. Follow `revoked-by`.
- **Technique ID spaces are disjoint across domains** (zero overlap in all directions, including revoked).
  ICS is mid-renumbering: 16 of 97 active ICS techniques are `T1###` (T1691–T1695 families), not `T0###`.
- `kill_chain_name` is domain-specific (`mitre-attack` / `mitre-mobile-attack` / `mitre-ics-attack`).
- **Cross-domain software:** 21 malware STIX ids appear in two bundles with the same id and both domains in
  `x_mitre_domains` (EKANS, Stuxnet, NotPetya…). `x_mitre_domains` order is not canonical — sort before
  comparing.
- ATT&CK software ID space: `S` + 4 digits, max **S9044**; MITRE is allocating a live **S9000 block**.
- Field coverage: on 100% of software: `type, id, created, modified, created_by_ref, external_references,
  object_marking_refs, name, x_mitre_modified_by_ref, x_mitre_deprecated, x_mitre_domains, x_mitre_version,
  x_mitre_attack_spec_version, labels`. Field profiles are **domain- AND type-specific**
  (`x_mitre_platforms`: 97.1% enterprise malware, 82.1% enterprise tool).
- Relationships: `uses` rels touching software have `description` 99.95%, `external_references` 99.8%.
  Citation markers `(Citation: NAME)` resolve to a `source_name` in the same object's refs at 99.996%
  (relationships) / 99.992% (all objects).
- Calibration (active enterprise software, n=825): median 11 techniques, 6 tactics, 1 group; 26.4% have no
  group. Mobile: only 12.7% of active software has a group link.
- W001 platform intersection is near-useless in ICS (73/97 techniques have platform `["None"]`, 24 have none).

### 2.2 mitreattack-python 6.2.1 (measured)

- Python `>=3.11,<4`; depends on `stix2>=3.0.1`. Modules: `stix20` (`MitreAttackData`,
  `custom_attack_objects`), `diffStix` (`diff_stix` CLI, `DiffStix` class), `attackToExcel`, `navlayers`,
  `collections`, `download_stix`, `release_info`.
- **Read/query only.** `MitreAttackData` wraps `stix2.MemoryStore().load_from_file`. The custom classes cover
  only `x-mitre-*` types (matrix, tactic, data source, …). **There is no Malware/Tool/Intrusion-set/
  Relationship class and no bundle writer.** So per D14: minted malware/tool/intrusion-set/relationship use
  `stix2.v20.{Malware,Tool,IntrusionSet,Relationship}(…, allow_custom=True)`; serialize with
  `json.loads(obj.serialize())`. Without `allow_custom`, `x_mitre_*` properties raise.
- Load time (`MitreAttackData(path)`): **enterprise 10–14 s**, mobile 0.9 s, ics 0.65 s.
- A minted object with a sha256-derived id with version bits forced to 4 and `external_id: "SX0001"` loads
  cleanly; `get_object_by_attack_id("SX0001","malware")`, `get_attack_id`, `get_software`,
  `get_techniques_used_by_software`, `get_software_using_technique` all work. A **uuid5 id is rejected**
  (stix2 enforces UUIDv4 for STIX 2.0) — the v4-bit forcing is mandatory.
- `diff_stix --old DIR --new DIR` compares bundle versions into additions / major / minor / patch changes /
  revocations / deprecations / deletions (JSON + markdown). Took 25.6 s on mobile. **It does not track `uses`
  relationships** (only mitigation/detection relationships) — we add our own check.

### 2.3 Consumers (measured by building them)

- **attack-website**: ingests bundles from `ATTACK_WEBSITE_STIX_LOCATION_{ENTERPRISE,MOBILE,ICS}` (URL or local
  path) into a `stix2.MemoryStore`; custom bundles are a supported workflow (`docs/CUSTOMIZING.md`). A build
  with a minted `SX0001` software + `GX0001` group rendered `/software/SX0001/` and `/groups/GX0001/`; the
  technique page links back, both indices and search list them, SX0001's page lists both the minted group
  and the real group linked to it. Only gap: `random_page.py` regexes `S[0-9]{4}` / `G[0-9]{4}` — GX is
  excluded from the random-page pool (accepted, document it).
- **attack-navigator** (v5.3.2): loads bundles via `config.json` (`collection_index_url` or
  `versions.entries[].domains[].data`) or a layer's `customDataURL`. **ATT&CK ID is read from
  `external_references[0].external_id`** — the `mitre-attack` ref must be **first** (lint E009). No regex on
  S/G IDs. SX software highlights its techniques. A group highlights only its **direct**
  `intrusion-set → attack-pattern` relationships; group→software→technique is never followed (true for real
  groups too, e.g. Confucius in mobile).
- No consumer needs an `x-mitre-collection` object or bundle metadata updated when objects are added.

---

## 3. Architecture

```
mitre-mapper/
├── pyproject.toml, uv.lock, README.md, AGENTS.md, CLAUDE.md, PLAN.md, .gitignore
├── docs/agents/                     # issue tracker / triage labels / domain docs config
├── datasets/
│   ├── MANIFEST.json                # pinned ATT&CK release per domain: version, url, sha256, fetched_at
│   ├── allocations.json             # COMMITTED global SX/GX registry
│   ├── changelogs/<old>→<new>.{json,md}   # diff_stix output from each update
│   └── {enterprise,mobile,ics}-attack.json   # gitignored
├── intake/                          # user intake files (*.md)
├── skills/map-software/
│   ├── SKILL.md                     # mapping procedure; body = system prompt
│   └── references/{linter-rules.md,stix-shapes.md,judge-rubric.md}
├── .claude/skills/diagnose-runs/SKILL.md   # the improvement-loop skill
├── src/mitre_mapper/
│   ├── models.py        # pydantic contracts
│   ├── intake.py        # parse + validate intake markdown
│   ├── store.py         # AttackStore over MitreAttackData; liveness, revoked redirect, holdout
│   ├── search.py        # BM25 over the store
│   ├── fetch.py         # reference fetchers + cache; never raises
│   ├── allocations.py   # SX/GX registry
│   ├── mint.py          # stix2/mitreattack-python construction; deterministic ids
│   ├── lint.py          # rule registry with severities
│   ├── delta.py         # delta write / combine / materialize / doctor
│   ├── datasets.py      # release pinning, update, diff_stix
│   ├── runlog.py        # events, index, run.md, report, review, budget
│   ├── tools.py         # the single tool surface (plain functions, logged) shared by MCP + LangChain
│   ├── judge.py         # judge(proposal, intake, evidence) -> Verdict
│   ├── agent.py         # create_agent wiring over tools.py
│   ├── run.py           # map_software(): the outer loop
│   ├── mcp_server.py    # FastMCP over tools.py
│   └── cli.py           # typer
├── evals/{cases/*.yaml, fixtures/<case>/{intake.md,evidence/*.txt}, score.py}
├── tests/
└── runs/                # partially committed — see §3.9
```

### 3.1 Intake (`intake.py`)

```markdown
---
name: Pegasus for iOS
type: malware                 # malware | tool
aliases: [Pegasus]
platforms: [iOS]
domains: [mobile-attack]      # optional; else derived from platforms
references:
  - source_name: Lookout Pegasus
    url: https://...
    description: "Lookout. (2016). Technical Analysis of Pegasus Spyware."
techniques: [T1430]           # optional, user-pinned
groups:                       # optional, user-asserted
  - ref: G0142                # existing ATT&CK group
  - new:                      # user-defined → minted GX####
      name: Example Actor
      aliases: [...]
      description: ...
      references: [...]
      techniques: [T1404]     # optional, user-asserted group→technique (Navigator highlighting)
---
Free-text intake prose (becomes the description input).
```

- Validate with pydantic **before any model call**; an invalid file fails fast with a logged `intake_invalid`.
  `platforms` is **required when the software maps to enterprise-attack** (E006: 97% of enterprise malware
  carries `x_mitre_platforms`, and the agent cannot fix a missing value).
- **User-asserted items** (pinned techniques, `groups[].ref`, `groups[].new`, new-group `techniques`) are
  always included, cited to the intake file (a `mitre-mapper intake` external reference), flagged
  `user_asserted: true` in the proposal and log, **never sent to the judge**, linted only as INFO (I004), and
  **excluded from eval scoring**. Eval fixtures must contain none.
- Domain resolution is deterministic: explicit `domains`, else platforms (`iOS`/`Android` → mobile; ICS
  platforms → ics; else enterprise). No LLM triage — technique ID disjointness means E002 catches
  cross-domain hallucinations for free.

### 3.2 Store (`store.py`, `search.py`)

- Built on **`MitreAttackData`**, one instance per domain, **loaded lazily** (a mobile-only run costs ~1 s).
  Cache per process. Re-measure enterprise load after the build; add a pickle cache keyed by manifest sha256
  **only** if it hurts in practice.
- Use the library's helpers (revoked-by, subtechniques, software↔technique, group↔software) rather than
  building our own traversal indices. A thin `dict[(stix_type, attack_id)] → obj` lookup is acceptable where
  the library has none, always type-scoped.
- **Read-only.** Tool handlers return copies. Say so in the module docstring.
- **Liveness is a store invariant:** search and get exclude inactive objects by default. If an ID resolves to
  a revoked object, follow `revoked-by`, return the successor, emit `revoked_redirect`. `include_inactive=True`
  is a human-only escape hatch.
- **Group alias resolution:** `resolve_group(name)` matches name + `aliases` case-insensitively (reports use
  vendor names: CARBON SPIDER = FIN7, Chafer = APT39, IRON LIBERTY = Dragonfly, Octo Tempest = Scattered
  Spider).
- `search.py`: BM25 over name + description + aliases (techniques, groups, software). Plain functions. Expose
  a `get_software_techniques(attack_id)` tool so the agent can inspect how comparable software was mapped.
- `holdout: HoldoutSpec | None` (§4.2) applied at load.

### 3.3 Fetch (`fetch.py`)

- Dispatch dict `scheme → callable`: `http(s)` via httpx (follow redirects — old us-cert/fireeye URLs
  redirect), `file://` or bare path → disk. Handle `url: None` (S0289 has one).
- **Never raises:** returns `FetchResult(ok=False, error=…)` and emits `reference_fetch_failed`.
- Extraction: HTML → text (trafilatura), PDF → text (pypdf), text/markdown as-is. Failures logged.
- Cache: `runs/<id>/evidence/<slug>.txt` + content-addressed `.cache/fetch/<sha256>`; `--no-cache`.
- Truncation emits `evidence_truncated` with original length.
- Agent reads evidence through a `get_evidence(source_name)` tool, not the system prompt.
- `--evidence-dir DIR` makes fetch read only from a frozen directory (used by `eval`; network disabled).

### 3.4 Allocations and mint (`allocations.py`, `mint.py`)

- **Deterministic STIX ids, v4-shaped** (uuid5 is rejected by stix2):
  ```python
  def deterministic_uuid4(*parts: str, namespace: str = "mitre-mapper") -> uuid.UUID:
      digest = hashlib.sha256((namespace + ":" + ":".join(parts)).encode()).digest()[:16]
      return uuid.UUID(bytes=digest, version=4)
  ```
  Software keyed on normalized name + type; groups on normalized name; relationships on
  `(type, source_ref, target_ref)`.
- **`datasets/allocations.json`** (committed): `{"SX0001": {"stix_id": …, "name": …, "first_run": …}, …}`
  and the same for `GX`. Sequential, global, never reused. Re-minting the same name returns the existing ID.
  The registry write is the only shared-state write in the tool — make it atomic (write temp + rename).
- Construction per D14: `stix2.v20` classes with `allow_custom=True`; mitreattack-python classes for any
  `x-mitre-*` type. MITRE `created_by_ref`, marking, `x_mitre_modified_by_ref`; `labels`;
  `x_mitre_version "1.0"`; `x_mitre_attack_spec_version "3.3.0"`; `x_mitre_domains` sorted;
  `external_references[0] = {"source_name": "mitre-attack", "external_id": "SX0001", "url": "https://attack.mitre.org/software/SX0001"}`
  (the website derives the same path). Groups likewise with `/groups/GX0001`.
- Relationships: `software → attack-pattern` and `intrusion-set → software`, each with description +
  external references; agent-proposed group links carry the verbatim quote in the description with a
  `(Citation: …)` marker.
- **Cross-domain merge:** one software object per run; `x_mitre_domains` = sorted union of domains with
  accepted proposals; relationships partitioned by domain.
- New groups: **only** from `intake.groups[].new`. Same name across intake files → same `GX` (deterministic
  id). Conflicting definitions → W005, first-minted wins until the user reconciles.

### 3.5 Lint (`lint.py`)

Registry of `LintRule(id, severity, description, check(proposal, store, domain, evidence) -> list[LintFinding])`.
Every rule has a test pinning it against real data. **Rules that count things are INFO, never ERROR** — a
quota manufactures false positives.

**ERROR**
| id | rule |
|---|---|
| E001 | ≥1 technique relationship **unless** `declined: true` (a decline is `declined: true` + `techniques: []` + rationale) |
| E002 | every technique ID exists **in this domain**, type-scoped, and is active |
| E003 | no duplicate `(relationship_type, source_ref, target_ref)` |
| E004 | every minted relationship has a non-empty `description` and ≥1 external reference |
| E005 | every `(Citation: NAME)` marker resolves to a `source_name` in the same object's refs |
| E006 | minted object carries every field present in ≥95% of real objects of that (domain, type) |
| E007 | bundle domain ∈ `x_mitre_domains` (subset, not equality) |
| E008 | valid STIX ids; every `source_ref`/`target_ref` resolves (store or same delta) |
| E009 | `external_references[0]` is `source_name: "mitre-attack"` with `external_id` matching `^SX\d{4}$` / `^GX\d{4}$` and consistent with `allocations.json` |
| E010 | **round-trip:** the minted objects merged into the domain bundle load through `MitreAttackData` and resolve via `get_object_by_attack_id` and `get_techniques_used_by_software` |
| E011 | **agent-proposed group link quote:** the relationship carries a verbatim quote that appears in fetched evidence text (whitespace-normalized) and contains the software name/alias **and** the ATT&CK group name/alias. Log which aliases matched. |

**WARN**: W001 platform intersection (software ∩ technique platforms ≠ ∅; ignore in ICS) · W002
name/alias collision with existing software ("this may be S0605 — review") · W003 parent and child technique
both proposed · W004 `tool` in ics (zero precedent) · W005 conflicting user-defined group definition.

**INFO**: I001 technique count vs domain median · I002 tactic count vs median · I003 group-link count ·
I004 user-asserted items present (count, by kind). Calibrate mobile/ics medians at build time.

Deliberately **not** rules (do not re-add): "≥2 tactics", "≥1 group", "≥3 techniques" (quotas, false for
real data), "`x_mitre_domains` equals bundle domain" (wrong for 21 objects), "sub-technique where parent too
generic" (no deterministic definition).

### 3.6 Judge (`judge.py`)

- Pure `judge(proposal, intake, evidence, model) -> Verdict` with **per-rubric-item** results
  (e.g. `evidence_grounding`, `technique_specificity`, `omission_check`, `group_attribution`).
- Sees only agent-proposed items, never user-asserted ones.
- `judge-rubric.md` is loaded by the judge directly and is **not readable by the mapping agent** (not in the
  `read_reference` allowlist) — otherwise approval carries no independent information.
- Replayable standalone: `mitre-mapper judge --run <id> --attempt <n>` re-runs against `proposal_<n>.json`.

### 3.7 Datasets and deltas (`datasets.py`, `delta.py`)

- **MANIFEST.json** per domain: `attack_release`, versioned `source_url`
  (`attack-stix-data/<domain>/<domain>-<version>.json`), `sha256`, `fetched_at`, `n_objects`.
- Release list comes from `attack-stix-data/index.json`; bundles are downloaded from `mitre/cti` at tag
  `ATT&CK-v<version>` (STIX 2.0). Done for v19.2 at Wave 0 — see `docs/adr/0001`.
- `mitre-mapper datasets update [--to VERSION]`: read upstream `index.json`, download the target release to a
  temp dir, run `diff_stix` old→new into `datasets/changelogs/`, swap files atomically, update the manifest,
  then run `delta doctor --all`.
- `runs/<id>/delta.json`: `schema_version, run_id, created, dataset_manifest (releases + sha256), tool_version,
  git_sha, prompt_sha256, allocations used, target_domains, objects`. Only new objects. Never write patched
  bundles per run.
- `mitre-mapper materialize <run_id>... [--domain] [--out]`: combine one or more deltas (dedupe by STIX id —
  deterministic ids make shared groups collapse) into patched bundles. Re-runs E010 on the output.
- `mitre-mapper delta doctor <run_id>|--all`: against current datasets + latest changelog report: targets
  that no longer exist, became revoked/deprecated (with successors), **our own `uses`-target resolution
  check** (diff_stix doesn't cover `uses`), whether MITRE has since published real software/groups matching
  our names/aliases (retire the delta), and allocation non-collision.
- `docs/rendering.md`: how to build attack-website (`ATTACK_WEBSITE_STIX_LOCATION_*`) and point Navigator
  (`config.json` data URLs) at materialized bundles. Document: GX groups are not in the website's random-page
  pool; groups highlight in Navigator only via direct group→technique relationships (user-asserted
  `techniques` on new groups).

### 3.8 Tools, agent, outer loop (`tools.py`, `agent.py`, `run.py`)

- **`tools.py` is the single tool surface**: plain functions (`search_techniques, get_technique,
  search_groups, get_group, search_software, get_software, get_software_techniques, get_evidence,
  read_reference, lint_proposal, mint_delta`), each wrapped by `runlog` so **every call logs identically**
  whether invoked by MCP or LangChain. `agent.py` and `mcp_server.py` are thin adapters over it.
- `agent.py`: `create_agent` with structured output (`MappingProposal`); verify the current `langchain`
  `create_agent` signature at Wave 0. Raise LangGraph `recursion_limit` deliberately and log it. Accept model
  strings or instances.
- `run.py` outer loop:
  ```
  map_software(intake_path, max_attempts=3, budget):
    run_start; intake = parse+validate; domains = resolve_domains(intake)
    evidence = gather_evidence(intake)              # never raises
    for domain in domains:
      feedback = None
      for attempt in 1..max_attempts:
        proposal = agent.invoke(messages(intake, evidence, domain, feedback))   # budget-checked
        dump proposal_<n>.json; findings = lint(...); dump lint_<n>.json
        if ERROR: feedback = render(findings); retry event; continue
        verdict = judge(...); dump verdict_<n>.json
        if verdict.approved: break
        feedback = render(verdict)
    merge cross-domain; add user-asserted items; final lint; mint delta if clean
    ALWAYS (finally): run_end + index row + run.md, whatever happened
  ```
- **Budget (D20):** `--max-model-calls` (default 60 per domain) and optional token cap. Exceeding it →
  `terminal_state: budget_exhausted`. Provider errors (rate limit, quota, auth) are caught →
  `provider_error` with the provider's message. Both still write `run_end`, index row and `run.md`. A test
  must kill a fake-model run mid-loop and assert the index row exists.
- `RunLogMiddleware` (per-turn logging) is the only LangChain middleware, and it only forwards to `runlog`.

### 3.9 Run log and the improvement loop (`runlog.py`, `.claude/skills/diagnose-runs/`)

This is the paramount feature. **The cross-run index and the closed loop are the deliverable, not the
per-run log.**

**`runs/<run_id>/`**
- `events.jsonl` — one small JSON object per line, `event` discriminator.
- `prompt.txt` — the verbatim system prompt, once.
- `intake.md` — copy of the intake file.
- `<domain>/proposal_<n>.json`, `lint_<n>.json`, `verdict_<n>.json` — replayable.
- `calls/<n>.json` — full tool payloads (search results etc.); events carry IDs + hash only.
- `evidence/` — fetched text.
- `delta.json` (if minted), `scores.json` (eval mode).
- `run.md` — short human summary: outcome, techniques/groups with evidence, findings, unmatched actors.
- `review.json` — the user's verdict (below).

**Events:** `run_start, intake_invalid, domain_resolved, reference_fetch, reference_fetch_failed,
evidence_truncated, search, revoked_redirect, tool_call, proposal_draft, lint_result, judge_verdict, retry,
group_quote_check, unmatched_actor, user_asserted, merge, allocation, mint, budget_exhausted,
provider_error, run_end, error`.

**Must be logged** (each answers a "what is it tripping on" question):
- Every search: query, k, returned IDs, and which the agent later cited. **Zero-hit queries** counted.
- **Rejected candidates**: techniques/groups the agent saw and did not cite.
- Every lint finding with `rule_id`; judge verdicts **per rubric item**.
- Retry count and the **set-diff between proposal N and N+1**.
- `group_quote_check`: pass/fail, which aliases matched, evidence source.
- `unmatched_actor`: actor name + quote when evidence names an actor with no ATT&CK group.
- Eval mode: **retriever recall@k** vs gold, separately from end-to-end recall.
- Per-call tokens/latency aggregated into `run_end` (not one event per call).

**`runs/index.jsonl`** — one append-only line per run:
```json
{"run_id":"...","ts":"...","software_name":"...","intake_sha256":"...","domains":[...],
 "model":"...","judge_model":"...","git_sha":"...","prompt_sha256":"...","tool_version":"...",
 "dataset_release":{"mobile-attack":"..."},"n_model_calls":12,"tokens":{"in":0,"out":0},"wall_s":0,
 "attempts":{"mobile-attack":2},
 "terminal_state":"minted|declined|lint_failed|judge_rejected|budget_exhausted|provider_error|error",
 "error_rule_ids":[],"warn_rule_ids":[],"judge_fail_items":[],"zero_hit_queries":0,
 "unmatched_actors":0,"fetch_failures":0,"eval_case":null,"eval_scores":null,"review":null}
```
`git_sha` and `prompt_sha256` are **required** — without them no cross-run comparison is interpretable.

**Git policy:** full run folders are gitignored; **commit `runs/index.jsonl`, `runs/*/run.md`,
`runs/*/review.json`**:
```
runs/*/*
!runs/*/run.md
!runs/*/review.json
```
`mitre-mapper runs archive [--older-than]` tars old run folders for safekeeping.

**`mitre-mapper review <run_id>`** — interactive (and `--file` non-interactive): mark each technique/group
accepted or rejected, list missed ones, free-text notes → `review.json`; the summary is folded into the index
row (the index is append-only, so append a `review` record line keyed by `run_id`; `report` joins them).
Reviewed runs become **additional ground truth** that `eval` can score against.

**`mitre-mapper report [--last N] [--since] [--json]`** — most frequent ERROR/WARN rule ids, judge rubric
failure rates, zero-hit query rate, fetch-failure rate, unmatched actors, terminal-state distribution,
review precision/recall, and score trend grouped by `prompt_sha256` and `git_sha`.

**`/diagnose-runs` skill** (`.claude/skills/diagnose-runs/SKILL.md`): runs `report --json`, reads the
relevant runs' events, `run.md` and reviews, clusters recurring failure patterns, and files **one GitHub issue
per pattern** (per `docs/agents/issue-tracker.md`, labelled `needs-triage`) with run IDs and event excerpts
as evidence and a proposed fix hypothesis. The issue body names the eval command that will confirm a fix.
Closing the loop: fix on a branch → `mitre-mapper eval` → `report` compares the new `git_sha`/`prompt_sha256`
against the baseline.

### 3.10 SKILL.md and MCP

- `skills/map-software/SKILL.md` is the single source of truth for the mapping procedure. Its body is the
  system prompt; `references/*.md` are served lazily via `read_reference(name)` (allowlist excludes
  `judge-rubric.md`).
- `mcp_server.py` (FastMCP) exposes `tools.py`. `mint_delta` **refuses on any ERROR**. MCP sessions open a run
  via `start_run(intake_path)` and close it via `mint_delta` or `end_run(reason)`, so Claude Code-driven runs
  appear in the index like any other. An MCP session that disconnects without ending is closed as
  `terminal_state: abandoned` on the next server start.
- Portability: SKILL.md + MCP server is a complete LangChain-free implementation.

### 3.11 Config

A `@dataclass` with defaults plus typer options; no pydantic-settings. Knobs: `model`, `judge_model`,
`datasets_dir`, `runs_dir`, `max_attempts`, `max_model_calls`, `fetch`, `fetch_timeout`, `evidence_dir`.
Model defaults read from one env var each (`MITRE_MAPPER_MODEL`, `MITRE_MAPPER_JUDGE_MODEL`).

---

## 4. Evals (`evals/`)

### 4.1 Cases

| case | domain | input | gold |
|---|---|---|---|
| `pegasus-ios` | mobile | user intake prose + references, **frozen evidence** | S0289: 15 techniques — T1636.002, T1421, T1644, T1456, T1404, T1645, T1426, T1636.003, T1636.004, T1660, T1430, T1664, T1409, T1429, T1658 (T1636 itself is *not* in the set); 0 groups |
| `pegasus-ios-thin` | mobile | ATT&CK's S0289 description only (~39 words) **with its links and URLs stripped**, no references | same |
| `crackmapexec` | enterprise | user intake prose + references, frozen evidence | S0488: 20 techniques; 5 groups — G0035 Dragonfly, G0046 FIN7, G0069 MuddyWater, G0087 APT39, G1003 Ember Bear |

Rich-vs-thin gap measures what evidence contributes. Frozen evidence for CrackMapExec: CISA TA18-074A
(Dragonfly) and CrowdStrike Carbon Spider (FIN7) were verified live; MuddyWater (TrendMicro/Symantec) timed out
or untested; APT39 (FireEye) is dead; Ember Bear is a CISA PDF. Freeze whatever is obtainable and record which
groups have evidence in the case YAML (`groups_with_evidence`). Pegasus: the Lookout PDF returns 403 —
freeze what is obtainable and note gaps; never fetch during `eval`.

### 4.2 Holdout (predicate, not a list)

- **Pegasus:** drop objects whose name / aliases / description / external_references match
  `(?i)pegasus|chrysaor|\bnso\b` (**anchored `\bnso\b`** — unanchored deletes T1430 and T1660 via "Insomnia" /
  "sensors"), plus S0316 entirely, plus their relationships. Known channels this closes: S0289's description
  links S0316 and its own URL; S0316 (Jaccard 0.32 with S0289); `Chrysaor` alias; Confucius group refs;
  enterprise T1583/T1584/T1588/T1588.005 carrying Pegasus citation keys.
- **CrackMapExec:** drop objects matching `(?i)crack\s*map\s*exec` (not "CME") plus S0488 and its
  relationships, and **mask** the 4 group→technique relationships that name it (Dragonfly T1110.002, T1588.002;
  APT39 T1046, T1135). Closest twin S0165 OSInfo, Jaccard 0.25.
- Print the holdout diff (removed, by type) into the run log. **Leakage-probe tests** assert zero hits for the
  same anchored patterns on the held-out store.

### 4.3 Scoring

1. **Technique recall** against ATT&CK at three granularities: exact, parent-lenient, tactic.
2. **Unjustified-addition rate**: for proposed techniques not in ATT&CK, the judge scores only "does the cited
   evidence support this". Precision-against-evidence replaces precision-against-ATT&CK.
3. **Group recall, two numbers:** vs all ATT&CK groups, and vs `groups_with_evidence`. The gap is evidence
   loss, not tool error. **Group precision against evidence** via E011 + judge `group_attribution`.
4. **Baselines on every run:** copy-nearest-twin (Pegasus: copy S0316 → P 0.50 / R 0.47 / F1 0.48;
   CrackMapExec: copy S0165) and a no-retrieval model-only baseline. A score that clears neither means nothing.
5. Reviewed runs (`review.json`) are scored as extra cases when `--include-reviews`.

Scores → `runs/<id>/scores.json` and the index row.

---

## 5. Build order

Within a wave, launch agents in one message; each owns disjoint files. Give every agent this file and the
instruction: *"verify the plan's facts against the real datasets/libraries — spot-check at least one before
relying on it."* Every wave after 2 ends by re-running the slice test and `report`.

**Wave 0 — scaffold (main session).** Install uv; `git` remote (`gh repo create`); `uv init`, Python >=3.11;
deps: `mitreattack-python>=6.2.1` (brings `stix2`), `langchain`, `langgraph`, `typer`, `pydantic`, `pyyaml`
(or `python-frontmatter`), `rank-bm25`, `httpx`, `pypdf`, `trafilatura`, `fastmcp`; dev: `pytest`.
`.gitignore` (§3.9, datasets json, `.cache/`). Identify and pin the dataset release (§3.7). Check the
`langchain` version and `create_agent` signature. Create `datasets/allocations.json` (empty).

**Wave 1 — contracts (2 agents).** A: `models.py` (IntakeSpec, ExternalReference, TechniqueMapping,
GroupMapping, NewGroup, MappingProposal, Verdict, RubricItem, LintFinding, Severity, Delta, RunRecord,
FetchResult, Review). B: `runlog.py` core (events, index, run.md, budget, always-finalize context manager).

**Wave 2 — thin end-to-end slice (1–2 agents; consider opus).** Minimal `intake`, `store` (MitreAttackData,
liveness, revoked redirect, type-scoped lookup), `search`, `allocations`, `mint` (software + technique rels),
`lint` (E001, E002, E008, E009, E010 only), `tools.py`, `agent.py`, `run.py`, `cli map` + `cli report`.
**Gate:** with the fake chat model, Pegasus iOS produces `delta.json`, an index row, `run.md`, and a `report`;
a budget-kill test and a provider-error test also produce index rows. Do not proceed until green.

**Wave 3 — broaden the core (4 agents).** A: `fetch.py` + cache + frozen evidence dir. B: full `lint.py`
(all rules, each pinned against real data). C: groups — store alias resolution, new-group minting, group
relationships, E011, W005. D: `judge.py` + `judge-rubric.md` + per-item logging.

**Wave 4 — surfaces and datasets (3 agents).** A: `datasets.py` + `delta.py` (pinning, update with
`diff_stix`, materialize/combine, doctor) + `docs/rendering.md`. B: `mcp_server.py` (start/end run, abandoned
detection). C: `SKILL.md` + `references/{linter-rules.md,stix-shapes.md}` — **use opus**; this file is the
product.

**Wave 5 — the loop and evals (3 agents).** A: `evals/` — cases, fixtures with frozen evidence, holdout
predicates, leakage probes, `score.py`, baselines. B: `review` command + `report` full aggregation + `runs
archive`. C: `.claude/skills/diagnose-runs/SKILL.md`.

**Wave 6 — integration (main session).** Live Pegasus + CrackMapExec runs (`-m live`); `eval`; `report`;
materialize and build attack-website + Navigator per `docs/rendering.md` and confirm SX/GX render. Then run
`/diagnose-runs` on the logs from a fresh session and ask *"what is this tool getting tripped up on?"* — if
the logs can't answer it, §3.9 is not done.

---

## 6. Acceptance criteria

1. `uv run mitre-mapper map intake/pegasus-ios.md` writes `runs/<id>/delta.json`, an index row and `run.md`.
2. A run killed by budget or a provider error still writes `run_end`, an index row and `run.md`
   (`terminal_state` budget_exhausted / provider_error). Tested with the fake model.
3. `uv run mitre-mapper eval` runs all three cases **with no network**, printing technique recall (3
   granularities), unjustified-addition rate, both group-recall numbers, and both baselines.
4. Leakage probes pass for both holdouts (anchored patterns).
5. Pegasus rich beats the copy-S0316 baseline (F1 0.48). If not, say so plainly; do not tune the metric.
6. `report --last 10` produces the cross-run summary; `review <run_id>` writes `review.json` and `report`
   reflects it.
7. `/diagnose-runs` files at least one well-evidenced GitHub issue from real run logs (or states there is no
   recurring pattern, with evidence).
8. `datasets update` to a newer release (or `--to` the current one in a test) writes a changelog and `delta
   doctor --all` runs clean.
9. A materialized bundle containing SX software + GX group loads through `MitreAttackData` (E010), builds
   attack-website with `/software/SX####/` and `/groups/GX####/` pages, and shows in Navigator.
10. Claude Code completes a mapping using only SKILL.md + the MCP server, and that run appears in
    `runs/index.jsonl`.
11. `judge()` is called exactly once per lint-clean proposal (unit test).
12. Combining two deltas that share a user-defined group yields one `intrusion-set`.
13. No module outside `agent.py`, `judge.py`, `run.py` imports `langchain`.
14. No minted object is built from a hand-written STIX dict (grep/test: construction only via
    `stix2.v20` / mitreattack-python classes in `mint.py`).

---

## 7. Open items

- Write the intake prose for `pegasus-ios` and `crackmapexec` fixtures (user's own words + reference list);
  freeze obtainable evidence.
- Calibrate I001/I002 medians for mobile and ics.
- If enterprise load (10–14 s) hurts CLI ergonomics, add the manifest-keyed pickle cache.
- Optional later: publish a collection index so Navigator can load materialized bundles via
  `collection_index_url`.
