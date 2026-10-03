# 0001 — Dataset source is mitre/cti (STIX 2.0); LangChain 1.x baseline

Date: 2026-10-03 · Status: accepted

## Dataset source

The bundles in `datasets/` are **ATT&CK v19.2 in STIX 2.0**, byte-identical (sha256) to
`mitre/cti` at tag `ATT&CK-v19.2`. The previous manifest claimed `attack-stix-data/master`, which is wrong:
`attack-stix-data` publishes **STIX 2.1** (objects carry `spec_version: "2.1"`, software has `is_family`
instead of `labels`, and each bundle includes an `x-mitre-collection` object). Apart from those encoding
differences, the 19.2 objects are identical in both repos (same ids, same `modified`).

Consequences:

- `MANIFEST.json` pins `attack_release: "19.2"` with `mitre/cti` tag URLs.
- `datasets update` reads the **list of releases** from `attack-stix-data/index.json`, but **downloads** from
  `https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v<version>/<domain>/<domain>.json`, so we stay on
  STIX 2.0 (the format mint targets: `labels`, no `spec_version`).
- If `mitre/cti` ever stops getting releases, switching to 2.1 means changing mint (`is_family`,
  `spec_version`), the E006 field profiles, and the tests that pin STIX 2.0 facts. That's a deliberate
  migration, not a drop-in swap.

## LangChain baseline (measured at Wave 0)

langchain 1.4.3, langchain-core 1.6.6, langgraph 1.2.12, mitreattack-python 6.2.1, stix2 3.0.2,
fastmcp 4.0.10.

`create_agent(model, tools=None, *, system_prompt, middleware, response_format, state_schema,
context_schema, checkpointer, store, …)`. `response_format` accepts a pydantic type or
`ToolStrategy`/`ProviderStrategy`/`AutoStrategy`. `GenericFakeChatModel` does not implement `bind_tools`,
so tests use a project-local scripted fake that emits tool calls (see `tests/fakes.py`, Wave 2).
