# Rendering minted objects on the ATT&CK website and in Navigator

A run writes only `runs/<id>/delta.json`. To see the objects, materialize one or more deltas into
patched copies of the pinned bundles, then point the upstream tools at them.

```sh
uv run mitre-mapper materialize <run_id> [<run_id> ...] [--domain mobile-attack] [--out .cache/materialized]
```

Output: `<out>/<domain>.json` (STIX 2.0, same shape as `datasets/<domain>.json`). Deltas are
combined first (deduplicated by STIX id, so a user-defined group shared by two intake files is one
`intrusion-set`). An object is added to a domain bundle when its `x_mitre_domains` include that domain;
a relationship only when both endpoints are in that bundle. `materialize` then loads the **entire**
patched bundle with `MitreAttackData` and checks that every `SX`/`GX` object resolves with
`get_object_by_attack_id` and that each `SX` software's `get_techniques_used_by_software` matches its
`uses` relationships. It refuses (and writes no file for that domain) on failure or if an `SX`/`GX` id
already exists upstream. The pinned `datasets/` files are never modified.

Timing (this machine): mobile-only about 5 s, enterprise about 25 s (bundle load dominates).

Before rendering, `uv run mitre-mapper delta doctor --all` confirms the deltas still apply to the
current datasets.

## attack-website (`mitre-attack/attack-website`)

The site is generated from STIX bundles and accepts custom ones. Each location is a URL or a local
file path (`docs/CUSTOMIZING.md`):

```sh
export ATTACK_WEBSITE_STIX_LOCATION_ENTERPRISE=$PWD/.cache/materialized/enterprise-attack.json
export ATTACK_WEBSITE_STIX_LOCATION_MOBILE=$PWD/.cache/materialized/mobile-attack.json
export ATTACK_WEBSITE_STIX_LOCATION_ICS=$PWD/datasets/ics-attack.json   # unpatched domains: the pinned file
# then, in an attack-website checkout (needs Just, uv, Node.js; see its docs/DEVELOPMENT.md):
just install-deps
just build-full-website --attack-brand --all-extras
```

Expect `/software/SX0001/` and `/groups/GX0001/`; the technique pages link back to the software, and
the software page lists both the minted group and any real group linked to it.

Measured gaps (PLAN section 2.3):

- `random_page.py` matches `S[0-9]{4}` / `G[0-9]{4}`, so `GX####` groups are excluded from the
  random-page pool. Accepted. (`SX####` also fails `S[0-9]{4}`; treat both as excluded and verify when
  you build.)
- A non-materialized domain must still be given a location, otherwise the site downloads upstream's.

## ATT&CK Navigator (`mitre-attack/attack-navigator`)

Navigator reads bundles from `nav-app/src/assets/config.json`. Either:

1. `versions.enabled: true` and an entry whose `domains[].data` lists the materialized file(s) (the
   shipped `config.json` has an example entry, `assets/custom-enterprise-attack.json`; copy the
   materialized bundle into `nav-app/src/assets/` or serve it over HTTP), identifier `enterprise-attack`
   / `mobile-attack` / `ics-attack`; or
2. keep the default config and open a layer file whose `customDataURL` points at the bundle.

Behaviour to know about (measured against Navigator v5.3.2):

- The ATT&CK id shown is read from `external_references[0].external_id`. The `mitre-attack` reference
  must therefore be **first** (lint E009 enforces this for every minted object).
- A software object (`SX####`) highlights the techniques it `uses`.
- A group highlights only its **direct** `intrusion-set -> attack-pattern` relationships.
  group -> software -> technique is never followed (true for real groups too). To highlight techniques
  for a user-defined `GX####` group, give the new group `techniques:` in the intake file; the tool mints
  those direct, user-asserted relationships.

## What was and was not verified

Verified in this session by reading the upstream docs (`attack-website` README, `docs/CUSTOMIZING.md`,
`docs/DEVELOPMENT.md`; `attack-navigator` README and shipped `config.json`):

- the `ATTACK_WEBSITE_STIX_LOCATION_{ENTERPRISE,MOBILE,ICS,PRE}` variables (URL or local path), the
  `ATTACK_WEBSITE_` prefix, and that STIX 2.0 and 2.1 are both accepted;
- the `just install-deps` / `just build-full-website --attack-brand --all-extras` commands;
- the Navigator `config.json` keys `collection_index_url` and `versions.entries[].domains[].data`.

Not re-verified here (taken from the planning-session builds in PLAN section 2.3, not repeated in this
wave): an actual website build and Navigator session with the current minted objects; the `customDataURL`
layer route; the random-page regex behaviour for `SX`. Wave 6 re-does the real build (acceptance #9).
The Navigator README's "Loading Content from Local Files" section was linked but not read.
