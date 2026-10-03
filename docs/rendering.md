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

## Verified build (Wave 6, 2026-10-03)

Both consumers were built from source on macOS (x86_64, Node v25.8.1, uv 0.12.22) against one
materialized bundle and checked page by page. Upstream commits:

| Repo | Commit | Notes |
| --- | --- | --- |
| `mitre-attack/attack-website` | `3c038272ab4a7b517cf75c820e16190eb80cbb00` (2026-10-01) | Python 3.13.16 venv (its `install-deps` pins 3.13) |
| `mitre-attack/attack-navigator` | `734a1caba29fcd51f20b9ca239ce652b3354a47e` (2026-09-10) | `nav-app` v5.3.2, Angular 19 |

The fixture was one mobile delta made with the scripted fake model (`tests/fakes.py`), a scratch runs dir and a
scratch copy of `allocations.json`. It had `SX0001` "Wave6 Render Spyware" (`uses` T1430, T1429, T1409) and a
user-defined `GX0001` "Wave6 Render Actor" with `techniques: [T1404, T1430]`, and the intake file had
`groups: [{ref: G0142}, {new: ...}]`. The result was 1 malware, 1 intrusion-set and 7 relationships.

```sh
uv run mitre-mapper materialize <run_id> --runs-dir <scratch>/runs --out <scratch>/bundles   # 3.3 s, mobile only
```

## attack-website (`mitre-attack/attack-website`)

The site is generated from STIX bundles and accepts custom ones. Each location can be a URL or a local
file path (`docs/CUSTOMIZING.md`). Every domain needs a location: an unset one is downloaded from
`mitre/cti` master, which would mix releases.

`just` is optional. The commands below are the `justfile` recipes run by hand (`just install-deps`,
`just build-assets`, `just build-website`):

```sh
git clone --depth 1 https://github.com/mitre-attack/attack-website.git && cd attack-website
# install-deps (34 s)
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r requirements.txt
npm --prefix attack-search ci
npm --prefix attack-style ci
# build-assets (13 s)
npm --prefix attack-search run build-copy
npm --prefix attack-style run build-copy
# build-website (376 s wall clock, see below)
export ATTACK_WEBSITE_STIX_LOCATION_ENTERPRISE=$MM/datasets/enterprise-attack.json   # unpatched: the pinned file
export ATTACK_WEBSITE_STIX_LOCATION_MOBILE=$MM/.cache/materialized/mobile-attack.json
export ATTACK_WEBSITE_STIX_LOCATION_ICS=$MM/datasets/ics-attack.json
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python update-attack.py --attack-brand
python3 -m http.server 8800 -d output    # then open http://127.0.0.1:8800/software/SX0001/
```

Time per module: matrices 47 s (bundle load), techniques 23 s, groups 18 s, software 11 s, redirections
33 s, website_build (Pelican) 101 s, search index 107 s, tests about 10 s. Output was 340 MB and 8003 pages.
No extras were built: `--all-extras` adds `versions`, which downloads every archived ATT&CK release, so it
was left out on purpose.

Rendering was checked over HTTP:

- `/software/SX0001/` lists Techniques Used T1429, T1430 and T1409, each with the minted `description`
  and citation. Under "Groups That Use This Software" it lists **G0142 Confucius** and **GX0001 Wave6 Render
  Actor**, each with "... is asserted by the user in the intake file to use Wave6 Render Spyware." It also
  has a Navigator layer link to `/software/SX0001/SX0001-mobile-layer.json`, which contains the 3 techniques.
- `/groups/GX0001/` shows Associated Groups W6RA and Techniques Used T1404 and T1430 (user-asserted). Its
  Software table has SX0001 together with that software's techniques. It also has a layer JSON.
- Back-links: `/techniques/T1430/` lists GX0001 and SX0001 under Procedure Examples, `/techniques/T1404/`
  lists GX0001, and `/groups/G0142/` lists SX0001.
- Indices and search: `/software/` and `/groups/` link SX0001 and GX0001. `search/software.json` has
  `{"attackId": "SX0001", "domains": ["mobile"]}` and `search/groups.json` has `GX0001`. Both are in
  `sitemap.xml`.

Gotchas:

- **The process exits 1 even though the site is fine.** The `tests` module reports "Internal Links
  FAILED: 3882 pages referencing broken link(s)". Every broken link points to `/resources/...`
  (contact, faq, contribute), which only the `resources` extra builds. SX/GX pages have no broken links
  besides that shared footer link. Add `-e resources` or `--no-test-exitstatus` to get a clean exit.
- **Random page:** `random_page.py` filters paths with `G[0-9]{4}` / `S[0-9]{4}`. The built
  `random_page.json` contains neither `SX0001` nor `GX0001`, while G0142 and S0316 are in it. Both minted
  kinds are left out of the random-page pool. This is accepted.
- `ATTACK_WEBSITE_STIX_LOCATION_PRE` defaults to a download of `pre-attack.json` from `mitre/cti`
  master. This happened during the build and is harmless, but it means the build is not offline. Point it
  at a local copy to build without network.
- The other ID regexes in `modules/util/buildhelpers.py` (`^T[0-9]{4}$`) only touch techniques, so they
  do not affect SX/GX.

## ATT&CK Navigator (`mitre-attack/attack-navigator`)

Navigator reads bundles from `nav-app/src/assets/config.json`. This route was verified:
`versions.enabled: true` and an entry whose `domains[].data` is an HTTP URL to the materialized bundle.

```sh
git clone --depth 1 https://github.com/mitre-attack/attack-navigator.git && cd attack-navigator/nav-app
npm ci                                       # 76 s (README asks for Node 22; Node 25 worked)
# edit src/assets/config.json -> "versions":
#   {"enabled": true, "entries": [{"name": "mitre-mapper materialized", "version": "19",
#     "domains": [{"name": "Mobile", "identifier": "mobile-attack",
#                  "data": ["http://localhost:8765/mobile-attack.json"]}]}]}
npx ng build --configuration production      # 44 s -> dist/browser/
python3 -m http.server 4300 -d dist/browser  # the app
# the bundle, from a server that sends Access-Control-Allow-Origin: * (python's http.server does not;
# a 5-line SimpleHTTPRequestHandler subclass adding that header was used), on :8765
```

Another way to avoid CORS is to copy the bundle into `src/assets/` before building and use
`"data": ["assets/mobile-attack.json"]`. That route is in the upstream README but was not exercised here.

Checked headlessly (playwright-core with the installed Chrome). Choosing Create New Layer -> Mobile fetched
`http://localhost:8765/mobile-attack.json` (200, 3.8 MB) and the mobile matrix rendered. Then, in the search &
multiselect panel:

- Searching by ATT&CK ID `SX0001` gave Software (1) Wave6 Render Spyware, and `GX0001` gave Threat
  Groups (1) Wave6 Render Actor. The ID comes from `external_references[0].external_id`
  (`classes/stix/stix-object.ts`), so the `mitre-attack` reference must be **first**. Lint E009 enforces
  this.
- **select** on SX0001 highlighted exactly Location Tracking, Audio Capture and Stored Application Data
  (T1430, T1429, T1409).
- **select** on GX0001 highlighted exactly Exploitation for Privilege Escalation and Location Tracking
  (T1404, T1430). These are its direct, user-asserted `intrusion-set -> attack-pattern` relationships.
- **select** on G0142 Confucius highlighted **nothing**. In the mobile bundle its only relationships go to
  malware (2 upstream plus our SX0001), and `services/data.service.ts` builds `group_uses` only from
  `intrusion-set -> attack-pattern` relationships. Group -> software -> technique is never followed, for
  real groups as well. To make a user-defined `GX` group highlight, give it `techniques:` in the intake
  file.
- The panel's **view** links are hard-coded to `https://attack.mitre.org/groups/GX0001` and
  `.../software/SX0001`, which do not exist upstream. The website's own per-object "view" layer link follows
  `navigator_link` in its `modules/site_config.py`.

Screenshots: `nav-02-mobile-layer.png`, `nav-04-select-SX0001.png`, `nav-05-select-GX0001.png`,
`nav-06-select-G0142.png`, `web-SX0001.png`, `web-GX0001.png` (kept in the session scratchpad, not committed).

## Still unverified

- Enterprise and ICS bundles with minted objects. Only a mobile delta was rendered; enterprise was the
  pinned, unpatched file. The code paths are the same, but nothing was built with an enterprise `SX`.
- `--all-extras` builds (archived versions, blog and so on), the Docker build, and the `just` binary itself
  (its recipes were run by hand).
- The Navigator `ng serve` dev server, the copy-into-`src/assets` route, the layer-file `customDataURL`
  route, and `collection_index_url`.
- A combined bundle from two deltas that share a group (acceptance #12) is tested in `tests/` but was not
  rendered.
