# mitre-mapper

Maps a piece of software (malware or tool), described in an intake file, to MITRE ATT&CK and emits a STIX
delta that can be materialized into patched ATT&CK bundles for attack-website and ATT&CK Navigator. Every
run is logged so its failures can feed back into improving the tool.

Status: under construction — see `PLAN.md`.

```bash
uv sync
uv run pytest            # default: no live model calls
uv run pytest -m slow    # tests that load the enterprise bundle
```

Datasets: `datasets/*-attack.json` are pinned in `datasets/MANIFEST.json` (ATT&CK v19.2, STIX 2.0, from
`mitre/cti`) and are not committed.
