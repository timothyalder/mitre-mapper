# Mapping from Claude Code through the MCP server

`mitre-mapper-mcp` is a FastMCP stdio server over the same deterministic core the LangChain agent uses
(`session.py`, `tools.py`). Claude Code follows `skills/map-software/SKILL.md` and calls the server's tools.
An MCP run writes the same `runs/<run_id>/` folder, `run.md`, `delta.json` and `runs/index.jsonl` row as
`mitre-mapper map`, with `surface: "mcp"`.

The tool list and argument contract are in the module docstring of `src/mitre_mapper/mcp_server.py`:
`start_run`, `search_techniques`, `get_technique`, `search_groups`, `get_group`, `search_software`,
`get_software`, `get_software_techniques`, `get_evidence`, `read_reference`, `lint_proposal`,
`submit_proposal`, `mint_delta` and `end_run`.

## Register with Claude Code

```sh
claude mcp add mitre-mapper -- uv run --directory /abs/path/to/mitre-mapper mitre-mapper-mcp
```

Server options. Each flag has an environment variable that sets the same thing:

| flag | env | default |
|---|---|---|
| `--runs-dir` | `MITRE_MAPPER_RUNS_DIR` | `<repo>/runs` |
| `--datasets-dir` | `MITRE_MAPPER_DATASETS_DIR` | `<repo>/datasets` |
| `--allocations-path` | `MITRE_MAPPER_ALLOCATIONS_PATH` | `<datasets-dir>/allocations.json` |
| `--max-attempts` | none | 3 |

Then ask Claude Code to map an intake file with the map-software skill. It opens the run with
`start_run(intake_path)` and closes it with `mint_delta` or `end_run`.

## Allocation registry: keep demo runs off the real SX/GX ids

`mint_delta` allocates `SX####`/`GX####` ids in the registry, and an id is never reused. Demo, test and
eval-style runs often map software ATT&CK already has. Point those runs at a scratch copy of the registry
so they don't use up real ids. They still write to the real `runs/`, because they are improvement-loop data:

```sh
cp datasets/allocations.json /tmp/scratch-allocations.json
mitre-mapper-mcp --allocations-path /tmp/scratch-allocations.json        # MCP
mitre-mapper map intake.md --allocations-path /tmp/scratch-allocations.json   # LangChain CLI
```

`run_start.allocations_path` records the registry each run used. It is null for the canonical
`datasets/allocations.json`. `mitre-mapper delta doctor` reads that field. A run minted against another
registry, or an eval run, gets one **D009 info** finding ("non-canonical allocation registry ... not
checked") and no D006 mismatches. The one exception is when doctor's own `allocations_path` is that same
registry. In that case doctor checks the run normally.

## Holdout: score a Claude Code run against an eval case

`start_run(..., holdout="pegasus" | "crackmapexec")` applies the eval holdout predicate from
`holdout.py` to every ATT&CK tool for that run. S0289 or S0488, their twins and the objects that name them
become invisible to `search_*`/`get_*`. The diff is logged as `merge` kind=holdout. This does not make the
run an eval run: `eval_case` stays null, no `scores.json` is written and the index row has
`eval_scores: null`. To score it, run `evaluate.score_run` against the case afterwards. The holdout does
not cover the model's own memory. Claude may already know the published ATT&CK mapping for well-known
software.

## Headless run (what acceptance #10 used)

From a scratch working directory, use an MCP config that launches the server:

```json
{"mcpServers": {"mitre-mapper": {"type": "stdio", "command": "uv",
  "args": ["run", "--directory", "<repo>", "mitre-mapper-mcp",
           "--runs-dir", "<repo>/runs", "--allocations-path", "<scratch>/allocations.json"]}}}
```

```sh
claude -p "$(cat prompt.txt)" --mcp-config mcp.json --strict-mcp-config \
  --tools "" --allowedTools "mcp__mitre-mapper" --setting-sources "" \
  --model claude-sonnet-5-5 --no-session-persistence --output-format stream-json --verbose > transcript.jsonl
```

`--tools ""` removes every built-in tool, so the only tools Claude has are the MCP server's.
`--setting-sources ""` keeps user hooks, plugins and CLAUDE.md out of the session. `prompt.txt` holds the
SKILL.md body (without frontmatter) followed by a short task:

```
start_run(intake_path="<repo>/evals/fixtures/<case>/intake.md", fetch=false,
          evidence_dir="<repo>/evals/fixtures/<case>/evidence", holdout="<holdout>")
... finish with mint_delta (or end_run). Work autonomously.
```

### What the runs looked like (2026-10-03, claude-sonnet-5-5, holdout on, frozen evidence)

| run | state | attempts | lint | exact P / R / F1 | groups | cost / wall |
|---|---|---|---|---|---|---|
| `20261003T130703Z-pegasus-for-ios-74ff83` | minted SX0001 | 3 of 3 | E012 x2, then E012 x1, then clean | 0.50 / 0.60 / 0.55 (copy-twin S0316: 0.48 F1) | none (gold none) | $0.52 / 83 s |
| `20261003T162134Z-crackmapexec-eba47f` | minted SX0002 | 1 of 3 | clean first time | 0.76 / 0.65 / 0.70 (copy-twin S0165: 0.40 F1) | G0069 only (recall 1/5 all, 1/3 with evidence) | $0.63 / 86 s |
| `20261003T130859Z-crackmapexec-13537a` | abandoned | 1 | clean | none | none | Claude Code hit its usage limit before `mint_delta`. The next server start closed the run as `abandoned`. |

- **Pegasus.** The tool sequence was: `start_run`, 6 x `get_evidence`, 13 x `search_techniques`,
  `submit_proposal` (E012 on T1456 and T1544), `submit_proposal` (E012 on T1456), a `lint_proposal`
  dry run of T1456 alone, `submit_proposal` (clean), then `mint_delta`. It made no `get_technique` calls,
  even though SKILL.md step 5 asks for one per candidate, and no `search_software` calls. All three E012
  failures were real quotes broken across a PDF line with a hyphen ("compro-\nmise", "ex-\nploits") in
  `lookout-pegasus.txt`. The E012 normaliser does not join hyphenated line breaks. That cost two of the
  three attempts. Claude fixed it by quoting a different sentence or source.
- **CrackMapExec.** The tool sequence was: `start_run`, 14 x `get_evidence`, `get_group` for Seedworm,
  IRON LIBERTY and CARBON SPIDER, 1 x `search_techniques`, 16 x `get_technique`, `submit_proposal`
  (clean), then `mint_delta`. Claude went straight to ids it already knew and checked each with
  `get_technique`, rather than searching by behaviour, so retriever recall is only 0.15. It did not link
  Dragonfly or FIN7 because those reports' sentences say "the threat group", which is correct under the
  Groups rules.
- **Leakage.** No ATT&CK tool result in either transcript mentions S0289, S0316, S0488, Pegasus, NSO or
  CrackMapExec. Claude never called `get_software` on the answer. Its own memory remains a possible
  channel.

## Caveats

- **No judge in MCP mode.** Only lint gates `mint_delta`. `judge_model` is null and `n_model_calls`/
  `tokens` are 0 in the index, because the model's calls are invisible to the server. Cost and turns are
  in the Claude Code transcript (`--output-format stream-json`), not in `runs/`.
- **Abandoned runs.** A session that ends without `mint_delta`/`end_run` because of a crash, a usage
  limit or a disconnect stays open. The next server start closes it as `abandoned`, once it has been idle
  for at least 30 minutes.
- **Holdout and eval scoring are opt-in.** See above. Without `holdout`, `search_software`/`get_software`
  can return the real ATT&CK entry for software that is already published.
- **SKILL.md adherence is not enforced.** The server can't see whether Claude ran `get_technique` on
  every candidate or searched by behaviour. Lint and the run log are the only checks.
