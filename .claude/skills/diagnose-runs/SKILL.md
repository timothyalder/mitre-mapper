---
name: diagnose-runs
description: Diagnose mitre-mapper run logs and turn recurring failures into evidenced GitHub issues. Reads `mitre-mapper report --json`, clusters recurring patterns (lint ERRORs, judge rubric failures, zero-hit searches, fetch failures, unmatched actors, review rejections, eval regressions), confirms each one against events.jsonl and the per-attempt artifacts, dedupes against open issues and drafts one `needs-triage` issue per pattern with a confirming eval command and a baseline to beat. Use when asked "what is the tool getting tripped up on?", "diagnose runs", "why do runs fail", "file issues from run logs", or to close the improvement loop after a fix.
---

# /diagnose-runs

This skill closes the improvement loop (PLAN.md §0, §3.9): **logs → report → GitHub issues → fix →
re-eval → compare**. Your output is a short list of real, recurring, evidenced patterns: drafted as
issues, or filed if the user has said to file. If nothing recurs, say that and show what you checked.
Never file noise.

Work from the repo root. Every command here only reads, except `gh issue create`, `gh issue comment`
and `gh label create`, which run **only after the user confirms** (step 7).

## 0. Inputs

- Window: use the user's `--last N` / `--since DATE|RUN_ID`. With no window, use `--last 20`. Say
  which window you used.
- Explicit filing: the user wrote "file", "create the issues" or similar → file after drafting
  without asking again. Otherwise draft, show, and wait.
- Read `CONTEXT.md` and `docs/adr/` if they exist (`docs/agents/domain.md`), and use their terms in
  issue titles.

## 1. Report

```bash
uv run mitre-mapper report --json --last 20 > "$TMPDIR/dr-report.json"    # or --since 2026-10-01 / --since <run_id>
uv run mitre-mapper report --last 20                                  # same data, human view
```

Keys you use (schema: `src/mitre_mapper/report.py` docstring, `schema_version` 1):

| key | what it holds |
|---|---|
| `window` | `n_runs`, `first_run_id`/`last_run_id`, `runs_without_events` (runs whose `events.jsonl` is missing or archived) |
| `terminal_states`, `terminal_state_detail[]` | `{state, n_runs, share_of_runs, run_ids}`, non-minted first |
| `rules.error[]`, `rules.warn[]` | `{rule_id, n_findings, n_runs, share_of_runs, run_ids, examples[{run_id, domain, attempt, message, target}]}` |
| `judge_items[]`, `judge` | `{item, n_failed, n_verdicts, fail_rate, n_runs, run_ids, examples[{…, rationale}]}`; `judge.reject_rate` |
| `searches` | `n_zero_hit`, `zero_hit_rate`, `run_ids`, `top_zero_hit_queries[{query, count}]`, `example_queries` |
| `fetch` | `failure_rate`, `by_error[{error, count}]`, `examples[{run_id, source_name, url, error}]` |
| `unmatched_actors[]` | `{actor, count, n_runs, run_ids, example_quote, example_source_name}` |
| `group_quote_checks` | `fail_rate`, `by_reason[{reason, count}]`, `run_ids` |
| `retries` | `by_reason[{reason, count}]` (`lint_errors: E002,…`, `judge_rejected: …`, `judge_output_invalid`, `no_structured_output: …`) |
| `reviews` | `precision`, `recall`, `most_rejected[{id, count, run_ids}]`, `most_missed[…]` |
| `eval` | `{case: [{run_id, ts, git_sha, prompt_sha256, scores}]}`, in index order |
| `cohorts[]` | grouped by (`prompt_sha256`, `git_sha`), 12-char prefixes, oldest first; `metrics` (`minted_rate`, `terminal_ok_rate`, `lint_error_run_share`, `mean_attempts`, `zero_hit_per_run`, `fetch_failures_per_run`, `judge_fail_runs_share`, `review_precision`, `review_recall`, and eval scores flattened as `eval.<case>.<dotted.path>`, e.g. `eval.pegasus-ios.technique.exact.f1`, `eval.pegasus-ios.technique.parent_lenient.recall`, `eval.crackmapexec.groups.recall_evidence`, `eval.<case>.retriever.union_recall`, `eval.<case>.unjustified_additions.rate`, `eval.<case>.baselines.copy_twin.f1`) |
| `cohort_comparison[]` | consecutive cohorts only: `{from, to, diff: {metric: to - from}}` |
| `by_surface` | `langchain` vs `mcp` terminal states |

`run_ids` lists are capped at 10 and `examples` at 5. Use the counts (`n_runs`, `count`) for frequency,
and `facts.sh` (step 3) for the full run list.

If `window.runs_without_events > 0`, the events for those runs are gone or archived. A fresh clone only
has `runs/index.jsonl`, `runs/*/run.md` and `runs/*/review.json`. Archived runs are in
`runs/archive/*.tar.gz`. Extract one to a scratch dir, never back into `runs/`:
`tar -tzf runs/archive/X.tar.gz | grep '<run_id>/events.jsonl'`, then
`tar -xzf runs/archive/X.tar.gz -C "$TMPDIR" '<run_id>/'`, and use `RUNS_DIR="$TMPDIR"` below.

## 2. Candidate patterns, ranked by frequency × impact

Read each signal below as a candidate. **Frequency** is `n_runs` (distinct runs, not findings).
**Impact** weights:

- **3**: the run produced no delta, or the output was wrong. Non-ok terminal states (`lint_failed`,
  `judge_rejected`, `budget_exhausted`, `error`, `abandoned`), ERRORs in `lint_result` with
  `attempt: "final"`, review-rejected items, and eval score drops between cohorts.
- **2**: the run recovered but paid for it. ERROR rule ids fixed on retry, judge failures later
  approved, `judge_output_invalid`, `no_structured_output` retries, high `mean_attempts`.
- **1**: evidence or coverage loss. Zero-hit queries, fetch failures, `unmatched_actors`,
  `group_quote_checks` failures, review-missed techniques/groups, WARN rules.

Sources, in the order to check:

1. `terminal_state_detail`: every state other than `minted`/`declined`.
2. `rules.error`, then `retries.by_reason`. A rule that appears in `retries` but never with
   `attempt: "final"` cost a retry. A rule that reaches `lint_failed` cost the run.
3. `judge_items` with `fail_rate` > 0, and `judge.reject_rate`.
4. `searches.top_zero_hit_queries`, `fetch.by_error`, `unmatched_actors`, `group_quote_checks.by_reason`.
5. `reviews.most_rejected` / `most_missed`: what the user said was wrong or missing.
6. Eval regressions: in `cohort_comparison[-1].diff` (or by diffing two `cohorts[].metrics` yourself),
   an `eval.<case>.<recall/F1 metric>` going down, or `lint_error_run_share`/`mean_attempts` going up.
   `report.eval.<case>` shows the per-run trend.
7. `by_surface`: a pattern that occurs only on `mcp` (e.g. `abandoned`) points at the MCP surface or
   `skills/map-software/SKILL.md`, not the LangChain loop.

Rank by `n_runs × weight` and keep the top 5 or so. Drop WARN-only and INFO-level items unless a review
or eval regression ties them to wrong output.

## 3. Read the evidence for each candidate

Get the full fact list, one TSV row per occurrence (`run_id, kind, key, detail`), then count distinct runs
per pattern key. The helper only reads:

```bash
S=.claude/skills/diagnose-runs/scripts
jq -r '.runs[] | select(.has_events) | .run_id' "$TMPDIR/dr-report.json" | sort -u \
  | xargs $S/facts.sh > "$TMPDIR/dr-facts.tsv"                                  # the report's window
cut -f1-3 "$TMPDIR/dr-facts.tsv" | sort -u | cut -f2,3 | sort | uniq -c | sort -rn   # runs per pattern
$S/facts.sh                                                                     # no args: every run in runs/
$S/facts.sh <run_id> <run_id>                                                   # facts for some runs
$S/facts.sh | awk -F'\t' '$2=="lint_error" && $3 ~ /^E012/'                     # one pattern, all runs
```

Keys are `rule_id[:details.reason]` for lint (quoted names normalised to `<name>`), the rubric item for
`judge_fail`, the tool for `zero_hit`, the error text for `fetch_failed`, the state for `terminal`.

Layout of a run (`runs/<run_id>/`): `events.jsonl` · `run.md` · `review.json` · `prompt.txt` ·
`intake.md` · `<domain>/proposal_<n>.json` · `<domain>/lint_<n>.json` (and `lint_final.json`) ·
`<domain>/verdict_<n>.json` · `calls/NNNN.json` (4-digit, `{call_id, tool, sha256, payload: {args, result}}`)
· `evidence/*.txt` · `delta.json`. Each event line has `ts`, `seq`, `event` and the event's own fields
(contract: the `src/mitre_mapper/runlog.py` module docstring).

One-liners (jq 1.6+; `R=runs/<run_id>`, or `runs/*/events.jsonl` for every run):

```bash
# start with the run summary
cat $R/run.md
# how did it end
jq -c 'select(.event=="run_end") | {terminal_state, error, n_model_calls, wall_s}' $R/events.jsonl
# lint ERRORs by attempt ("final" = after the user-asserted merge)
jq -c 'select(.event=="lint_result") | {domain, attempt, errors: [.findings[] | select(.severity=="ERROR") | {rule_id, target, details}]}' $R/events.jsonl
jq '.[] | select(.severity=="ERROR")' $R/mobile-attack/lint_2.json           # same, from the artifact
# one rule across every run, with run id
jq -r 'select(.event=="lint_result") | .findings[] | select(.rule_id=="E012") | "\(input_filename|split("/")[-2])\t\(.target)\t\(.details.reason)\t\(.message)"' runs/*/events.jsonl
# what changed between attempts, and why it retried
jq -c 'select(.event=="retry") | {domain, attempt, reason, added, removed}' $R/events.jsonl
# judge item failures with rationale (full verdict: $R/<domain>/verdict_<n>.json)
jq -r 'select(.event=="judge_verdict") | .items[] | select(.passed==false) | "\(.name): \(.rationale)"' $R/events.jsonl
# what was proposed, and what the agent saw but did not cite
jq -c 'select(.event=="proposal_draft") | {domain, attempt, technique_ids, group_ids, declined, rejected_candidates}' $R/events.jsonl
jq '.techniques[] | {technique_id, evidence}' $R/mobile-attack/proposal_1.json
# zero-hit searches, then the full call payload
jq -r 'select(.event=="search" and ((.returned_ids // []) | length)==0) | "\(.tool)\t\(.query)\tcall=\(.call_id)"' $R/events.jsonl
jq '.payload' $R/calls/$(printf '%04d' 7).json
# every tool call in order (agent behaviour; summary = tool-specific facts)
jq -r 'select(.event=="tool_call") | "\(.seq)\t\(.tool)\t\(.args|tostring)\tok=\(.ok)"' $R/events.jsonl
# group quote check failures (the E011 detail)
jq -c 'select(.event=="group_quote_check" and .passed==false) | {attempt, group_id, reason, source, software_aliases_matched, group_aliases_matched}' $R/events.jsonl
# evidence: fetch failures, truncations, actors without an ATT&CK group
jq -c 'select(.event=="reference_fetch_failed" or .event=="evidence_truncated" or .event=="unmatched_actor")' $R/events.jsonl
# crashes / provider / budget
jq -r 'select(.event=="error") | "\(.type): \(.message)\n\(.traceback)"' $R/events.jsonl
jq -c 'select(.event=="provider_error" or .event=="budget_exhausted")' $R/events.jsonl
# the user's review
jq '{techniques, groups, missed_techniques, missed_groups, notes}' $R/review.json
# cohort (full shas) of a run
jq -c 'select(.record=="run" and .run_id=="<run_id>") | {git_sha, prompt_sha256, model, judge_model, surface, eval_case, eval_scores}' runs/index.jsonl
```

To check a quote failure (E011/E012), grep the quote prefix in `$R/evidence/*.txt`. That separates "the
agent paraphrased" from "normalisation missed curly quotes or a hyphenated line break".

**A pattern is real** when it occurs in **≥2 distinct runs**, or in 1 run with a deterministic cause
(a traceback, a lint rule that misfires on valid input, a wrong event field). Discard it when:

- every occurrence is one intake that is itself wrong (missing `platforms` → E006), and the fix belongs
  to the user, not the tool;
- every occurrence comes from a single cohort that a later cohort already fixed (check `cohorts[]`);
- the runs are tests or scratch runs (software names like `bad`/`nope`, `fetch disabled` on every
  reference) rather than real mappings;
- the `git_sha` ends in `-dirty`. These runs don't map to a commit, so say so instead of guessing the code.

Quote 2–4 verbatim event lines per pattern (`jq -c` output, trimmed with `…`). Paraphrase is not evidence.

## 4. Classify and locate the fix

Put each pattern in one class. State the class and the file a fix most likely touches.

| class | signals | likely fix location |
|---|---|---|
| **tool bug** | `error` events with traceback; E008/E009/E010 on proposals that used tool-returned ids; E007; a lint rule firing on correct input; wrong or missing event fields; a counter in `report` that disagrees with `events.jsonl` | the module in the traceback; `mint.py`, `allocations.py`, `lint.py`, `groups.py` (quote normalisation, alias matching), `session.py`/`run.py` (loop, merge), `runlog.py`/`report.py` (logging) |
| **prompt / SKILL.md gap** | E002 `not_found` (cross-domain ids), E004/E005 (wrong `source_name`), E012 `quote_not_found` (paraphrase), E011 missing alias, W003, judge `evidence_grounding` / `technique_specificity` / `omission_check` / `group_attribution`, `no_structured_output`, the same ERROR repeating after feedback (`retry` with empty `added`/`removed`), budget spent on repeated searches | `skills/map-software/SKILL.md`, `skills/map-software/references/linter-rules.md`; retry feedback rendering in `run.py`; `judge_output_invalid` → `judge.py` / judge model choice |
| **retrieval gap** | zero-hit queries for concepts that exist in ATT&CK; gold or review-missed techniques never appearing in any `search` `returned_ids` | `search.py` (BM25 fields/tokenisation); query guidance in SKILL.md |
| **data / evidence limitation** | `reference_fetch_failed` with `HTTP 403/404`, `no url`, `not in frozen evidence`; `evidence_truncated` cutting the cited passage; unmatched actors with no ATT&CK group; missing intake `platforms` | `fetch.py` only for extraction/redirect bugs; otherwise `evals/fixtures/<case>/` (re-freeze) or the intake. Often a doc note, not code |
| **expected behaviour** | W002 on software already in ATT&CK, `provider_error` from rate limits/auth, `declined` on thin evidence, I-rule numbers | no issue. List it in the summary as checked and dismissed |

An unmatched actor that *is* an ATT&CK group name or alias is a `store.py`/`groups.py` alias-resolution
bug, not a data limitation. Check (lower-case the actor; use the run's domain bundle):
`jq -r '.objects[] | select(.type=="intrusion-set") | select([.name] + (.aliases // []) | map(ascii_downcase) | index("carbon spider")) | "\(.external_references[0].external_id) \(.name)"' datasets/enterprise-attack.json`

## 5. Dedupe against the tracker

```bash
gh issue list --state open --label needs-triage --json number,title,body,labels,comments \
  --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'
gh issue list --state open --search "E012 in:title,body" --json number,title     # by rule id / item / error text
```

Search all open issues too (drop `--label`), since triaged ones lose `needs-triage`. Same pattern
(same rule id + reason, rubric item, error text or actor) → **comment** new evidence with
`gh issue comment <n>` (new run ids, counts, window, cohort) instead of a new issue. Note any closed issue
whose pattern has come back, and reference it (`Regressed after #<n>`).

## 6. Draft one issue per pattern

Title: `[diagnose-runs] <class>: <pattern in domain terms>`, e.g.
`[diagnose-runs] prompt gap: E012 quote_not_found on paraphrased technique quotes`.

Body (fill every section, and write "none" if a section is empty):

```markdown
## Pattern
<one paragraph: what goes wrong, at which step, with what consequence>

## Frequency
<n_runs>/<window.n_runs> runs (<share>), <n_findings> occurrences; window `--last N` (<first_run_id> .. <last_run_id>); impact: <weight + why>
Runs: <every run id from facts.sh, not just the capped report list>

## Evidence
<2–4 verbatim jq -c event lines, each prefixed with its run id; plus the relevant lint_<n>/verdict_<n>/proposal_<n> excerpt>

## Classification and hypothesis
<tool bug | prompt/SKILL.md gap | retrieval gap | data/evidence limitation> — <why the evidence points there; what was ruled out>

## Proposed fix location
<file(s) and the specific function/section>

## Confirming eval
`uv run mitre-mapper eval --case <case> [--case <case>] --model <baseline model> --judge-model <baseline judge>` — <which `eval.<case>.…` metric should move, and which rule/item count should drop>

## Baseline to beat
cohort git_sha `<full sha from index>` / prompt_sha256 `<full sha>`; model `<model>`, judge `<judge_model>`
<the cohort metrics that matter, e.g. lint_error_run_share 0.31, mean_attempts 1.6, eval.pegasus-ios.<score> 0.42>
```

Cases are the names in `evals/cases/*.yaml` (`pegasus-ios`, `pegasus-ios-thin`, `crackmapexec`); pass the
same `--model`/`--judge-model` as the baseline cohort (the run row's `model`/`judge_model`), or the
comparison is meaningless. Pick the eval cases the pattern occurred in (`eval_case` on the run rows). If it only occurred in
non-eval runs, use the closest case and say so. The baseline is the cohort containing the failing runs
(`cohorts[]` entry whose `run_ids` include them; take the full shas from `runs/index.jsonl`). If that
cohort has no eval runs, say so and make "run the eval on the baseline commit first" the first step of
the fix.

## 7. Show, confirm, create

Show the user a ranked table (pattern, class, n_runs, impact, dedupe result: new / comment on #n /
dismissed) and the drafts. Unless the user already said to file, **stop and ask**. On confirmation:

```bash
gh label list --json name --jq '.[].name' | grep -qx needs-triage || \
  gh label create needs-triage --description "Maintainer needs to evaluate this issue" --color FBCA04
gh issue create --title "<title>" --label needs-triage --body-file "$TMPDIR/issue-1.md"
gh issue comment <n> --body-file "$TMPDIR/comment-<n>.md"
```

Write bodies to temp files (`--body-file`): event excerpts contain quotes and backticks that break
heredocs. Report the created issue URLs.

## 8. Nothing recurs

Say so plainly, with the evidence: window and `n_runs`, `terminal_states`, the top `rules.error` entries
and their `n_runs`, `judge.reject_rate`, `searches.zero_hit_rate`, `fetch.failure_rate`, review
precision/recall, the latest `cohort_comparison` diff, and each candidate you dismissed with the reason
(single run with no deterministic cause, expected behaviour, already fixed in a later cohort, already
tracked as #n). Do not file anything.

## 9. Closing the loop (put this in your summary, and follow it when asked to verify a fix)

1. Fix on a branch named for the issue (`git switch -c fix/<n>-<slug>`): code, `SKILL.md` or
   references, whichever step 4 named. Commit so runs get a clean `git_sha` (a `-dirty` sha can't be
   compared). A prompt change also changes `prompt_sha256`.
2. Run the confirming eval from the issue:
   `uv run mitre-mapper eval --case <case> --model <m> --judge-model <j>` (`--json` prints the scores;
   `--include-reviews` also scores reviewed runs). It uses frozen evidence and a held-out store with no
   network. Each case writes a normal run with `eval_case` and `eval_scores` on its index row. If it
   fails the evidence-lock check, run `uv run mitre-mapper eval freeze` first (the only networked step).
3. Compare cohorts. Use `uv run mitre-mapper report --json --since <first new run_id>` for the new
   cohort alone, then compare the full report's `cohorts[]` entry for the new
   (`prompt_sha256`, `git_sha`) against the baseline from the issue:
   ```bash
   uv run mitre-mapper report --json | jq --arg b <baseline_git12> --arg n <new_git12> '
     (.cohorts | map(select(.git_sha | startswith($b))) | last) as $base
     | (.cohorts | map(select(.git_sha | startswith($n))) | last) as $new
     | {baseline: $base.metrics, new: $new.metrics,
        diff: ($new.metrics | with_entries(select(.value | type == "number") | .value -= ($base.metrics[.key] // 0)))}'
   ```
   (`cohort_comparison[-1]` gives the same diff when the two cohorts are consecutive.) Also re-run
   `facts.sh` over the new run ids: the pattern's key should be gone or rarer.
4. Comment the result on the issue with `gh issue comment <n>`: new git_sha/prompt_sha256, the eval
   numbers vs the baseline, and the pattern's before/after count. Then link the PR. If the numbers
   didn't move, say so. Never tune the metric to make a fix look good (PLAN.md acceptance #5).
