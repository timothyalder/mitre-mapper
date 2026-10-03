#!/usr/bin/env bash
# Read-only. Flatten every failure fact in run logs into TSV so patterns can be counted.
#
#   facts.sh [RUN_ID ...]          # default: every runs/*/events.jsonl
#   RUNS_DIR=path facts.sh ...     # default: runs
#
# Output columns: run_id <TAB> kind <TAB> key <TAB> detail
#   kind = terminal | lint_error | lint_warn | judge_fail | zero_hit | fetch_failed
#          | group_quote_fail | unmatched_actor | no_structured_output | error
#   key  = what to cluster on (terminal_state, rule_id[:details.reason], rubric item, tool, ...)
# One line per occurrence (a rule failing on 3 attempts gives 3 lines); count distinct runs with
#   facts.sh | cut -f1-3 | sort -u | cut -f2,3 | sort | uniq -c | sort -rn
set -euo pipefail
RUNS_DIR="${RUNS_DIR:-runs}"
if [ "$#" -gt 0 ]; then
  files=(); for r in "$@"; do files+=("$RUNS_DIR/$r/events.jsonl"); done
else
  shopt -s nullglob; files=("$RUNS_DIR"/*/events.jsonl)
fi
[ "${#files[@]}" -gt 0 ] || { echo "no events.jsonl under $RUNS_DIR" >&2; exit 1; }

jq -r --arg q "'" '
  def run: input_filename | split("/") | .[-2];
  def clip: tostring | gsub("[\t\n]"; " ") | .[0:160];
  (if .event == "run_end" and ((.terminal_state == "minted" or .terminal_state == "declined") | not) then
     [run, "terminal", .terminal_state, (.error // "" | clip)]
   elif .event == "lint_result" then
     .findings[]? as $f
     | ($f.severity | ascii_upcase) as $s
     | select($s == "ERROR" or $s == "WARN")
     | [run, (if $s == "ERROR" then "lint_error" else "lint_warn" end),
        ($f.rule_id + (if ($f.details.reason? // null) != null then ":" + ($f.details.reason | tostring | gsub($q + "[^" + $q + "]*" + $q; "<name>")) else "" end)),
        ("attempt=" + (.attempt | tostring) + " target=" + ($f.target // "" | tostring) + " " + ($f.message | clip))]
   elif .event == "judge_verdict" then
     .items[]? | select(.passed == false) | [run, "judge_fail", .name, (.rationale // "" | clip)]
   elif .event == "search" and ((.returned_ids // []) | length) == 0 then
     [run, "zero_hit", .tool, ((.query // "" | clip) + " call=" + (.call_id | tostring))]
   elif .event == "reference_fetch_failed" then
     [run, "fetch_failed", (.error // "" | clip), ((.source_name // "") + " " + (.url // "null"))]
   elif .event == "group_quote_check" and .passed == false then
     [run, "group_quote_fail", ((.reason // "") | gsub($q + "[^" + $q + "]*" + $q; "<name>") | clip),
      ("attempt=" + (.attempt | tostring) + " " + (.group_id // "") + " source=" + (.source // ""))]
   elif .event == "unmatched_actor" then
     [run, "unmatched_actor", (.actor // ""), (.quote // "" | clip)]
   elif .event == "retry" and ((.reason // "") | startswith("no_structured_output")) then
     [run, "no_structured_output", .domain, (.reason | clip)]
   elif .event == "error" or .event == "provider_error" or .event == "budget_exhausted" then
     [run, "error", (.event + (if .type then ":" + .type else "" end)), (.message // "" | clip)]
   else empty end) | @tsv
' "${files[@]}"
