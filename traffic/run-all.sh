#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1

export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export OUTDIR="${OUTDIR:-$(pwd)/results}"
export OUT="${OUT:-$OUTDIR/traffic-$RUN_ID.tsv}"
export WITH_TOOLS="${WITH_TOOLS:-1}"

printf '=== ПРОГОН %s -> %s ===\n\n' "$RUN_ID" "${WAF:-http://waf}"
./legit.sh
./attack.sh

printf '\n=== ИТОГ ПРОГОНА %s ===\n' "$RUN_ID"
awk -F'\t' -v r="$RUN_ID" 'NR>1 && $1==r {n[$3"\t"$5]++} END {for (k in n) printf "%s\t%d\n", k, n[k]}' "$OUT" |
    sort | awk -F'\t' 'BEGIN{printf "%-8s %-6s %s\n","класс","код","запросов"} {printf "%-8s %-6s %d\n",$1,$2,$3}'
