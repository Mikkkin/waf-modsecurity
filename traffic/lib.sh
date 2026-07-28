#!/usr/bin/env bash

WAF="${WAF:-http://waf.lab}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTDIR="${OUTDIR:-$(pwd)/results}"
OUT="${OUT:-$OUTDIR/traffic-$RUN_ID.tsv}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36}"

mkdir -p "$OUTDIR"

if [ ! -s "$OUT" ]; then
    printf 'run_id\tcase\tclass\tmethod\tcode\ttarget\n' >"$OUT"
fi

req() {
    local case_id="$1" class="$2" method="$3" path="$4"
    shift 4
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
        --max-time 20 \
        -X "$method" \
        -A "$UA" \
        -H "X-Lab-Run: $RUN_ID" \
        -H "X-Lab-Case: $case_id" \
        -H "X-Lab-Class: $class" \
        "$@" \
        "$WAF$path" 2>/dev/null) || code=000
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$RUN_ID" "$case_id" "$class" "$method" "$code" "$path" >>"$OUT"
    printf '%-10s %-7s %-6s %-4s %s\n' "$case_id" "$class" "$method" "$code" "$path"
}

login_token() {
    local email="$1" password="$2"
    curl -sS --max-time 20 \
        -A "$UA" \
        -H "X-Lab-Run: $RUN_ID" \
        -H "X-Lab-Case: AUTH-TOKEN" \
        -H "X-Lab-Class: legit" \
        -H 'Content-Type: application/json' \
        --data-raw "{\"email\":\"$email\",\"password\":\"$password\"}" \
        "$WAF/rest/user/login" 2>/dev/null |
        sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

summary() {
    printf '\n== %s ==\n' "$1"
    awk -F'\t' -v r="$RUN_ID" 'NR>1 && $1==r {n[$5]++} END {for (c in n) printf "  HTTP %s : %d\n", c, n[c]}' "$OUT" | sort
    printf '  файл: %s\n' "$OUT"
}
