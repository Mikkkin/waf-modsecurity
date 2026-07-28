#!/usr/bin/env bash
set -uo pipefail

LOG="${LOG:-/var/log/modsec/audit.log}"
RUN="${RUN:-}"

records() {
    grep -ao '{"transaction".*}' "$LOG" |
        jq -cR 'fromjson? // empty' |
        if [ -n "$RUN" ]; then jq -c --arg r "$RUN" 'select(.transaction.request.headers["X-Lab-Run"] == $r)'; else cat; fi
}

usage() {
    cat <<'EOF'
analyze.sh <команда>

  top          топ сработавших правил: сколько раз и какой id
  table        запрос -> id правила -> сообщение
  fp           таблица разбора: класс трафика -> запрос -> правило (легитимный класс = кандидат в ложные)
  api          сработки только на /rest/ и /api/
  score        итоговый счет аномалии по транзакциям
  clean        легитимные запросы, не вызвавшие ни одного срабатывания
  rule <id>    полностью одна транзакция по id правила
  cases        сводка код ответа x класс трафика
EOF
}

case "${1:-}" in
top)
    records | jq -r '.transaction.messages[]?.details.ruleId' | sort | uniq -c | sort -rn
    ;;
table)
    records | jq -r '.transaction as $t | $t.messages[]?
        | [$t.request.headers["X-Lab-Case"] // "-", $t.request.method, $t.request.uri, .details.ruleId, .message]
        | @tsv'
    ;;
fp)
    records | jq -r '.transaction as $t | $t.messages[]?
        | [$t.request.headers["X-Lab-Class"] // "?", $t.request.headers["X-Lab-Case"] // "-",
           $t.request.uri, .details.ruleId, ($t.response.http_code|tostring), .message]
        | @tsv' | sort
    ;;
api)
    records | jq -r 'select(.transaction.request.uri | test("/rest/|/api/"))
        | .transaction as $t | $t.messages[]?
        | [$t.request.uri, .details.ruleId, .message] | @tsv'
    ;;
score)
    records | jq -r '.transaction as $t
        | ($t.messages[]? | select(.details.ruleId == "949110") | .message) as $m
        | [$t.request.headers["X-Lab-Case"] // "-", ($t.response.http_code|tostring), $m] | @tsv'
    ;;
clean)
    records | jq -r 'select((.transaction.messages // []) | length == 0)
        | select(.transaction.request.headers["X-Lab-Class"] == "legit")
        | [.transaction.request.headers["X-Lab-Case"], (.transaction.response.http_code|tostring), .transaction.request.uri]
        | @tsv'
    ;;
rule)
    [ -n "${2:-}" ] || { usage; exit 1; }
    records | jq --arg id "$2" 'select(any(.transaction.messages[]?; .details.ruleId == $id))'
    ;;
cases)
    records | jq -r '[.transaction.request.headers["X-Lab-Class"] // "?", (.transaction.response.http_code|tostring)] | @tsv' |
        sort | uniq -c | sort -k2,2 -k3,3n
    ;;
*)
    usage
    exit 1
    ;;
esac
