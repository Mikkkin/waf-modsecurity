#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
. ./lib.sh

JSON='Content-Type: application/json'
LAB_USER="${LAB_USER:-shopper@lab.test}"
LAB_PASS="${LAB_PASS:-L4bSh0pper!2026}"

req WEB-01 legit GET /
req WEB-03 legit GET /polyfills.js
req WEB-04 legit GET /styles.css
req WEB-05 legit GET /main.js
req WEB-06 legit GET /assets/public/favicon_js.ico
req WEB-07 legit GET /rest/admin/application-version
req WEB-08 legit GET /rest/admin/application-configuration
req WEB-09 legit GET /rest/languages

req CAT-01 legit GET /rest/products/search -G --data-urlencode 'q='
req CAT-02 legit GET /rest/products/search -G --data-urlencode 'q=apple'
req CAT-03 legit GET /rest/products/search -G --data-urlencode 'q=juice'
req CAT-04 legit GET /rest/products/search -G --data-urlencode 'q=lemon'
req CAT-05 legit GET /api/Products/1
req CAT-06 legit GET /api/Products/6
req CAT-07 legit GET /rest/products/1/reviews
req CAT-08 legit GET /api/Quantitys/
req CAT-09 legit GET /rest/products/search -G --data-urlencode 'q=Bananen'

req EDGE-01 legit GET /rest/products/search -G --data-urlencode 'q=best match (2024)'
req EDGE-02 legit GET /rest/products/search -G --data-urlencode 'q=price < 5 and rating > 3'
req EDGE-03 legit GET /rest/products/search -G --data-urlencode 'q=100% organic'
req EDGE-04 legit GET /rest/products/search -G --data-urlencode 'q=https://example.com/a?b=c'
req EDGE-05 legit GET /rest/products/search -G --data-urlencode "q=O'Reilly & sons"
req EDGE-06 legit GET /rest/products/search -G --data-urlencode 'q=1+1=2'
req EDGE-07 legit GET /rest/products/search -G --data-urlencode 'q=C++ book'
req EDGE-08 legit GET /rest/products/search -G --data-urlencode 'q=select the best juice'

req REG-01 legit POST /api/Users -H "$JSON" \
    --data-raw "{\"email\":\"$LAB_USER\",\"password\":\"$LAB_PASS\",\"passwordRepeat\":\"$LAB_PASS\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"lab\"}"
req REG-02 legit POST /rest/user/login -H "$JSON" \
    --data-raw "{\"email\":\"$LAB_USER\",\"password\":\"$LAB_PASS\"}"

TOKEN="$(login_token "$LAB_USER" "$LAB_PASS")"
if [ -z "$TOKEN" ]; then
    printf 'Токен не получен, авторизованные сценарии пропущены\n' >&2
    summary "ЛЕГИТИМНЫЙ ТРАФИК"
    exit 0
fi
AUTH="Authorization: Bearer $TOKEN"

req USR-01 legit GET /rest/user/whoami -H "$AUTH"
req USR-02 legit GET /api/SecurityQuestions -H "$AUTH"
req USR-03 legit GET /rest/user/security-question -G --data-urlencode "email=$LAB_USER"

BID="$(curl -sS --max-time 20 -A "$UA" -H "$AUTH" "$WAF/rest/user/whoami" 2>/dev/null | sed -n 's/.*"id":\([0-9]*\).*/\1/p')"
BID="${BID:-1}"

req BSK-01 legit GET "/rest/basket/$BID" -H "$AUTH"
req BSK-02 legit POST /api/BasketItems -H "$AUTH" -H "$JSON" \
    --data-raw "{\"ProductId\":1,\"BasketId\":\"$BID\",\"quantity\":1}"

ITEM="$(curl -sS --max-time 20 -A "$UA" -H "$AUTH" "$WAF/rest/basket/$BID" 2>/dev/null |
    grep -o '"BasketItem":{[^}]*}' | head -1 | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)"
if [ -n "$ITEM" ]; then
    req BSK-03 legit PUT "/api/BasketItems/$ITEM" -H "$AUTH" -H "$JSON" --data-raw '{"quantity":3}'
    req BSK-04 legit DELETE "/api/BasketItems/$ITEM" -H "$AUTH"
fi

req REV-01 legit PUT /rest/products/1/reviews -H "$AUTH" -H "$JSON" \
    --data-raw '{"message":"Fresh and tasty, delivery took 2 days","author":"shopper@lab.test"}'
req REV-02 legit GET /rest/products/1/reviews -H "$AUTH"
req CPN-01 legit PUT "/rest/basket/$BID/coupon/n<0LP+8sh" -H "$AUTH"
req FBK-01 legit GET /rest/captcha
req IMG-01 legit GET /assets/public/images/products/apple_juice.jpg

summary "ЛЕГИТИМНЫЙ ТРАФИК"
