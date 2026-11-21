#!/usr/bin/env bash
# =====================================================================
# Shield Wall: BENIGN replay script (PS6)
# 41 normal user requests: browsing, search, form use, login with the
# correct credentials, logout and login again. Run from the "client"
# container (its own source IP, so it never shares a rate-limit bucket
# or a ban with the attacker).
#
#   allowed    = the WAF / rate limiter did not block it (not 403 / 429 / refused)
#   functional = the expected page content came back as well (end-to-end check)
# PASS when allowed >= 95% (the PS6 acceptance threshold).
# =====================================================================
set -uo pipefail
TARGET="${TARGET:-https://shieldwall.local:9443}"
OUT="${1:-/work/evidence/benign_waf.csv}"
source "$(dirname "$0")/lib.sh"
mkdir -p "$(dirname "$OUT")"

echo "== Shield Wall benign replay: target=$TARGET =="
csv_row timestamp n category description method request http_code time_s allowed functional > "$OUT"
N=0; ALLOWED=0; FUNCTIONAL=0

# step CATEGORY DESCRIPTION EXPECT_REGEX METHOD PATH [curl args]
#   EXPECT_REGEX is matched against the body, or against "HTTP <code> <location>"
#   when it starts with "HTTP ", or against the Content-Type header when it starts with "CT:".
step() {
  local cat="$1" desc="$2" expect="$3" method="$4" path="$5"; shift 5
  http "$method" "$path" "$@"
  N=$((N+1))
  local allowed="yes" functional="no"
  # conservative: ANY non-response (000, whatever the reason) or edge block counts as NOT allowed
  [[ "$CODE" == "403" || "$CODE" == "429" || "$CODE" == "000" ]] && allowed="no"
  if [[ "$allowed" == "yes" ]]; then
    ALLOWED=$((ALLOWED+1))
    if [[ "$expect" == HTTP* ]]; then
      [[ "HTTP $CODE $LOCATION" =~ ${expect} ]] && functional="yes"
    elif [[ "$expect" == CT:* ]]; then
      grep -qiE "^content-type: *${expect#CT:}" "$HDRS" && functional="yes"
    else
      grep -qE -- "$expect" "$BODY" && functional="yes"
    fi
  fi
  [[ "$functional" == "yes" ]] && FUNCTIONAL=$((FUNCTIONAL+1))
  local shown="$path"; [[ $# -gt 0 ]] && shown="$path  [POST data]"
  csv_row "$(date -u +%FT%TZ)" "$N" "$cat" "$desc" "$method" "$shown" "$CODE" "$TIME_S" "$allowed" "$functional" >> "$OUT"
  local col="$c_grn"; [[ "$allowed" == "no" ]] && col="$c_red"; [[ "$allowed" == "yes" && "$functional" == "no" ]] && col="$c_ylw"
  printf '  %2d %-10s %-46s HTTP %-3s %sallowed=%-3s functional=%s%s\n' "$N" "$cat" "${desc:0:46}" "$CODE" "$col" "$allowed" "$functional" "$c_rst"
}

login_step() {  # login_step DESCRIPTION
  http GET /login.php; local token; token=$(get_token)
  step auth "$1" "HTTP 302 .*index\.php" POST /login.php \
       --data-urlencode "username=admin" --data-urlencode "password=password" \
       --data-urlencode "user_token=$token" --data "Login=Login"
}
form_token() {  # form_token PATH -> echoes the CSRF token of a page, or nothing
  http GET "$1"; get_token
}
enc() { jq -rn --arg v "$1" '$v|@uri'; }

# ---- arrive and log in
step browse "landing page (unauthenticated -> login)"   "HTTP 302 .*login\.php"   GET /
step browse "login page"                                 "Login"                   GET /login.php
login_step  "login with correct credentials admin/password"
step browse "home page after login"                      "Welcome to Damn Vulnerable" GET /index.php
step browse "about page"                                 "About"                   GET /about.php
step browse "instructions page"                          "Instructions"            GET /instructions.php
step browse "instructions: README document"              "Damn Vulnerable"         GET "/instructions.php?doc=readme"
step browse "instructions: CHANGELOG document"           "Instructions"            GET "/instructions.php?doc=changelog"
step browse "security level page"                        "Security Level"          GET /security.php

# ---- user lookup ("search by ID")
step search "user lookup page"                           "User ID"                 GET /vulnerabilities/sqli/
for id in 1 2 3 4 5; do
  step search "user lookup id=$id"                       "First name:"             GET "/vulnerabilities/sqli/?id=$id&Submit=Submit"
done

# ---- name search / greeting form (realistic names, including the apostrophes and accents that often trip WAFs)
for name in "Alice" "O'Brien" "Anne-Marie Smith" "José García" "Tom & Jerry" "Dr. Jane Doe, PhD"; do
  step search "name search: $name"                       "Hello "                  GET "/vulnerabilities/xss_r/?name=$(enc "$name")"
done

# ---- guestbook
step browse "guestbook page"                             "Guestbook"               GET /vulnerabilities/xss_s/
step form   "sign guestbook with a normal message"       "Great site"              POST /vulnerabilities/xss_s/ \
     --data-urlencode "txtName=Bob" --data-urlencode "mtxMessage=Great site, thanks! I'll be back at 5 o'clock." --data "btnSign=Sign+Guestbook"
step form   "sign guestbook: punctuation-heavy message"  "Can't wait"              POST /vulnerabilities/xss_s/ \
     --data-urlencode "txtName=Mary-Jane O'Neil" --data-urlencode "mtxMessage=Can't wait -- see you @ 5pm; bring snacks & drinks (and the 2024/25 report)!" --data "btnSign=Sign+Guestbook"

# ---- network tool (ping) used as intended
step browse "ping tool page"                             "Ping a device"           GET /vulnerabilities/exec/
step form   "ping 127.0.0.1"                             "bytes from 127.0.0.1"    POST /vulnerabilities/exec/ --data-urlencode "ip=127.0.0.1" --data "Submit=Submit"
step form   "ping localhost (hostname)"                  "PING localhost"          POST /vulnerabilities/exec/ --data-urlencode "ip=localhost" --data "Submit=Submit"

# ---- file viewer used as intended
step browse "file viewer page"                           "file1.php"               GET "/vulnerabilities/fi/?page=include.php"
step browse "file viewer: file1"                         "File 1"                  GET "/vulnerabilities/fi/?page=file1.php"
step browse "file viewer: file2"                         "File 2"                  GET "/vulnerabilities/fi/?page=file2.php"

# ---- other pages and static assets
step browse "brute-force exercise page (no login)"       "Username"                GET /vulnerabilities/brute/
step auth   "brute page: one correct credential check"   "Welcome to the password protected area" GET "/vulnerabilities/brute/?username=admin&password=password&Login=Login"
step browse "CSRF exercise page"                         "Change your admin password" GET /vulnerabilities/csrf/
step static "stylesheet"                                 "CT:text/css"                  GET /dvwa/css/main.css
step static "javascript"                                 "CT:(text|application)/javascript"                GET /dvwa/js/dvwaPage.js
step static "logo image"                                 "CT:image/png"                  GET /dvwa/images/logo.png
step static "favicon"                                    "CT:image/"                  GET /favicon.ico
step static "robots.txt"                                 "User-agent"              GET /robots.txt

# ---- log out, then log back in
step auth   "logout"                                     "HTTP 302 .*login\.php"   GET /logout.php
login_step  "login again with correct credentials"
step browse "home page after re-login"                   "Welcome to Damn Vulnerable" GET /index.php

PCT=$(awk -v a="$ALLOWED" -v n="$N" 'BEGIN{printf "%.1f", (n?100*a/n:0)}')
FPCT=$(awk -v a="$FUNCTIONAL" -v n="$N" 'BEGIN{printf "%.1f", (n?100*a/n:0)}')
echo
echo "RESULT: $ALLOWED / $N benign requests allowed (${PCT}%), $FUNCTIONAL / $N fully functional (${FPCT}%)   (CSV: $OUT)"
if awk -v p="$PCT" 'BEGIN{exit !(p>=95)}'; then echo "${c_grn}PASS: >= 95% of benign traffic allowed${c_rst}"; exit 0
else echo "${c_red}FAIL: below 95% benign traffic allowed${c_rst}"; exit 1; fi
