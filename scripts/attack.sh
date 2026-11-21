#!/usr/bin/env bash
# =====================================================================
# Shield Wall: ATTACK replay script (PS6)
#
#   --mode waf     (default) attack through the WAF, https://shieldwall.local:9443
#                  PASS = every attack request blocked (403 WAF / 429 rate limit / refused by ban)
#   --mode direct  same attacks straight at the app, http://dvwa (backend network)
#                  shows each attack really works when no WAF is in the way
#   --tools        also run real tools (sqlmap, nikto, ffuf) through the WAF before the
#                  brute-force burst (expect 403s, then a fail2ban ban of the scanner)
#
# Classes: SQLi (CWE-89), XSS (CWE-79), path traversal (CWE-22), OS command
# injection (CWE-78), scanner user agents (T1595.002), login brute force (T1110.001)
# =====================================================================
set -uo pipefail
MODE="waf"; RUN_TOOLS=0; OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --tools) RUN_TOOLS=1; shift;;
    --out) OUT="$2"; shift 2;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done
if [[ "$MODE" == "direct" ]]; then TARGET="${TARGET:-http://dvwa}"; else TARGET="${TARGET:-https://shieldwall.local:9443}"; fi
source "$(dirname "$0")/lib.sh"
OUT="${OUT:-/work/evidence/attack_${MODE}.csv}"
mkdir -p "$(dirname "$OUT")"

echo "== Shield Wall attack replay: mode=$MODE target=$TARGET =="
csv_row timestamp mode class technique test method request http_code time_s verdict evidence > "$OUT"

TOTAL=0; PASSED=0

# record CLASS TECHNIQUE TEST METHOD REQUEST VERDICT EVIDENCE
record() {
  local class="$1" tech="$2" test="$3" method="$4" req="$5" verdict="$6" ev="$7"
  csv_row "$(date -u +%FT%TZ)" "$MODE" "$class" "$tech" "$test" "$method" "$req" "$CODE" "$TIME_S" "$verdict" "$ev" >> "$OUT"
  local col="$c_grn"; [[ "$verdict" == FAIL* || "$verdict" == "NOT-EXPLOITED" ]] && col="$c_red"
  [[ "$verdict" == ALLOWED-BURST* ]] && col="$c_ylw"
  printf '  %-16s %-34s HTTP %-3s %s%-14s%s %s\n' "$class" "$test" "$CODE" "$col" "$verdict" "$c_rst" "$ev"
}

# judge: decide the verdict for one ordinary attack request.
#   waf mode   : blocked when 403 / 429 / 000 (connection refused by ban)
#   direct mode: EXPLOITED when the success marker (regex) is in the body, or the
#                response time is over the threshold for time-based tests
judge() {
  local class="$1" tech="$2" test="$3" method="$4" req="$5" marker="$6" min_time="${7:-}"
  TOTAL=$((TOTAL+1))
  if [[ "$MODE" == "waf" ]]; then
    if is_blocked; then
      PASSED=$((PASSED+1)); record "$class" "$tech" "$test" "$method" "$req" "BLOCKED" "$(blocked_by)"
    elif [[ "$CODE" == "000" ]]; then
      record "$class" "$tech" "$test" "$method" "$req" "FAIL-ERROR" "no HTTP response ($NET): $CURL_ERR"
    else
      record "$class" "$tech" "$test" "$method" "$req" "FAIL-ALLOWED" "reached application"
    fi
  else
    local hit=""
    if [[ -n "$min_time" ]]; then
      awk -v t="$TIME_S" -v m="$min_time" 'BEGIN{exit !(t>=m)}' && hit="response delayed ${TIME_S}s (>= ${min_time}s)"
    elif [[ -n "$marker" ]] && grep -qE "$marker" "$BODY"; then
      hit="$(grep -oE "$marker" "$BODY" | head -1 | cut -c1-60)"
    fi
    local word="EXPLOITED"; [[ "$class" == "ScannerUA" ]] && word="REACHED-APP"
    if [[ -n "$hit" ]]; then PASSED=$((PASSED+1)); record "$class" "$tech" "$test" "$method" "$req" "$word" "$hit"
    else record "$class" "$tech" "$test" "$method" "$req" "NOT-EXPLOITED" "marker not found"; fi
  fi
}

blocked_by() {
  case "$CODE" in
    403) echo "WAF 403 (ModSecurity, request-id $(grep -i '^x-request-id:' "$HDRS" | tr -d '\r' | awk '{print $2}'))";;
    429) echo "nginx rate limit 429";;
    000) echo "connection refused (fail2ban ban): $CURL_ERR";;
  esac
}

# ---------------------------------------------------------------- pre-flight
http GET /login.php
if [[ "$CODE" == "000" ]]; then
  if [[ "$NET" == "refused" ]]; then
    echo "${c_red}ABORT: $TARGET refuses connections from this host. The attacker IP is probably still"
    echo "banned by fail2ban from a previous run. Run 'make unban' (or 'make reset') and retry.${c_rst}"
  else
    echo "${c_red}ABORT: $TARGET is not reachable ($NET: $CURL_ERR). Is the lab up? ('make status')${c_rst}"
  fi
  exit 3
fi

# ---------------------------------------------------------------- setup
# Authenticate like any user would, so that in direct mode the vulnerable
# pages are reachable. This is not an attack request and is not scored.
if dvwa_login admin password; then echo "  [setup] authenticated session established"; else echo "  [setup] login failed (HTTP $CODE). Continuing anyway: in waf mode the WAF decides before auth"; fi
SQLI='/vulnerabilities/sqli/'; XSSR='/vulnerabilities/xss_r/'; XSSS='/vulnerabilities/xss_s/'
FI='/vulnerabilities/fi/'; EXEC='/vulnerabilities/exec/'

# ---------------------------------------------------------------- 1. SQL injection (CWE-89, CAPEC-66, T1190)
echo "-- SQL injection"
P="1' OR '1'='1"
http GET "${SQLI}?id=$(jq -rn --arg v "$P" '$v|@uri')&Submit=Submit"
judge SQLi T1190 "tautology  1' OR '1'='1" GET "${SQLI}?id=$P" "First name: Hack"

P="1' UNION SELECT user,password FROM users-- -"
http GET "${SQLI}?id=$(jq -rn --arg v "$P" '$v|@uri')&Submit=Submit"
judge SQLi T1190 "UNION dump of password hashes" GET "${SQLI}?id=$P" "Surname: [0-9a-f]{32}"

P="1' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -"
http GET "${SQLI}?id=$(jq -rn --arg v "$P" '$v|@uri')&Submit=Submit"
judge SQLi T1190 "time-based blind SLEEP(3)" GET "${SQLI}?id=$P" "" 3

# ---------------------------------------------------------------- 2. Cross-site scripting (CWE-79, CAPEC-63, T1190)
echo "-- Cross-site scripting"
P='<script>alert(document.cookie)</script>'
http GET "${XSSR}?name=$(jq -rn --arg v "$P" '$v|@uri')"
judge XSS T1190 "reflected <script> cookie theft" GET "${XSSR}?name=$P" "<script>alert\(document.cookie\)</script>"

P='<svg/onload=alert(1)>'
http GET "${XSSR}?name=$(jq -rn --arg v "$P" '$v|@uri')"
judge XSS T1190 "reflected <svg onload> handler" GET "${XSSR}?name=$P" "<svg/onload=alert\(1\)>"

P='<img src=x onerror=alert(1)>'
http POST "$XSSS" --data-urlencode "txtName=guest" --data-urlencode "mtxMessage=$P" --data "btnSign=Sign+Guestbook"
judge XSS T1190 "stored <img onerror> guestbook" POST "$XSSS mtxMessage=$P" "<img src=x onerror=alert\(1\)>"

# ---------------------------------------------------------------- 3. Path traversal / LFI (CWE-22, CAPEC-126, T1190)
echo "-- Path traversal"
P='../../../../../../etc/passwd'
http GET "${FI}?page=${P}"
judge PathTraversal T1190 "../ sequence to /etc/passwd" GET "${FI}?page=$P" "root:x:0:0:"

P='..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'
http GET "${FI}?page=${P}"
judge PathTraversal T1190 "URL-encoded ..%2f traversal" GET "${FI}?page=$P" "root:x:0:0:"

P='/etc/passwd'
http GET "${FI}?page=${P}"
judge PathTraversal T1190 "absolute path /etc/passwd" GET "${FI}?page=$P" "root:x:0:0:"

# ---------------------------------------------------------------- 4. OS command injection (CWE-78, CAPEC-88, T1190)
echo "-- Command injection"
P='127.0.0.1; cat /etc/passwd'
http POST "$EXEC" --data-urlencode "ip=$P" --data "Submit=Submit"
judge CmdInjection T1190 "; cat /etc/passwd" POST "$EXEC ip=$P" "root:x:0:0:"

P='127.0.0.1 | id'
http POST "$EXEC" --data-urlencode "ip=$P" --data "Submit=Submit"
judge CmdInjection T1190 "| id" POST "$EXEC ip=$P" "uid=[0-9]+\([a-z-]+\)"

P='127.0.0.1 && whoami && uname -a'
http POST "$EXEC" --data-urlencode "ip=$P" --data "Submit=Submit"
judge CmdInjection T1190 "&& whoami && uname -a" POST "$EXEC ip=$P" "www-data|Linux [a-z0-9]+"

# ---------------------------------------------------------------- 5. Scanner user agents (T1595.002)
echo "-- Scanner user agents"
for ua in "sqlmap/1.10.11#stable (https://sqlmap.org)" \
          "Mozilla/5.00 (Nikto/2.6.0) (Evasions:None) (Test:000001)" \
          "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"; do
  UA="$ua" http GET "/index.php"
  judge ScannerUA T1595.002 "UA: ${ua:0:30}" GET "/index.php  [User-Agent: $ua]" "Welcome to Damn Vulnerable"
done

# ---------------------------------------------------------------- optional real tools
# Runs BEFORE the brute-force burst, because that burst ends with the attacker IP banned.
# The tools are informational (not scored). Their requests show up in the central log and summary.
if [[ $RUN_TOOLS -eq 1 && "$MODE" == "waf" ]]; then
  echo "-- Real tools through the WAF (sqlmap, nikto, ffuf). Expect 403s and then a fail2ban ban"
  mkdir -p /work/evidence/tools
  SID=$(awk '$6=="PHPSESSID"{print $7}' "$JAR" | tail -1)
  sqlmap -u "${TARGET}${SQLI}?id=1&Submit=Submit" --cookie="PHPSESSID=${SID}; security=low" --batch --flush-session --random-agent \
         --level 1 --risk 1 --technique=BEUT --timeout 5 --retries 0 --disable-coloring \
         --output-dir /work/evidence/tools/sqlmap 2>&1 | tail -n 15 | tee /work/evidence/tools/sqlmap.txt
  nikto.pl -h "$TARGET" -ssl -maxtime 60s -nointeractive 2>&1 | tail -n 15 | tee /work/evidence/tools/nikto.txt
  printf '%s\n' admin backup config .git .env phpmyadmin server-status wp-admin login.php setup.php > /tmp/words.txt
  ffuf -u "${TARGET}/FUZZ" -w /tmp/words.txt -k -mc all -s -t 5 2>&1 | head -n 20 | tee /work/evidence/tools/ffuf.txt
fi

# ---------------------------------------------------------------- 6. Login brute-force burst (T1110.001)
echo "-- Login brute-force burst (POST /login.php, 12 attempts, correct password last)"
# A fresh session, as a brute-force tool would use
: > "$JAR"
PASSWORDS=(123456 password1 letmein qwerty admin welcome monkey dragon iloveyou abc123 111111 password)
n=0; got_in=0; saw_block=0; correct_blocked=0
for pw in "${PASSWORDS[@]}"; do
  n=$((n+1))
  http GET /login.php; token=$(get_token)
  http POST /login.php --data-urlencode "username=admin" --data-urlencode "password=$pw" \
       --data-urlencode "user_token=$token" --data "Login=Login"
  req="/login.php username=admin password=$pw (attempt $n/${#PASSWORDS[@]})"
  if [[ "$MODE" == "waf" ]]; then
    if is_blocked; then
      saw_block=1; [[ "$pw" == "password" ]] && correct_blocked=1
      record BruteForce T1110.001 "attempt $n pw=$pw" POST "$req" "BLOCKED" "$(blocked_by)"
    elif [[ "$CODE" == "302" && "$LOCATION" == *index.php* ]]; then
      got_in=1; record BruteForce T1110.001 "attempt $n pw=$pw" POST "$req" "FAIL-LOGGED-IN" "credential accepted"
    elif [[ "$CODE" == "000" ]]; then
      record BruteForce T1110.001 "attempt $n pw=$pw" POST "$req" "FAIL-ERROR" "no HTTP response ($NET): $CURL_ERR"
    else
      record BruteForce T1110.001 "attempt $n pw=$pw" POST "$req" "ALLOWED-BURST" "wrong password inside the burst allowance"
    fi
  else
    if [[ "$CODE" == "302" && "$LOCATION" == *index.php* ]]; then
      got_in=1; record BruteForce T1110.001 "attempt $n pw=$pw" POST "$req" "EXPLOITED" "logged in as admin"
    else
      record BruteForce T1110.001 "attempt $n pw=$pw" POST "$req" "attempt-failed" "Location: $LOCATION"
    fi
  fi
done
# Automatic blocking: fail2ban must ban the source IP shortly after the burst
banned=0
if [[ "$MODE" == "waf" ]]; then
  for i in $(seq 1 15); do
    http GET /login.php
    if [[ "$CODE" == "000" && "$NET" == "refused" ]]; then banned=1; break; fi
    sleep 1
  done
  if [[ $banned -eq 1 ]]; then
    record BruteForce T1110 "auto-ban check" GET "/login.php (after burst)" "BANNED" "fail2ban ban active after ${i}s: connection refused"
  else
    record BruteForce T1110 "auto-ban check" GET "/login.php (after burst)" "FAIL-NOT-BANNED" "source IP still reaches the edge"
  fi
fi
TOTAL=$((TOTAL+1))
if [[ "$MODE" == "waf" ]]; then
  if [[ $got_in -eq 0 && $saw_block -eq 1 && $correct_blocked -eq 1 && $banned -eq 1 ]]; then
    PASSED=$((PASSED+1)); BF="BLOCKED (burst cut off by rate limit, correct password never reached the app, source IP auto-banned)"
  else BF="FAIL (got_in=$got_in saw_block=$saw_block correct_blocked=$correct_blocked banned=$banned)"; fi
else
  if [[ $got_in -eq 1 ]]; then PASSED=$((PASSED+1)); BF="EXPLOITED (password found)"; else BF="NOT-EXPLOITED"; fi
fi
csv_row "$(date -u +%FT%TZ)" "$MODE" BruteForce T1110.001 "burst verdict" POST "/login.php x${#PASSWORDS[@]}" "-" "-" "$BF" "" >> "$OUT"
echo "  BruteForce burst verdict: $BF"

echo
if [[ "$MODE" == "waf" ]]; then
  echo "RESULT: $PASSED / $TOTAL attack test cases blocked   (CSV: $OUT)"
  [[ $PASSED -eq $TOTAL ]] && { echo "${c_grn}PASS: every attack was blocked${c_rst}"; exit 0; } || { echo "${c_red}FAIL: some attacks reached the application${c_rst}"; exit 1; }
else
  echo "RESULT: $PASSED / $TOTAL attack test cases succeeded against the unprotected app (exploited / reached app)   (CSV: $OUT)"
  exit 0
fi
