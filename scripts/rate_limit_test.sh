#!/usr/bin/env bash
# =====================================================================
# Shield Wall: dedicated rate-limiting + automatic-blocking test (run on the host)
#   make ratelimit
#
#  T1  GET /login.php x20 fast         -> never 429 (page views are not counted)
#  T2  flood 120 parallel requests     -> general zone (20 r/s, burst 40) answers some with 429
#  T3  POST /login.php burst x10       -> login zone (6/min, burst 3): 429 after the burst
#  T4  fail2ban                        -> attacker IP banned within seconds (connection refused)
#  T5  benign client                   -> still served (HTTP 200): limits are per source IP
#  T6  evidence                        -> nginx error-log lines + fail2ban jail status
# Starts from a clean state (lifts bans, waits for the login bucket to drain).
# =====================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose "$@"; }
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
declare -a RES; FAILS=0
check() { if [[ "$2" == "0" ]]; then RES+=("${G}PASS${N}  $1"); else RES+=("${R}FAIL${N}  $1"); FAILS=$((FAILS+1)); fi; }
URL=https://shieldwall.local:9443
OUT=evidence/rate_limit_test.csv
echo "test,request_no,http_code" > "$OUT"

echo "=== [0] clean start: lift bans, let the login bucket drain (12 s)"
dc exec -T fail2ban fail2ban-client unban --all >/dev/null
sleep 12

# ------------------------------------------------------------------ T1
echo "=== [T1] 20 fast GETs of the login PAGE (viewing is not rate-limited)"
codes=$(dc exec -T attacker bash -c "for i in \$(seq 1 20); do curl -s -o /dev/null -w '%{http_code}\n' --cacert /work/certs/ca.crt $URL/login.php; done")
n=0; for c in $codes; do n=$((n+1)); echo "T1,$n,$c" >> "$OUT"; done
t1_429=$(grep -c '^429$' <<<"$codes"); t1_200=$(grep -c '^200$' <<<"$codes")
echo "  200: $t1_200   429: $t1_429"
check "T1 login page views are never throttled (20 x GET -> $t1_200 x 200, $t1_429 x 429)" $([[ $t1_429 -eq 0 && $t1_200 -eq 20 ]] && echo 0 || echo 1)

# ------------------------------------------------------------------ T2
sleep 3   # let the general bucket refill after T1
echo "=== [T2] flood: 120 requests, 30 in parallel (general zone 20 r/s + burst 40; max 20 connections per IP)"
codes=$(dc exec -T attacker bash -c "seq 1 120 | xargs -P 30 -I{} curl -s -o /dev/null -w '%{http_code}\n' --cacert /work/certs/ca.crt $URL/favicon.ico")
n=0; for c in $codes; do n=$((n+1)); echo "T2,$n,$c" >> "$OUT"; done
t2_200=$(grep -c '^200$' <<<"$codes"); t2_429=$(grep -c '^429$' <<<"$codes")
echo "  200: $t2_200   429: $t2_429   (excess beyond the burst is rejected at the edge)"
check "T2 flood throttled by the general limits ($t2_200 x 200 served, $t2_429 x 429 rejected)" $([[ $t2_429 -ge 1 && $t2_200 -ge 20 && $((t2_200 + t2_429)) -eq 120 ]] && echo 0 || echo 1)
sleep 3   # let the general bucket refill so T3 measures only the login zone

# ------------------------------------------------------------------ T3
echo "=== [T3] login brute force: 10 rapid POSTs with wrong passwords (login zone: 6/min, burst 3)"
codes=$(dc exec -T attacker bash -c '
  source /work/scripts/lib.sh
  for i in $(seq 1 10); do
    http GET /login.php; t=$(get_token)
    http POST /login.php --data-urlencode "username=admin" --data-urlencode "password=wrong$i" \
         --data-urlencode "user_token=$t" --data "Login=Login"
    echo "$CODE"
  done')
n=0; i=0; for c in $codes; do n=$((n+1)); echo "T3,$n,$c" >> "$OUT"; printf '  attempt %2d -> HTTP %s\n' "$n" "$c"; done
t3_ok=$(grep -c '^302$' <<<"$codes"); t3_429=$(grep -c '^429$' <<<"$codes"); t3_000=$(grep -c '^000$' <<<"$codes")
check "T3 login burst cut off: $t3_ok reached the app, $t3_429 x 429, $t3_000 refused" $([[ $t3_ok -le 4 && $((t3_429 + t3_000)) -ge 6 ]] && echo 0 || echo 1)

# ------------------------------------------------------------------ T4
echo "=== [T4] automatic blocking: is the attacker banned?"
banned_after=""
for s in $(seq 1 15); do
  c=$(dc exec -T attacker curl -s -m 3 -o /dev/null -w '%{http_code}' --cacert /work/certs/ca.crt $URL/login.php)
  [[ "$c" == "000" ]] && { banned_after=$s; break; }
  sleep 1
done
jail=$(dc exec -T fail2ban fail2ban-client status shieldwall-bruteforce)
echo "$jail" | sed 's/^/  /' | grep -E "Currently|Banned"
check "T4 attacker auto-banned (connection refused after ${banned_after:-?}s, IP in jail)" $([[ -n "$banned_after" ]] && grep -q 10.66.10.66 <<<"$jail" && echo 0 || echo 1)

# ------------------------------------------------------------------ T5
echo "=== [T5] the benign client (different IP) is unaffected"
c=$(dc exec -T client curl -s -o /dev/null -w '%{http_code}' --cacert /work/certs/ca.crt $URL/login.php)
echo "  client -> HTTP $c"
check "T5 benign client still served (HTTP $c)" $([[ "$c" == "200" ]] && echo 0 || echo 1)

# ------------------------------------------------------------------ T6
echo "=== [T6] evidence (nginx error log)"
dc exec -T waf sh -c 'grep "limiting requests" /var/log/shieldwall/nginx/error.log | tail -n 4' | cut -c1-200 | sed 's/^/  /'
{ echo "### nginx limit_req rejections (last 30)"; dc exec -T waf sh -c 'grep "limiting requests" /var/log/shieldwall/nginx/error.log | tail -n 30'
  echo; echo "### fail2ban jail"; echo "$jail"; echo; echo "### iptables in the WAF namespace"; dc exec -T fail2ban iptables -S | grep f2b; } > evidence/rate_limit_evidence.txt

echo; echo "=================== RATE-LIMIT RESULTS ==================="
printf '%s\n' "${RES[@]}"
echo "CSV: $OUT   evidence: evidence/rate_limit_evidence.txt"
echo "${Y}Note: the attacker stays banned for 10 min. Run 'make unban' before other attack runs.${N}"
exit $FAILS
