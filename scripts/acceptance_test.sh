#!/usr/bin/env bash
# =====================================================================
# Shield Wall: PS6 acceptance test (what the judges check), from a clean state
#   A1  TLS terminated at the proxy (TLS 1.2+ only, valid cert, HTTP->HTTPS)
#   A2  every request in the attack script is blocked
#   A3  >= 95% of the benign script is allowed
#   A4  login brute force is rate-limited AND the source is automatically banned
#   A5  WAF + proxy logs are centralized and summarized by attack type
# =====================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose "$@"; }
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
declare -a RES; FAILS=0
check() { if [[ "$2" == "0" ]]; then RES+=("${G}PASS${N}  $1"); else RES+=("${R}FAIL${N}  $1"); FAILS=$((FAILS+1)); fi; }

echo "=== [0] reset to a clean state"; make --no-print-directory reset || exit 1

echo "=== [A1] TLS termination"
v13=$(dc exec -T attacker sh -c 'echo | openssl s_client -connect shieldwall.local:9443 -servername shieldwall.local -CAfile /work/certs/ca.crt -brief 2>&1' | grep -c "Verification: OK")
# the client is allowed to offer TLS 1.1 (SECLEVEL=0), so a refusal must come from the server (alert 70)
v11=$(dc exec -T attacker sh -c 'echo | openssl s_client -connect shieldwall.local:9443 -servername shieldwall.local -tls1_1 -cipher "DEFAULT:@SECLEVEL=0" 2>&1' | grep -c "alert protocol version")
redir=$(dc exec -T attacker curl -s -o /dev/null -w '%{http_code}' http://shieldwall.local:9080/)
echo "  verified TLS handshake: $v13 | server rejected TLS1.1 (alert 70): $v11 | http status: $redir"
check "A1 TLS terminated (cert verifies, TLS1.1 refused, HTTP 301 -> HTTPS)" $([[ $v13 -ge 1 && $v11 -ge 1 && $redir == 301 ]] && echo 0 || echo 1)

echo "=== [A3] benign replay"
dc exec -T client bash /work/scripts/benign.sh; b=$?
check "A3 >= 95% of benign requests allowed ($(tail -n +2 evidence/benign_waf.csv | grep -c '"yes","[a-z]*"$') / $(tail -n +2 evidence/benign_waf.csv | wc -l))" $b

echo "=== [extra] judge-style evasion variants"
dc exec -T attacker bash /work/scripts/judge_variations.sh | tail -3; jv=${PIPESTATUS[0]}
check "Extra: all evasion variants blocked ($(grep -c '"BLOCKED"$' evidence/judge_variations.csv) / $(tail -n +2 evidence/judge_variations.csv | wc -l))" $jv
dc exec -T fail2ban fail2ban-client unban --all >/dev/null

echo "=== [A2/A4] attack replay"
dc exec -T attacker bash /work/scripts/attack.sh --mode waf; a=$?
check "A2 every attack request blocked (16 test cases across 6 classes)" $a
banned=$(dc exec -T fail2ban fail2ban-client status shieldwall-bruteforce | grep -c "10.66.10.66")
r429=$(grep -c '"429"' evidence/attack_waf.csv)
client_ok=$(dc exec -T client curl -s -o /dev/null -w '%{http_code}' --cacert /work/certs/ca.crt https://shieldwall.local:9443/login.php)
echo "  429 responses: $r429 | attacker banned: $banned | benign client still served: HTTP $client_ok"
check "A4 brute force rate-limited ($r429 x 429) and attacker auto-banned, client unaffected" $([[ $r429 -ge 1 && $banned -ge 1 && $client_ok == 200 ]] && echo 0 || echo 1)

echo "=== [A5] centralized logs + alert summary"
make --no-print-directory summary; s=$?
srcs=$(jq -r '.source' logs/central/events.ndjson 2>/dev/null | sort -u | tr '\n' ' ')
types=$(jq '[.by_attack_type[] | select(.blocked>0)] | length' reports/alert_summary.json)
fps=$(jq '.benign_false_positives' reports/alert_summary.json)
echo "  sources in central log: $srcs | attack types with blocks: $types | benign FPs: $fps"
check "A5 central log has proxy+waf+fail2ban, summary covers >= 6 attack types" $([[ $s -eq 0 && "$srcs" == *fail2ban* && "$srcs" == *proxy* && "$srcs" == *waf* && $types -ge 6 ]] && echo 0 || echo 1)

echo; echo "=================== ACCEPTANCE RESULTS ==================="
printf '%s\n' "${RES[@]}"
[[ $FAILS -eq 0 ]] && echo "${G}ALL ACCEPTANCE TESTS PASSED${N}" || echo "${R}$FAILS acceptance test(s) FAILED${N}"
exit $FAILS
