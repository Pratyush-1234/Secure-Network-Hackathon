#!/usr/bin/env bash
# Collects proof artefacts into evidence/ (run on the host from the project root).
set -uo pipefail
cd "$(dirname "$0")/.."
E=evidence; mkdir -p "$E/tls" "$E/logs" "$E/fail2ban"
dc() { docker compose "$@"; }

echo "[evidence] TLS termination checks (from the benign client; the attacker may be banned at this point)"
{
  echo "### TLS 1.3 handshake (certificate verified against the lab CA)"
  dc exec -T client sh -c 'echo | openssl s_client -connect shieldwall.local:9443 -servername shieldwall.local -CAfile /work/certs/ca.crt -brief 2>&1' | head -12
  echo; echo "### TLS 1.2 handshake"
  dc exec -T client sh -c 'echo | openssl s_client -connect shieldwall.local:9443 -servername shieldwall.local -CAfile /work/certs/ca.crt -tls1_2 -brief 2>&1' | head -6
  echo; echo "### TLS 1.1 must be refused (client allows it via SECLEVEL=0, so the SERVER must answer alert 70 protocol_version)"
  dc exec -T client sh -c 'echo | openssl s_client -connect shieldwall.local:9443 -servername shieldwall.local -tls1_1 -cipher "DEFAULT:@SECLEVEL=0" 2>&1 | grep -iE "alert|CONNECTED" | head -3'
  echo; echo "### TLS 1.0 must be refused (server must answer alert 70 protocol_version)"
  dc exec -T client sh -c 'echo | openssl s_client -connect shieldwall.local:9443 -servername shieldwall.local -tls1 -cipher "DEFAULT:@SECLEVEL=0" 2>&1 | grep -iE "alert|CONNECTED" | head -3'
  echo; echo "### HTTP -> HTTPS redirect"
  dc exec -T client curl -sI http://shieldwall.local:9080/login.php | grep -iE "^HTTP|^location"
  echo; echo "### Security headers on an HTTPS response"
  dc exec -T client curl -sI --cacert /work/certs/ca.crt https://shieldwall.local:9443/login.php | grep -iE "^HTTP|strict-transport|x-content-type|x-frame|referrer-policy|permissions-policy|set-cookie|^server"
  echo; echo "### Backend is not reachable from the frontend network (app is only behind the WAF)"
  dc exec -T client sh -c 'c=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://10.66.20.20/); echo "client -> dvwa 10.66.20.20:80 : HTTP $c (000 = no route: unreachable, as designed)"'
} > "$E/tls/tls_checks.txt" 2>&1
dc exec -T client nmap -Pn -p 9443 --script ssl-enum-ciphers shieldwall.local > "$E/tls/nmap_ssl_enum_ciphers.txt" 2>&1

echo "[evidence] fail2ban state"
{ dc exec -T fail2ban fail2ban-client status; for j in shieldwall-bruteforce shieldwall-waf; do dc exec -T fail2ban fail2ban-client status "$j"; done
  echo; echo "### iptables inside the WAF network namespace"; dc exec -T fail2ban iptables -S; } > "$E/fail2ban/fail2ban_status.txt" 2>&1

echo "[evidence] log excerpts"
dc exec -T waf sh -c 'tail -n 400 /var/log/shieldwall/nginx/access.json' > "$E/logs/nginx_access_tail.json"
dc exec -T waf sh -c 'grep -E "limiting requests|ModSecurity: Access denied" /var/log/shieldwall/nginx/error.log | tail -n 60' > "$E/logs/nginx_error_blocks.log"
dc exec -T waf sh -c 'tail -n 60 /var/log/shieldwall/modsec/audit.json' > "$E/logs/modsec_audit_tail.json"
dc exec -T fail2ban sh -c 'grep -E "Ban|Unban|Found" /var/log/fail2ban/fail2ban.log | tail -n 60' > "$E/logs/fail2ban_actions.log"
dc exec -T client sh -c 'tail -n 400 /work/logs/central/events.ndjson' > "$E/logs/central_events_tail.ndjson"
ls -1 "$E" "$E"/tls "$E"/fail2ban "$E"/logs
