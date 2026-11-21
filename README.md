# PS6 Shield Wall: protecting a public-facing legacy application

A legacy web app (**DVWA**, run fully vulnerable at security level *low*) "cannot be patched this week".
We protect it at the network edge with an **nginx reverse proxy + ModSecurity v3 + OWASP CRS 4.30**.
The proxy terminates TLS, rate-limits the login, auto-bans abusers with **fail2ban**, and ships every proxy, WAF and ban event to one central log with **Vector**.
A Python job turns that log into an **alert summary by attack type**, plus a dashboard.

| Acceptance check | Result |
|---|---|
| WAF in front of the app, with TLS termination | TLS 1.2/1.3 only. TLS 1.0/1.1 get alert 70 (protocol_version). ECDSA cert, HTTP 301 → HTTPS, HSTS |
| Block every request in the attack script | **16/16 test cases blocked** (SQLi ×3, XSS ×3, traversal ×3, cmd-injection ×3, scanner UA ×3, brute-force burst) |
| Allow at least 95% of the benign script | **41/41 = 100% allowed**, 100% functionally correct, **0 false positives** |
| Rate limit + automatic blocking for login brute force | 429 after the burst allowance. The correct password (sent last) never reaches the app, and the source IP is banned about 2 s later. The benign client is unaffected |
| Centralized logs + alert summary by attack type | `logs/central/events.ndjson` → `reports/alert_summary.md / .csv / .json` |
| Stretch: virtual patching | Rules 10100 / 10110 / 10120 (allow-lists). 10100 stops `ip=127.0.0.1%0aid`, which CRS misses |
| Stretch: dashboard | `reports/dashboard.html` (self-contained) |
| Extra: judge-style evasion variants | **44/44 blocked** (`scripts/judge_variations.sh`) |

Before the WAF, the same attack script **exploits all 16 cases** against the bare app: password hashes dumped, `/etc/passwd` read, `uid=33(www-data)`, admin password found. See `evidence/attack_direct.csv`.

## Architecture

```
                      frontend 10.66.10.0/24                          backend 10.66.20.0/24 (internal: no route out, no host ports)
 attacker 10.66.10.66 ──┐                                         ┌──► dvwa 10.66.20.20:80 (PHP/Apache, security=low) ──► mariadb 10.66.20.30
 client   10.66.10.20 ──┼──► waf 10.66.10.10  :9443 TLS / :9080 ──┤
 host 127.0.0.1:9443 ───┘    nginx 1.30 + ModSecurity 3.0.17      │   attacker-direct 10.66.20.66 (profile "baseline":
                             + OWASP CRS 4.30.0 (PL2, scoring)    │   the "before" run and the DB reset only)
                             + limit_req + virtual patches        │
                             fail2ban 1.1.1 ── shares the WAF's network namespace: iptables bans apply at the edge only
                             vector 0.62 ── tails nginx access/error + ModSecurity audit + fail2ban
                                            └─► logs/central/events.ndjson ──► scripts/alert_summary.py ──► reports/
```

**Request path:** TLS handshake, then nginx rate limits (general 20 r/s; login 6/min, burst 3), then ModSecurity phase 1/2 (CRS anomaly scoring, then the Shield Wall virtual patches), then proxy to DVWA, then response headers hardened (Secure/HttpOnly/SameSite cookies, HSTS and others).
Every request gets an `X-Request-ID`, which is also the ModSecurity transaction ID, so you can join a 403 back to its audit entry.

## Requirements and quick start

Linux with Docker Engine ≥ 24 and Compose v2 (tested on Ubuntu 24.04, Docker 29.9, Compose 5.6). You also need `make`, `openssl` (for cert generation) and `jq` (the acceptance test uses it).
Nothing else is installed on the host. sqlmap, nikto, ffuf and nmap run inside the `shieldwall-tools` container.

```bash
make up          # certs + build toolbox + start 7 containers + create the DVWA DB
make baseline    # BEFORE: attacks straight at the app (no WAF) → all exploited
make test        # AFTER: clean reset + full acceptance test (benign, variations, attack, summary)
make evidence    # TLS / nmap / fail2ban / log evidence → evidence/
open reports/dashboard.html
```

Browse the protected app at **https://localhost:9443** (login `admin` / `password`). Import `certs/ca.crt` to drop the browser warning.
Host ports are 9080/9443 because 8080 was taken on the build machine. Change them in `.env`.

| `make` target | What it does |
|---|---|
| `attack` | Attack replay through the WAF (from 10.66.10.66) |
| `attack-tools` | The same, plus **real sqlmap, nikto and ffuf** through the WAF (expect 403s, then a ban) |
| `benign` | Benign replay (from 10.66.10.20) |
| `variations` | 44 extra evasion payloads |
| `ratelimit` | Dedicated rate-limit test: page views not throttled, flood → 429, login burst → 429, auto-ban, benign client unaffected |
| `summary` | Regenerate the alert summary and dashboard from the central log |
| `status` / `unban` | Show jails and bans / lift all bans |
| `reset` | Wipe logs, bans and rate-limit state, recreate the edge, reset the DB |
| `unprotected-up` / `unprotected-down` | DEMO ONLY: expose / hide the bare app (no WAF) at http://127.0.0.1:8081 |
| `zip` | Package the submission (excludes private keys and runtime logs) |

## Live demo runbook (5 to 7 min)

**Browser before/after demo:** run `make unprotected-up` to open the bare app at **http://127.0.0.1:8081** next to the protected **https://localhost:9443**. Follow **[docs/demo-guide.md](docs/demo-guide.md)** for the side-by-side script, payloads and talking points. `/setup.php` answers **404 through the WAF on purpose**: it is the DB-reset page, hidden at the edge.

1. **The problem (1 min).** Run `make baseline`. Every attack succeeds against the bare app: the UNION query dumps MD5 hashes, `../../etc/passwd` and `; cat /etc/passwd` return file contents, `| id` returns `uid=33(www-data)`, and the brute force finds `admin/password`.
2. **The shield (2 min).** Run `make test`. TLS is verified. Benign traffic gets 41/41 through. The 44 evasion variants and 16 attack cases are all blocked, each with a `request-id`. The brute force goes from 429 to a ban, while the benign client still gets 200.
3. **Why it works (1 min).** Show `waf/modsec/SHIELDWALL-CUSTOM-RULES.conf` (the virtual patches and the `\A…\z` lesson), `docs/tuning-notes.md` (the 2 PL2 false positives, fixed per parameter), and the `limit_req` + fail2ban settings.
4. **Detection (1 min).** Open `reports/dashboard.html` and `reports/alert_summary.md` (per attack type, with ATT&CK / CWE / CAPEC). Run `make logs` to watch the central stream.
5. **Judge's choice (1 to 2 min).** Run any of the commands below.

### Commands for judges' own payloads

```bash
make unban
# the attacker container: any payload, any tool
docker compose exec attacker curl -sk -o /dev/null -w '%{http_code}\n' \
  "https://shieldwall.local:9443/vulnerabilities/sqli/?id=1%27%20AND%20SLEEP(5)--%20-&Submit=Submit"     # 403
docker compose exec attacker curl -sk -o /dev/null -w '%{http_code}\n' \
  "https://shieldwall.local:9443/vulnerabilities/fi/?page=....//....//....//etc/passwd"                  # 403
docker compose exec attacker curl -sk -o /dev/null -w '%{http_code}\n' -d 'ip=127.0.0.1%0aid&Submit=Submit' \
  https://shieldwall.local:9443/vulnerabilities/exec/                                                    # 403 (rule 10100)
docker compose exec attacker sqlmap -u "https://shieldwall.local:9443/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --random-agent
# from the host browser or curl
curl -sk "https://localhost:9443/vulnerabilities/xss_r/?name=<script>alert(1)</script>" -o /dev/null -w '%{http_code}\n'  # 403
# find why a request was blocked: X-Request-ID response header → audit log
docker compose exec waf grep <request-id> /var/log/shieldwall/modsec/audit.json | jq '.transaction.messages[].message'
```

Host-originated requests arrive from the Docker gateway (10.66.10.1). If a judge brute-forces from the host, that address gets banned too. `make unban` lifts it.

## Repository layout

```
docker-compose.yml               7 services, 2 networks (backend is internal)
.env                             ports + CRS paranoia level (2)
waf/nginx/default.conf.template  TLS, redirects, rate limits, security headers, edge-hidden paths
waf/nginx/logging.conf.template  JSON access log
waf/nginx/shieldwall_proxy.conf  proxy settings + cookie hardening
waf/modsec/setup.conf.template   ModSecurity include order
waf/modsec/REQUEST-900-...conf   CRS tuning + scoped false-positive exclusions (1000, 1010, 1020)
waf/modsec/SHIELDWALL-CUSTOM-RULES.conf   virtual patches 10100/10110/10120, scanner UA rule 10200
fail2ban/jail.d, filter.d        brute-force jail + WAF-abuse jail (bans in the WAF network namespace)
vector/vector.yaml               log centralization and normalization (VRL)
certs/gen-certs.sh               lab CA + ECDSA P-256 server cert (SANs: shieldwall.local, localhost, waf, IPs)
tools/Dockerfile                 attacker/client toolbox (curl, sqlmap 1.10.11, nikto 2.6, ffuf 2.1, nmap 7.99)
scripts/attack.sh                attack replay (--mode waf | direct, --tools)
scripts/benign.sh                benign replay (41 requests)
scripts/judge_variations.sh      44 evasion variants
scripts/alert_summary.py         alert summary + dashboard (stdlib only)
scripts/acceptance_test.sh       end-to-end acceptance test
scripts/collect_evidence.sh      TLS / fail2ban / log evidence
scripts/dvwa_setup.sh, lib.sh    DB init, shared helpers
docs/report.md                   full write-up
docs/tuning-notes.md             false positives / negatives and their fixes
docs/attack-mapping.md           ATT&CK v20.1, CWE, CAPEC, D3FEND mapping
docs/PS6_Implementation_Answers.md  answers to the PS6 implementation worksheet (evidence in evidence/worksheet/)
evidence/                        CSVs and transcripts of every run, TLS + nmap, fail2ban, log excerpts
reports/                         alert_summary.md/.csv/.json, dashboard.html
```

**Pinned versions:**
- `owasp/modsecurity-crs:4.30.0-nginx-202611160811`
- `ghcr.io/digininja/dvwa:latest@sha256:61167ec2…` (pinned by digest: the 2026-11-17 build, PHP 8.5)
- `mariadb:10.11`
- `crazymax/fail2ban:1.1.1`
- `timberio/vector:0.62.0-alpine`
- `python:3.13-alpine`

**Lab-only secrets:** the DVWA/DB passwords and the CA key in `certs/` are throw-away lab values. `make zip` leaves out `*.key`.
Attacks are only ever sent to this lab, on this laptop.
