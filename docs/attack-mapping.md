# ATT&CK / CWE / CAPEC / D3FEND mapping

**Framework versions:** MITRE ATT&CK **Enterprise v20.1**, CAPEC **v3.9**, CWE (current list), MITRE D3FEND (current).
Every ID below was checked against the MITRE websites on 2026-11-21.

## Attack activity → ATT&CK

| # | Attack in `scripts/attack.sh` | ATT&CK tactic | Technique | Weakness (CWE) | Attack pattern (CAPEC) |
|---|---|---|---|---|---|
| 1 | SQL injection on `/vulnerabilities/sqli/` (tautology, UNION hash dump, time-based blind) | Initial Access | **T1190** Exploit Public-Facing Application | CWE-89 SQL Injection | CAPEC-66 SQL Injection |
| 2 | Cross-site scripting: reflected (`xss_r`) and stored (`xss_s`) | Initial Access | **T1190** Exploit Public-Facing Application | CWE-79 Cross-site Scripting | CAPEC-63 Cross-Site Scripting (XSS) |
| 3 | Path traversal / local file inclusion on `/vulnerabilities/fi/` (`../`, `..%2f`, absolute path) | Initial Access | **T1190** Exploit Public-Facing Application | CWE-22 Path Traversal | CAPEC-126 Path Traversal |
| 4 | OS command injection on `/vulnerabilities/exec/` (`;`, `\|`, `&&`) | Initial Access → Execution | **T1190**, then post-exploitation **T1059.004** Unix Shell | CWE-78 OS Command Injection | CAPEC-88 OS Command Injection |
| 5 | Scanner user agents (sqlmap, Nikto, Nmap NSE), and with `--tools` real sqlmap / nikto / ffuf runs | Reconnaissance | **T1595.002** Active Scanning: Vulnerability Scanning (ffuf content discovery: **T1595.003** Wordlist Scanning) | - | CAPEC-541 Application Fingerprinting |
| 6 | Login brute-force burst on `POST /login.php` (12 passwords, correct one last) | Credential Access | **T1110.001** Brute Force: Password Guessing | CWE-307 Improper Restriction of Excessive Authentication Attempts | CAPEC-49 Password Brute Forcing |

## Defences → ATT&CK mitigations and D3FEND

| Shield Wall control | Where | Counters | ATT&CK mitigation | D3FEND technique |
|---|---|---|---|---|
| ModSecurity v3 + OWASP CRS 4.30 at PL2 (anomaly scoring, inbound threshold 5) | `docker-compose.yml` (waf), `waf/modsec/*` | T1190 | **M1050** Exploit Protection, **M1031** Network Intrusion Prevention | **D3-ITF** Inbound Traffic Filtering, **D3-NTSA** Network Traffic Signature Analysis |
| Virtual patches 10100 / 10110 / 10120: positive allow-lists for `ip`, `id`, `page` | `waf/modsec/SHIELDWALL-CUSTOM-RULES.conf` | T1190 (CWE-78/89/22) | **M1050** Exploit Protection | **D3-ITF** Inbound Traffic Filtering |
| Scanner UA detection (CRS 913100 + rule 10200), restricted-file rules, edge 404 for admin paths | CRS + custom rules + nginx | T1595.002 / T1595.003 | **M1031**, **M1037** Filter Network Traffic | **D3-NTSA**, **D3-ITF** |
| Login rate limit (`limit_req` 6/min, burst 3 → HTTP 429) | `waf/nginx/default.conf.template` | T1110.001 | **M1036** Account Use Policies | **D3-ANET** Authentication Event Thresholding, **D3-ISVA** Inbound Session Volume Analysis |
| Automatic blocking (fail2ban bans the source IP in the WAF network namespace) | `fail2ban/` | T1110, T1595.002 | **M1037** Filter Network Traffic | **D3-ITF** Inbound Traffic Filtering |
| TLS termination (TLS 1.2/1.3 only, ECDSA cert, HSTS), cookie hardening | nginx | Network sniffing of credentials / session theft (supporting control) | **M1041** Encrypt Sensitive Information | (Message encryption) |
| Centralized logs (Vector) + alert summary by attack type | `vector/vector.yaml`, `scripts/alert_summary.py` | Detection for all of the above | **M1031** | **D3-NTA** Network Traffic Analysis |
| Backend on an `internal` Docker network, so the app is only reachable through the WAF | `docker-compose.yml` | Bypassing the edge | **M1030** Network Segmentation, **M1037** | **D3-ITF** |

**Long-term fix (outside this week's constraint):** **M1051** Update Software and **M1016** Vulnerability Scanning, i.e. patch the code. Add **M1032** Multi-factor Authentication on the login.

## Per-request evidence of the mapping

Each blocked request carries its technique in two places:

- The central event (`logs/central/events.ndjson`) has the `attack_type`, `attack_families`, `mitre` and `rule_ids` fields.
- The custom rules are tagged `attack/T1190` or `attack/T1595.002`, and every CRS rule carries its `capec/...` tag. Both appear in the ModSecurity audit log.

`reports/alert_summary.md` aggregates these per attack type, including the ATT&CK, CWE and CAPEC columns.
