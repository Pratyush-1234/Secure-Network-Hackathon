# PS6 Shield Wall: report

**Scenario:** a legacy web application cannot be patched this week, so protect it at the network edge.
**Approach:** put a TLS-terminating reverse proxy with a tuned WAF, rate limiting, automatic banning and centralized logging in front of an intentionally vulnerable application. Prove the attacks work before the shield, are blocked after it, and that normal users don't notice the shield.

---

## 1. What we built

| Component | Choice | Why |
|---|---|---|
| Vulnerable app | **DVWA** (`ghcr.io/digininja/dvwa`, PHP 8.5, security level **low**) + MariaDB 10.11 | The only common public target that has *all* the required classes: SQLi, reflected and stored XSS, file inclusion / traversal, OS command injection, and a real login form. Juice Shop has no command injection. |
| Edge proxy + WAF | **nginx 1.30 + ModSecurity 3.0.17 + OWASP CRS 4.30.0** (official `owasp/modsecurity-crs` image), paranoia level **2**, anomaly scoring with inbound threshold 5 | The industry-standard open-source WAF. PL2 gives broader detection than the default PL1, at the cost of false positives that we tuned (see §4). |
| TLS termination | TLS 1.2 + 1.3 only, ECDHE/AEAD ciphers only, ECDSA P-256 cert from a lab CA (SANs `shieldwall.local`, `localhost`, `waf`), HSTS, HTTP→HTTPS 301 | nmap `ssl-enum-ciphers` grades every offered suite **A**. TLS 1.0/1.1 are refused by the server (alert 70). |
| Rate limiting | nginx `limit_req`: login POST **6/min per IP, burst 3** (HTTP 429), general 20 r/s burst 40, max 20 connections per IP | Only credential *submissions* are counted (GET login page is not). |
| Automatic blocking | **fail2ban 1.1.1** sharing the WAF container's network namespace | Bans are iptables rules at the edge only; the host firewall is never modified. Two jails: brute force (5×429 in 60 s → 10 min ban) and WAF abuse (100 phase-1/2 denies in 120 s → 15 min ban). |
| Virtual patches (stretch) | ModSecurity rules **10100** (`exec/ ip` must be an IPv4 address or hostname), **10110** (`sqli/ id` must be numeric), **10120** (`fi/ page` must be on the allow-list) | Positive-security model: describes the *valid* input, so new encodings and new payloads don't matter. |
| Log centralization | **Vector 0.62** tails nginx access (JSON), nginx error (rate limits), ModSecurity audit (JSON) and fail2ban. It normalizes everything with VRL into one schema → `logs/central/events.ndjson` | One stream holding every proxy, WAF and ban event, joinable by `request_id` (= ModSecurity transaction ID = `X-Request-ID` header). |
| Alert summary + dashboard (stretch) | `scripts/alert_summary.py` (stdlib Python) → `reports/alert_summary.md/.csv/.json`, `reports/dashboard.html` | Counts per attack type with ATT&CK / CWE / CAPEC, top rules, sources, timeline, and a benign false-positive check. |
| Segmentation | App and DB on an `internal` Docker network with no host ports; only the WAF is attached to both networks | The WAF cannot be bypassed. `setup.php` and `phpinfo.php` answer 404 at the edge, and the DB reset runs from the internal network only. |

Traffic generators run in a toolbox container (curl, sqlmap 1.10.11, nikto 2.6.0, ffuf 2.1.0, nmap 7.99), so nothing is installed on the host.
The **attacker (10.66.10.66)** and the **benign client (10.66.10.20)** are separate containers with fixed IPs, so per-IP rate limits and bans can be shown to hit only the attacker.

## 2. Scripts

**`scripts/attack.sh`**: 6 classes, 16 scored test cases (27 HTTP requests including the 12-attempt burst):

| Class | Requests |
|---|---|
| SQL injection | `1' OR '1'='1` · `1' UNION SELECT user,password FROM users-- -` · `1' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -` |
| XSS | `<script>alert(document.cookie)</script>` · `<svg/onload=alert(1)>` · stored `<img src=x onerror=alert(1)>` (POST) |
| Path traversal | `../../../../../../etc/passwd` · `..%2f..%2f…etc%2fpasswd` · `/etc/passwd` |
| Command injection | `127.0.0.1; cat /etc/passwd` · `127.0.0.1 \| id` · `127.0.0.1 && whoami && uname -a` (POST) |
| Scanner UA | sqlmap, Nikto and Nmap NSE user agents |
| Brute-force burst | 12 × `POST /login.php` for `admin`, each with a fresh CSRF token. The correct password is **last**, then a check that the source is banned |

The same script runs in `--mode direct` (straight at DVWA, no WAF) to prove each attack really works, and in `--mode waf`. `--tools` adds real sqlmap, nikto and ffuf runs.

**`scripts/benign.sh`**: 41 requests:
- landing and login pages, then **login with the correct credentials**
- home, about, instructions and docs
- **user lookup (search) id=1..5**
- **name search** with realistic tricky names (`O'Brien`, `José García`, `Tom & Jerry`, `Dr. Jane Doe, PhD`)
- two guestbook posts with apostrophes, `--` and `;`
- ping `127.0.0.1` and `localhost`, and the file viewer for its own files
- the brute page with one correct check, static assets, then logout and **login again**

Every request is checked twice: was it *allowed* by the edge, and did the *expected content* come back (functional)?

**`scripts/judge_variations.sh`**: 44 extra payloads not in the attack script:
- case mixing, `/**/` comments, double URL encoding
- `....//`, backslash traversal, `php://filter`, `file://`, RFI
- `%0a`, `` `id` ``, `$(…)`, `c'a't /e??/p?ss??`
- 8 more tool user agents

## 3. Results

All numbers come from the clean `make test` run (`evidence/acceptance_test_output.txt`) and the run CSVs in `evidence/`.

### Before the shield (`evidence/attack_direct.csv`)
**16/16 succeeded.**
- **SQLi:** the tautology returned all 5 users, the UNION dumped the MD5 hash `5f4dcc3b…`, and the sleep delayed the response 3.0 s.
- **XSS:** all 3 payloads were reflected or stored unescaped.
- **Path traversal:** all 3 returned `root:x:0:0:`.
- **Command injection:** returned `/etc/passwd`, `uid=33(www-data)` and `www-data`.
- **Scanner UAs:** reached the app.
- **Brute force:** attempt 12 logged in as admin.

### After the shield

| Acceptance check | Result | Evidence |
|---|---|---|
| Every attack-script request blocked | **16/16 blocked**. The 15 payload requests got **403** from ModSecurity. In the burst, the first 2–3 wrong passwords reach the app (by design), **all later attempts get 429**, the correct password never reaches the app, and the IP is **banned ~2 s later** (connection refused) | `evidence/attack_waf.csv` |
| ≥ 95% of benign allowed | **41/41 (100%) allowed, 41/41 functionally correct, 0 WAF events for the client** | `evidence/benign_waf.csv`, `reports/alert_summary.md` ("False positives": none) |
| Evasion variants | **44/44 blocked** | `evidence/judge_variations.csv` |
| Brute force: rate limit + auto block | 429 → fail2ban `shieldwall-bruteforce` bans 10.66.10.66 (iptables REJECT in the WAF namespace). The benign client still gets 200 | `evidence/fail2ban/fail2ban_status.txt` |
| Real tools (`make attack-tools`) | sqlmap (random browser UA): **96 of its requests got 403, then the `shieldwall-waf` jail (100 denies from the source in 120 s, replay payloads included) banned it mid-scan**, before it confirmed any injection. nikto, run next in the same sequence, was refused outright (`Unable to connect`) by that ban. In a standalone nikto run (which rotates real browser UAs, so UA rules cannot see it), it was caught by behaviour: CRS restricted-file rules (403) and the general rate limit (429), followed by the ban | `evidence/tools/`, `evidence/attack_waf_tools.csv` |
| TLS | TLS 1.3 / TLS 1.2 handshakes verify against the lab CA. TLS 1.0 and 1.1 get **alert 70 protocol_version**. Only AEAD/ECDHE suites are offered, all grade A | `evidence/tls/` |
| Centralized logs + summary | `proxy`, `waf` and `fail2ban` sources in one NDJSON stream. The summary covers 7 attack-type rows with ATT&CK, CWE and CAPEC | `reports/alert_summary.md`, `reports/dashboard.html` |

**Alert summary by attack type** (final sequence: `make test`, then `make ratelimit`, then `make attack-tools`; full table in `reports/alert_summary.md`):

| Attack type | Blocked | ATT&CK | Top rules |
|---|---:|---|---|
| SQL Injection | 113 | T1190 | 942100 (libinjection), 942400, 942410, 942150 |
| Command Injection | 18 | T1190 | 932236, 932160, 930120, **10100** (virtual patch) |
| Cross-Site Scripting | 14 | T1190 | 941100 (libinjection), 941390, 941160, 941320 |
| Scanner / Recon | 14 | T1595.002 | 913100, 10200 |
| Path Traversal / File Inclusion | 12 | T1190 | 930110, 930120, 930100 |
| Brute Force / Rate Limit | 16 × 429 + 2 bans | T1110.001 | nginx `limit_req` (zone `login`), fail2ban |
| Flood / Rate Limit (from `make ratelimit` T2) | 74 × 429 | T1499 | nginx `limit_req` (zone `general`) |
| Automated attack (repeated WAF blocks) | 1 ban | T1595.002 / T1190 | fail2ban `shieldwall-waf` |

## 4. Tuning (summary; full detail in `docs/tuning-notes.md`)

- **FP-1 (PL1):** CRS response-leakage rules fired on `/instructions.php`, because DVWA's README quotes MySQL/PHP error strings. We found that nginx can't enforce a response-phase deny once headers are sent (`header already sent` alert): the user still gets the page, but a fake "blocked" alert is logged every time. **Fix:** remove those 4 rule IDs on that one URI.
- **FP-2 (PL2):** a guestbook message with apostrophes and `--` / `;` tripped 942200, 942440 and 932200. **Fix:** remove those 3 IDs for `ARGS:mtxMessage` on `/vulnerabilities/xss_s/` only. The XSS rules still inspect it, so the stored-XSS attack is still blocked.
- **FN-1 (bypass):** `ip=127.0.0.1%0aid` got through CRS PL1 *and* our first virtual patch. libmodsecurity compiles `@rx` in multiline mode, so `^…$` matched the first line. **Fix:** anchor every allow-list with `\A…\z`. The payload is now blocked by rule 10100 alone.
- **Operational:** fail2ban counts only phase-1/2 denies. The scanner-jail threshold is high enough that one scripted replay shows the WAF's own verdict per request, but a real scanner is banned.

Untuned PL2 benign result: 39/41 (95.1%). Tuned PL2: **41/41 (100%)**, with no loss of attack coverage.

## 5. ATT&CK mapping (summary; full detail in `docs/attack-mapping.md`)

| Activity | Technique | Defence (mitigation / D3FEND) |
|---|---|---|
| SQLi, XSS, traversal, command injection against the web app | **T1190** Exploit Public-Facing Application (cmd-injection then **T1059.004** Unix Shell) | WAF + virtual patches: **M1050** Exploit Protection, **M1031** Network Intrusion Prevention; **D3-ITF**, **D3-NTSA** |
| Scanner user agents, sqlmap, nikto, ffuf | **T1595.002** Vulnerability Scanning (ffuf: **T1595.003** Wordlist Scanning) | UA rules + ban: **M1031**, **M1037** Filter Network Traffic; **D3-ITF** |
| Login brute-force burst | **T1110.001** Password Guessing | Rate limit + ban: **M1036** Account Use Policies, **M1037**; **D3-ANET**, **D3-ISVA** |
| Monitoring of all of the above | - | Central log + summary: **D3-NTA** Network Traffic Analysis |

Weakness references: CWE-89 / CAPEC-66, CWE-79 / CAPEC-63, CWE-22 / CAPEC-126, CWE-78 / CAPEC-88, CWE-307 / CAPEC-49. (ATT&CK v20.1, CAPEC v3.9.)

## 6. Limitations and residual risk (honest)

1. **A WAF is a compensating control, not a fix.** DVWA is still vulnerable behind it. A novel bypass of both CRS and the virtual patch would still exploit it. The virtual patches cover the four known-vulnerable endpoints with allow-lists; other endpoints rely on CRS signatures.
2. **Response-phase rules on nginx are detect-only.** They can't stop a response that is already streaming. Data-leakage protection must come from the inbound rules.
3. **Per-IP brute-force controls** can be evaded by distributed attempts (botnets, credential stuffing from many IPs), and the first ≤ 3 guesses per IP reach the app. **Recommendation:** MFA (M1032), per-account lockout or backoff in the app, and breached-password checks once it can be changed.
4. **Shared source IPs:** clients behind one NAT (or, in this lab, the host via the Docker gateway 10.66.10.1) share a rate-limit bucket and a ban. In production, use the real client IP from a trusted upstream header (`real_ip`) and consider longer bans for repeat offenders (fail2ban `recidive`).
5. **Lab TLS:** the cert is issued by a private lab CA. In production, use a public CA (ACME) and enable OCSP stapling.
6. **Log privacy:** request bodies are deliberately *not* stored in the ModSecurity audit log (no part C), so passwords POSTed to `/login.php` are not retained. Only the matched fragment of a blocked parameter is logged. DVWA's brute-force exercise sends credentials in the **query string** (GET), and those do appear in the access-log URI. In production, mask such parameters in the `log_format` or move the form to POST.

## 7. Recommendation for next week (when patching becomes possible)

1. Fix the root causes in the code:
   - parameterized SQL queries (CWE-89)
   - output encoding / CSP (CWE-79)
   - `include` allow-list (CWE-22)
   - remove `shell_exec`, or validate as IPv4 and use `escapeshellarg` (CWE-78)
2. Keep the WAF at PL2 with the virtual patches as defence in depth. Switch individual virtual patches to log-only once each fix is verified.
3. Add MFA and account lockout to the login.
4. Forward `logs/central` to the SOC SIEM.
5. Alert on fail2ban bans and on any `blocked_waf` event from an internal or trusted range.
