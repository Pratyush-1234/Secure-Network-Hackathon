# Tuning notes: false positives, fixes and why they are safe

**Goal (PS6 task 2):** block 100% of the attack script and allow at least 95% of the benign script.
**Result:** 16/16 attack test cases blocked, 41/41 benign requests allowed (100%), 0 WAF events for the benign client.
We also block 44/44 extra evasion variants (`scripts/judge_variations.sh`).

**Stack:** OWASP CRS **4.30.0** on ModSecurity **3.0.17** (nginx connector 1.0.4), image `owasp/modsecurity-crs:4.30.0-nginx-202611160811`.

## Method

1. **Baseline at the CRS defaults** (paranoia level 1, inbound threshold 5, outbound threshold 4). We ran the benign and attack scripts and read every audit-log entry produced by the benign client (10.66.10.20).
2. **Raise the paranoia level (PL) to 2** for stronger detection, then rerun the benign script *untuned*. This is the evidence in `evidence/tuning/benign_pl2_untuned.csv`.
3. **Fix each false positive** with the narrowest possible exclusion: one URI, one rule ID, and one parameter where possible. CRS rules are never disabled globally, and the anomaly threshold is never raised.
4. Rerun all three scripts (benign, attack, evasion variants) after each change.
5. **Hunt for false negatives (bypasses).** We added hand-written evasion payloads and fixed what got through (see FN-1).

## Results per stage

| Stage | Benign allowed | Attack blocked | Evasion variants blocked |
|---|---|---|---|
| PL1, untuned | 40/40 (100%)* | 16/16 | 43/44 (`%0a` command-injection bypass) |
| PL1, plus fixed virtual patch (FN-1) | 40/40 | 16/16 | 44/44 |
| PL2, untuned | **39/41 (95.1%)**, 2 FPs | 16/16 | 44/44 |
| **PL2, tuned (deployed)** | **41/41 (100%)** | **16/16** | **44/44** |

\* The HTTP status said "allowed" at PL1, but the audit log showed response-side false positives on `/instructions.php` (FP-1). We fixed those too.

## False positives found and fixed

### FP-1: response "data leakage" rules on the documentation page (PL1 and above)

| | |
|---|---|
| Request | `GET /instructions.php`, `GET /instructions.php?doc=readme` (benign browsing) |
| Rules | 951230 (MySQL error leakage), 951250 (SQLite error leakage), 953100 (PHP error leakage), 953110 (PHP source leakage). Outbound score 18 > 4 triggers 959100 |
| Root cause | The page renders DVWA's README. Its troubleshooting section quotes real error strings: `ERROR 1045 (28000)`, `Fatal error:`, `fopen`, `Cannot modify header information`. |
| Impact | ModSecurity logged an *interrupted 403*. nginx could not apply it, because the response headers were already sent (`[alert] header already sent while sending to client`, see `evidence/tuning/nginx_header_already_sent.log`). So the user saw the page, but every view produced a fake "blocked" alert. These would have polluted the alert summary and fed the fail2ban scanner jail with the benign client's IP. |
| Fix | Rule **1010** (`waf/modsec/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`): `ctl:ruleRemoveById` for those 4 response rules, **only when `REQUEST_FILENAME == /instructions.php`**. |
| Why it is safe | The page is static documentation and no user input reaches a SQL or PHP sink. All inbound rules still apply to it, and leakage detection stays active on every other URL, including the vulnerable pages. |

### FP-2: free-text guestbook message (PL2)

| | |
|---|---|
| Request | `POST /vulnerabilities/xss_s/` with `mtxMessage=Great site, thanks! I'll be back at 5 o'clock.` and `mtxMessage=Can't wait -- see you @ 5pm; bring snacks & drinks (and the 2024/25 report)!` |
| Rules | **942200** (MySQL comment/space-obfuscated injection) on `, thanks! I'll be back at 5 o'`; **942440** (SQL comment sequence) on `--`; **932200** (RCE bypass) on quote + `;` + `/` |
| Root cause | Normal English uses apostrophes, double dashes and semicolons, the same characters these PL2 heuristics look for. |
| Fix | Rule **1020**: `ctl:ruleRemoveTargetById=942200;ARGS:mtxMessage`, plus the same for 942440 and 932200, **only on `/vulnerabilities/xss_s/`**. |
| Why it is safe | Only 3 rule IDs are removed, and only for one parameter on one URI. The XSS family (941xxx) still inspects `mtxMessage`, so the stored-XSS attack (`<img src=x onerror=alert(1)>`) is still blocked by 941xxx. libinjection SQLi (942100) and every other SQLi/RCE rule also still inspect it. `txtName` and every other parameter keep the full PL2 rule set. |

### FP-3 (operational): `fail2ban` must not count response-phase events

In nginx the phase 3/4 (response) "denies" are not enforceable, and they are triggered by the server's content, not by the client's input. The `shieldwall-modsec` filter only counts **phase 1/2** denies (`Access denied with code 403 (phase [12])`). Without this, a benign user browsing a page with leaky content could be banned.

## False negatives found and fixed (bypass hunting)

### FN-1: newline command injection `ip=127.0.0.1%0aid`

| | |
|---|---|
| Found by | `scripts/judge_variations.sh` (HTTP 200, `uid=33(www-data)` returned by the app) |
| Why CRS missed it | At PL1, CRS deliberately skips very short Unix commands such as `id` after a newline, to avoid false positives. |
| Why our first virtual patch missed it | libmodsecurity v3 compiles every `@rx` with **PCRE2_MULTILINE**, so `^`/`$` match at each line break. The allow-list `^<ipv4>$` matched the first line, `127.0.0.1`. |
| Fix | All virtual-patch allow-lists (10100, 10110, 10120) now anchor with `\A ... \z` (absolute start and end of the subject). |
| Verified | The same payload now gets 403 from rule **10100** (the only rule that fires on it), and benign `ip=127.0.0.1` / `ip=localhost` still pass. |

## Operational tuning

| Setting | Value | Reason |
|---|---|---|
| Paranoia level | **2** (`PARANOIA` in `.env`) | Better coverage than PL1. The two FPs it introduced are fixed narrowly. |
| Inbound / outbound anomaly threshold | 5 / 4 (CRS defaults) | Never raised, so one critical match still blocks. |
| Allowed methods | `GET HEAD POST` (rule 1000) | The legacy app uses nothing else. PUT, DELETE, TRACE and others are blocked. |
| Login rate limit | `POST /login.php` and `/vulnerabilities/brute/?Login=` at 6/min per IP, burst 3 | A person mistyping twice is unaffected. A tool is cut off after about 3 attempts. GET requests to the login page do not count. |
| General rate limit | 20 req/s per IP, burst 40, plus 20 concurrent connections | Stops floods and crawler bursts without affecting page loads with assets. |
| fail2ban `shieldwall-bruteforce` | 5 rate-limit rejections in 60 s, then a 10 min ban | Escalates from throttling to blocking. |
| fail2ban `shieldwall-waf` | 100 phase-1/2 WAF denies in 120 s, then a 15 min ban | A scanner is banned: in the final run sqlmap was cut off mid-scan, after 96 of its requests had been answered with 403 (the jail counts every phase-1/2 deny from the source in the window, including the replay payloads). A human tester or the scripted replay (16 + 44 requests) is not, so the scripts show the WAF's own verdict per request. |
| Hidden at the edge | `setup.php`, `phpinfo.php`, `config/`, `database/`, `docs/`, `tests/`, `.git`, `.env` return 404 | Admin and diagnostic surface the public never needs. The DB reset runs from the internal network only. |
| Response hardening | `Secure; HttpOnly; SameSite=Lax` added to the app's cookies, plus HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy | Found by nikto. Fixed at the edge, because the app cannot be patched. |

## How to reproduce the tuning evidence

```bash
PARANOIA=1 docker compose up -d --force-recreate waf fail2ban   # or edit .env
make unban && make benign && make variations
# comment out rules 1010/1020, then recreate the WAF to see the untuned PL2 false positives
```
