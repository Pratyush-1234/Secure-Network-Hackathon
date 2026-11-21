# Shield Wall: WAF & proxy alert summary

_Generated 2026-11-21 06:17:43 UTC from `/work/logs/central/events.ndjson` (703 centralized events: nginx access + error, ModSecurity audit, fail2ban)._

## Totals

| Metric | Value |
|---|---:|
| Requests reaching the edge proxy | 430 |
| Allowed to the application | 162 |
| Blocked by ModSecurity / CRS (HTTP 403) | 171 |
| Rejected by login rate limit (HTTP 429) | 97 |
| Sensitive paths hidden at the edge (HTTP 404) | 0 |
| WAF audit-log blocked transactions | 171 |
| Response-leakage detections (detect-only) | 0 |
| Automatic IP bans (fail2ban) | 3 |
| Banned source IPs | 10.66.10.66 |

## Alerts by attack type

| Attack type | Blocked | Detect-only | IP bans | Sources | ATT&CK | CWE | CAPEC | Top rules | First seen | Last seen |
|---|---:|---:|---:|---:|---|---|---|---|---|---|
| SQL Injection | 113 | 0 | 0 | 1 | T1190 | CWE-89 | CAPEC-66 | 942100, 942400, 942410, 942150 | 06:10:55 | 06:14:01 |
| Flood / Rate Limit | 74 | 0 | 0 | 1 | T1499 | CWE-770 | CAPEC-125 | nginx:limit_req | 06:13:36 | 06:13:36 |
| Command Injection | 18 | 0 | 0 | 1 | T1190 | CWE-78 | CAPEC-88 | 932236, 932160, 930120, 10100 | 06:10:55 | 06:13:58 |
| Brute Force / Rate Limit | 16 | 0 | 2 | 1 | T1110.001 | CWE-307 | CAPEC-49 | nginx:limit_req, fail2ban:ban | 06:10:58 | 06:13:45 |
| Cross-Site Scripting | 14 | 0 | 0 | 1 | T1190 | CWE-79 | CAPEC-63 | 941100, 941390, 941160, 941320 | 06:10:55 | 06:13:57 |
| Scanner / Recon | 14 | 0 | 0 | 1 | T1595.002 | - | CAPEC-541 | 913100, 10200, 932239 | 06:10:56 | 06:13:58 |
| Path Traversal / File Inclusion | 12 | 0 | 0 | 1 | T1190 | CWE-22 | CAPEC-126 | 930110, 930120, 930100, 932160 | 06:10:55 | 06:13:57 |
| Automated attack (repeated WAF blocks) | 0 | 0 | 1 | 1 | T1595.002 / T1190 | - | - | fail2ban:ban | 06:14:01 | 06:14:01 |

_Brute Force counts are nginx `limit_req` rejections plus fail2ban bans. All other rows are ModSecurity transactions (one per blocked request). Each one is classified by the attack family with the most matching CRS / Shield Wall rules, and scanner user agents always win. A payload can match several families, e.g. `?page=/etc/passwd` trips CRS LFI rule 930120 and RCE rules 932160/932236. Every matched family is kept in the event's `attack_families` field in the central log._

## Top triggered rules

| Rule ID | Description | Hits |
|---|---|---:|
| 942100 | SQL Injection Attack Detected via libinjection | 104 |
| 942400 | SQL Injection Attack | 58 |
| 942410 | SQL Injection Attack | 52 |
| 942150 | SQL Injection Attack: SQL function name detected | 45 |
| 942520 | Detects basic SQL authentication bypass attempts 4.0/4 | 43 |
| 942180 | Detects basic SQL authentication bypass attempts 1/3 | 41 |
| 942430 | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) | 38 |
| 942130 | SQL Injection Attack: SQL Boolean-based attack detected | 37 |
| 932240 | Remote Command Execution: Unix Command Injection evasion attempt detected | 37 |
| 942340 | Detects basic SQL authentication bypass attempts 3/3 | 37 |
| 942300 | Detects MySQL comments, conditions and ch(a)r injections | 36 |
| 942310 | Detects chained SQL injection attempts 2/2 | 36 |
| 942440 | SQL Comment Sequence Detected | 34 |
| 942380 | SQL Injection Attack | 34 |
| 942200 | Detects MySQL comment-/space-obfuscated injections and backtick termination | 32 |

## Sources

| Client IP | Requests | Allowed | Blocked 403 | Rate-limited 429 | Banned |
|---|---:|---:|---:|---:|---|
| 10.66.10.66 | 381 | 113 | 171 | 97 | yes |
| 10.66.10.20 | 49 | 49 | 0 | 0 | no |

## Sample blocked requests

| Time (UTC) | Source | Attack type | Request | Rules |
|---|---|---|---|---|
| 06:10:55 | 10.66.10.66 | SQL Injection | `GET /vulnerabilities/sqli/?id=1%20AND%20SLEEP(5)&Submit=Submit` | 942100 942160 942150 942300 942410 |
| 06:10:55 | 10.66.10.66 | SQL Injection | `GET /vulnerabilities/sqli/?id=1'%20AND%201=1--%20-&Submit=Submit` | 942100 942130 942180 942330 942400 942440 |
| 06:13:36 | 10.66.10.66 | Flood / Rate Limit | `GET /favicon.ico` | zone=general excess=40.560 |
| 06:13:36 | 10.66.10.66 | Flood / Rate Limit | `GET /favicon.ico` | zone=general excess=40.460 |
| 06:10:55 | 10.66.10.66 | Command Injection | `GET /vulnerabilities/fi/?page=....//....//....//....//etc/passwd&Submit...` | 930120 932160 932236 |
| 06:10:56 | 10.66.10.66 | Command Injection | `POST /vulnerabilities/exec/` | 10100 |
| 06:10:58 | 10.66.10.66 | Brute Force / Rate Limit | `POST /login.php` | zone=login excess=3.683 |
| 06:10:58 | 10.66.10.66 | Brute Force / Rate Limit | `POST /login.php` | zone=login excess=3.674 |
| 06:10:55 | 10.66.10.66 | Cross-Site Scripting | `GET /vulnerabilities/xss_r/?name=%3CScRiPt%3Ealert(1)%3C%2FsCrIpT%3E&Su...` | 941100 941110 941160 941390 941320 942131 |
| 06:10:55 | 10.66.10.66 | Cross-Site Scripting | `GET /vulnerabilities/xss_r/?name=%3Cimg%20src%3Dx%20onerror%3Dprompt(1)...` | 941100 941120 941160 941390 941150 941320 |
| 06:10:56 | 10.66.10.66 | Scanner / Recon | `GET /index.php` | 913100 10200 |
| 06:10:56 | 10.66.10.66 | Scanner / Recon | `GET /index.php` | 913100 10200 |
| 06:10:55 | 10.66.10.66 | Path Traversal / File Inclusion | `GET /vulnerabilities/fi/?page=..%5c..%5c..%5c..%5cetc%5cpasswd&Submit=S...` | 930100 930110 930110 930120 932240 |
| 06:10:55 | 10.66.10.66 | Path Traversal / File Inclusion | `GET /vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2...` | 930100 930110 930110 930120 932160 932236 |

## False positives against benign traffic

None. No request from the benign client was blocked by the WAF.

## Timeline (requests per minute)

| Minute (UTC) | Allowed | Blocked / rejected |
|---|---:|---:|
| 06:10 | 65 | 69 |
| 06:11 | 1 | 0 |
| 06:12 | 11 | 1 |
| 06:13 | 83 | 103 |
| 06:14 | 2 | 95 |
