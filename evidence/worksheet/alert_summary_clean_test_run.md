# Shield Wall: WAF & proxy alert summary

_Generated 2026-11-21 06:11:03 UTC from `/work/logs/central/events.ndjson` (205 centralized events: nginx access + error, ModSecurity audit, fail2ban)._

## Totals

| Metric | Value |
|---|---:|
| Requests reaching the edge proxy | 135 |
| Allowed to the application | 66 |
| Blocked by ModSecurity / CRS (HTTP 403) | 59 |
| Rejected by login rate limit (HTTP 429) | 10 |
| Sensitive paths hidden at the edge (HTTP 404) | 0 |
| WAF audit-log blocked transactions | 59 |
| Response-leakage detections (detect-only) | 0 |
| Automatic IP bans (fail2ban) | 1 |
| Banned source IPs | 10.66.10.66 |

## Alerts by attack type

| Attack type | Blocked | Detect-only | IP bans | Sources | ATT&CK | CWE | CAPEC | Top rules | First seen | Last seen |
|---|---:|---:|---:|---:|---|---|---|---|---|---|
| SQL Injection | 14 | 0 | 0 | 1 | T1190 | CWE-89 | CAPEC-66 | 942100, 942180, 942440, 942130 | 06:10:55 | 06:10:57 |
| Command Injection | 13 | 0 | 0 | 1 | T1190 | CWE-78 | CAPEC-88 | 932236, 932160, 930120, 10100 | 06:10:55 | 06:10:57 |
| Cross-Site Scripting | 11 | 0 | 0 | 1 | T1190 | CWE-79 | CAPEC-63 | 941100, 941390, 941160, 941320 | 06:10:55 | 06:10:57 |
| Scanner / Recon | 11 | 0 | 0 | 1 | T1595.002 | - | CAPEC-541 | 913100, 10200, 932239 | 06:10:56 | 06:10:58 |
| Path Traversal / File Inclusion | 10 | 0 | 0 | 1 | T1190 | CWE-22 | CAPEC-126 | 930110, 930120, 930100, 932160 | 06:10:55 | 06:10:57 |
| Brute Force / Rate Limit | 10 | 0 | 1 | 1 | T1110.001 | CWE-307 | CAPEC-49 | nginx:limit_req, fail2ban:ban | 06:10:58 | 06:10:59 |

_Brute Force counts are nginx `limit_req` rejections plus fail2ban bans. All other rows are ModSecurity transactions (one per blocked request). Each one is classified by the attack family with the most matching CRS / Shield Wall rules, and scanner user agents always win. A payload can match several families, e.g. `?page=/etc/passwd` trips CRS LFI rule 930120 and RCE rules 932160/932236. Every matched family is kept in the event's `attack_families` field in the central log._

## Top triggered rules

| Rule ID | Description | Hits |
|---|---|---:|
| 942100 | SQL Injection Attack Detected via libinjection | 13 |
| 930120 | OS File Access Attempt | 12 |
| 932236 | Remote Command Execution: Unix Command Injection (command without evasion) | 12 |
| 930110 | Path Traversal Attack (/../) or (/.../) | 11 |
| 913100 | Found User-Agent associated with security scanner | 11 |
| 10200 | Shield Wall: attack tool / vulnerability scanner user agent | 11 |
| 941100 | XSS Attack Detected via libinjection | 10 |
| 941390 | Javascript method detected | 10 |
| 932160 | Remote Command Execution: Unix Shell Code Found | 10 |
| 941160 | NoScript XSS InjectionChecker: HTML Injection | 9 |
| 942180 | Detects basic SQL authentication bypass attempts 1/3 | 7 |
| 941320 | Possible XSS Attack Detected - HTML Tag Handler | 7 |
| 942440 | SQL Comment Sequence Detected | 6 |
| 942370 | Detects classic SQL injection probings 2/3 | 6 |
| 942520 | Detects basic SQL authentication bypass attempts 4.0/4 | 6 |

## Sources

| Client IP | Requests | Allowed | Blocked 403 | Rate-limited 429 | Banned |
|---|---:|---:|---:|---:|---|
| 10.66.10.66 | 91 | 22 | 59 | 10 | yes |
| 10.66.10.20 | 44 | 44 | 0 | 0 | no |

## Sample blocked requests

| Time (UTC) | Source | Attack type | Request | Rules |
|---|---|---|---|---|
| 06:10:55 | 10.66.10.66 | SQL Injection | `GET /vulnerabilities/sqli/?id=1%20AND%20SLEEP(5)&Submit=Submit` | 942100 942160 942150 942300 942410 |
| 06:10:55 | 10.66.10.66 | SQL Injection | `GET /vulnerabilities/sqli/?id=1'%20AND%201=1--%20-&Submit=Submit` | 942100 942130 942180 942330 942400 942440 |
| 06:10:55 | 10.66.10.66 | Command Injection | `GET /vulnerabilities/fi/?page=....//....//....//....//etc/passwd&Submit...` | 930120 932160 932236 |
| 06:10:56 | 10.66.10.66 | Command Injection | `POST /vulnerabilities/exec/` | 10100 |
| 06:10:55 | 10.66.10.66 | Cross-Site Scripting | `GET /vulnerabilities/xss_r/?name=%3CScRiPt%3Ealert(1)%3C%2FsCrIpT%3E&Su...` | 941100 941110 941160 941390 941320 942131 |
| 06:10:55 | 10.66.10.66 | Cross-Site Scripting | `GET /vulnerabilities/xss_r/?name=%3Cimg%20src%3Dx%20onerror%3Dprompt(1)...` | 941100 941120 941160 941390 941150 941320 |
| 06:10:56 | 10.66.10.66 | Scanner / Recon | `GET /index.php` | 913100 10200 |
| 06:10:56 | 10.66.10.66 | Scanner / Recon | `GET /index.php` | 913100 10200 |
| 06:10:55 | 10.66.10.66 | Path Traversal / File Inclusion | `GET /vulnerabilities/fi/?page=..%5c..%5c..%5c..%5cetc%5cpasswd&Submit=S...` | 930100 930110 930110 930120 932240 |
| 06:10:55 | 10.66.10.66 | Path Traversal / File Inclusion | `GET /vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2...` | 930100 930110 930110 930120 932160 932236 |
| 06:10:58 | 10.66.10.66 | Brute Force / Rate Limit | `POST /login.php` | zone=login excess=3.683 |
| 06:10:58 | 10.66.10.66 | Brute Force / Rate Limit | `POST /login.php` | zone=login excess=3.674 |

## False positives against benign traffic

None. No request from the benign client was blocked by the WAF.

## Timeline (requests per minute)

| Minute (UTC) | Allowed | Blocked / rejected |
|---|---:|---:|
| 06:10 | 65 | 69 |
| 06:11 | 1 | 0 |
