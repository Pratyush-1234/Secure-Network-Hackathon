# Live demo guide: DVWA before vs after Shield Wall

Use **two browser windows side by side**, each showing the same DVWA:

| | Window A: BEFORE (no protection) | Window B: AFTER (Shield Wall) |
|---|---|---|
| URL | **http://127.0.0.1:8081** | **https://localhost:9443** |
| Path | browser → DVWA directly | browser → TLS → nginx rate limit → ModSecurity + CRS + virtual patches → DVWA |
| Login | admin / password | admin / password |

Use `127.0.0.1` for A and `localhost` for B. They are different host names, so the browser keeps their cookies apart and you can stay logged in to both.

## 0. Preparation (before the judges arrive)

```bash
cd /home/pratyush/Documents/SN_hack/shield-wall
make up               # if the lab is not already running
make reset            # clean logs, bans, fresh DB
make unprotected-up   # opens the BEFORE door at http://127.0.0.1:8081
```

- Log in to both windows as `admin` / `password`.
- Optional: import `certs/ca.crt` into the browser (Settings → Certificates → Authorities) so window B shows a padlock without a warning.
- Have a terminal ready in the project folder.

## 1. Opening line (20 s)

> "DVWA is our legacy app. It's full of holes and can't be patched this week. Window A is the app exposed as-is. Window B is the same app, same code, same database, behind our edge: nginx with ModSecurity and the OWASP Core Rule Set, TLS, rate limiting, automatic banning and central logging."

## 2. Attacks side by side (3 min)

Do each step in window A first (it works), then the same step in window B (it's blocked).

| # | DVWA page (left menu) | What to type | A: BEFORE | B: AFTER |
|---|---|---|---|---|
| 1 | **SQL Injection** | User ID: `1' OR '1'='1` → Submit | Lists **all 5 users** | **403 Forbidden** |
| 2 | **SQL Injection** | `1' UNION SELECT user,password FROM users-- -` (keep the space after `--`) | Shows usernames + **password hashes** (`5f4dcc3b…` = "password") | 403 |
| 3 | **XSS (Reflected)** | `<script>alert(document.cookie)</script>` | **Pop-up with the session cookie** | 403 |
| 4 | **File Inclusion** | Change the URL to `…/vulnerabilities/fi/?page=../../../../../../etc/passwd` | Page shows **/etc/passwd** (`root:x:0:0…`) | 403 |
| 5 | **Command Injection** | `127.0.0.1; cat /etc/passwd`, then `127.0.0.1 \| id` | Shows **/etc/passwd** / `uid=33(www-data)`: the server runs our command | 403 |
| 6 | **Command Injection** | Normal use: `127.0.0.1` | ping output | **ping output too**: legitimate use still works |
| 7 | Address bar | `/setup.php` | **Database reset page open to anyone** | **404**: admin page hidden at the edge (on purpose) |

Point out after step 6: **"Good traffic still works. That's the false-positive side, and we measured it: 41/41 normal requests allowed."**

### Step 7: why does setup.php give 404?

> "`setup.php` can wipe and re-create the whole database. The public never needs it, so the edge answers 404 (`waf/nginx/default.conf.template`). `phpinfo.php`, `config/`, `.git` and `.env` are hidden the same way. Admins reset the DB from the internal network only (`make setup`)."

So the 404 is a feature, not a bug. If a judge asks to use setup.php, show it in window A, or run `make setup`.

## 3. Proving why a request was blocked (30 s)

In window B, after a 403, open **DevTools → Network** and click the blocked request. Copy the **`x-request-id`** response header, then in the terminal run:

```bash
docker compose exec waf grep <paste-request-id> /var/log/shieldwall/modsec/audit.json \
  | jq -r '.transaction.messages[] | "\(.details.ruleId)  \(.message)"'
```

This shows the exact CRS rules that fired, e.g. `942100 SQL Injection Attack Detected via libinjection`.

## 4. Other visible differences (30 s)

Open DevTools → Application → Cookies:

| | A: BEFORE | B: AFTER |
|---|---|---|
| Transport | plain HTTP (password visible on the wire) | TLS 1.3 (TLS 1.0/1.1 refused) |
| `PHPSESSID` cookie | no Secure / HttpOnly / SameSite | **Secure, HttpOnly, SameSite=Lax** (added at the edge) |
| Security headers | none | HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy |

HttpOnly is why the XSS cookie theft from step 3 would not work in B even if a payload slipped through.

## 5. Brute force: use the terminal, not the browser (1 min)

```bash
make baseline        # full "before" script: brute force finds admin/password at attempt 12
make unban; make attack   # "after": 429 after the burst, correct password never reaches the app, IP banned
```

When the `make attack` output reaches the brute-force section, point out:
- **HTTP 429** on every attempt after the first two or three
- *"correct password never reached the app"*
- **`BANNED – connection refused`**

Then run `make status` to show the banned IP 10.66.10.66.

**Don't brute-force the login from your own browser.** Your browser's traffic comes from the Docker gateway (10.66.10.1), so it would get banned too, and window B would stop loading for 10 minutes. If it happens, run `make unban`.

## 6. Scoreboard and dashboard (1 min)

```bash
make test                       # every acceptance check prints PASS (takes about 1 min)
xdg-open reports/dashboard.html # alerts by attack type, top rules, sources, false positives = 0
```

Mention the tuning story in one sentence:

> "At paranoia level 2 the guestbook flagged normal English like *I'll* and *--* as SQL injection. We fixed it for that one field only. We also found a real bypass, a newline before the command, and closed it with a virtual-patch rule."

## 7. After the demo

```bash
make unprotected-down   # close the BEFORE door again
```

## Quick reference card

```
BEFORE  http://127.0.0.1:8081        AFTER  https://localhost:9443      login admin / password
SQLi    1' OR '1'='1                 XSS    <script>alert(document.cookie)</script>
LFI     ?page=../../../../../../etc/passwd
CMDi    127.0.0.1; cat /etc/passwd   127.0.0.1 | id
setup   /setup.php  → 200 before, 404 after (hidden on purpose)
make baseline | make unban | make attack | make test | make status | make unban
```
