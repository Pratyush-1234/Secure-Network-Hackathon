# PS6 Shield Wall: implementation-specific answers

These answers are based on the running stack in `shield-wall/`, not on generic definitions.

- **Line numbers** refer to the files as they are in the repository.
- **Measured values** come from the clean run on 2026-11-21: `make reset → make baseline → make test → make ratelimit → make attack-tools`.
- **Raw command output** cited below is saved in `evidence/worksheet/`:

| File | Contents |
|---|---|
| `runtime_containers.txt` | `docker compose ps`, port mappings, networks, restart policies |
| `runtime_waf_config.txt` | Rendered nginx / ModSecurity / CRS configuration inside the running WAF |
| `request_traces.txt` | One request per attack class, traced client → nginx → ModSecurity → central log |
| `bruteforce_trace.txt` | Burst → access log → error log → fail2ban → iptables → central log |
| `metrics_and_trace.txt` | Counts from the CSVs, cross-checked against raw logs; one summary row traced to raw events |
| `virtual_patch_test.txt` | Rule 10100 against the bypass payload and against legitimate input |
| `failure_modes.txt` | App container stopped / proxy container stopped |
| `processing_order_test.txt` | Measured order of ModSecurity vs `limit_req` vs location `return` |
| `alert_summary_clean_test_run.md` | Alert summary of the clean acceptance run |

**Implementation assumptions (all verified):**
- Docker-based vulnerable app: **DVWA**.
- **nginx** reverse proxy with **ModSecurity v3.0.17 + OWASP CRS 4.30.0**.
- TLS terminated at nginx.
- Attack and benign replay scripts.
- Centralized logs via **Vector**, plus an alert summary script.

**Additions beyond the assumptions:**
- fail2ban auto-blocking.
- Virtual-patch rules.
- A dashboard.

---

## 1. Your exact deployment and request path

**1.1 Which containers/services are defined in docker-compose.yml, and what is each responsible for?**

| Service (compose line) | Image | Responsibility |
|---|---|---|
| `db` (26) | `mariadb:10.11` | DVWA's MySQL-compatible database. Backend network only. |
| `dvwa` (43) | `ghcr.io/digininja/dvwa:latest@sha256:61167ec2…` | The vulnerable legacy app (PHP 8.5 / Apache), `DEFAULT_SECURITY_LEVEL: low`. Backend network only. |
| `waf` (64) | `owasp/modsecurity-crs:4.30.0-nginx-202611160811` | **The public entry point.** nginx 1.30.6 reverse proxy: TLS termination, ModSecurity + CRS, rate limiting, security headers. On both networks. |
| `fail2ban` (123) | `crazymax/fail2ban:1.1.1` | Automatic IP banning. Shares the WAF's network namespace (`network_mode: "service:waf"`, line 125), so its iptables rules only filter traffic arriving at the WAF. |
| `vector` (141) | `timberio/vector:0.62.0-alpine` | Log centralization: tails the nginx access/error logs, the ModSecurity audit log and the fail2ban log, and writes `logs/central/events.ndjson`. `network_mode: "none"` (line 152). |
| `attacker` (156) | `shieldwall-tools:1.0` (built from `tools/Dockerfile`) | Runs the attack replay, evasion variants and real tools (sqlmap, nikto, ffuf) from fixed IP 10.66.10.66. |
| `client` (162) | same | Runs the benign replay from fixed IP 10.66.10.20, so it never shares a rate-limit bucket or ban with the attacker. |
| `attacker-direct` (169, profile `baseline`) | same | Only for the "before" run and the DB reset. Sits on the backend network, with no WAF in the path. |
| `dvwa-direct` (178, profile `unprotected`) | same | **Demo only.** A plain TCP forwarder (`scripts/tcp_forward.py`) to DVWA on 127.0.0.1:8081, for the browser before/after demo. Off by default. |

**1.2 Which service is the public entry point, and how can you verify that from the port mappings in Compose?**

`waf`. It is the only service with a `ports:` section among the always-on services (lines 103–105):
```yaml
      - "127.0.0.1:${HTTP_PORT:-9080}:${HTTP_PORT:-9080}"
      - "127.0.0.1:${HTTPS_PORT:-9443}:${HTTPS_PORT:-9443}"
```
The `docker compose ps` output (`runtime_containers.txt`) shows ports only on `waf`:
`127.0.0.1:9080->9080/tcp, 8080/tcp, 127.0.0.1:9443->9443/tcp`.
The `8080/tcp` is an image `EXPOSE` with no host mapping. `db` and `dvwa` show only `3306/tcp` and `80/tcp`, with no `->`, so they are not published.

**1.3 What exact path does a request take from the host/browser to the vulnerable application?**

The order of steps 3–6 was measured (`processing_order_test.txt`), not assumed.

1. **Browser / curl on the host** → `https://localhost:9443`. A lab container instead uses `https://shieldwall.local:9443`, resolved by `extra_hosts` to 10.66.10.10.
2. **Docker port publish** 127.0.0.1:9443 → `waf` container 10.66.10.10:9443, on the `frontend` network.
   - Inside the WAF's network namespace, the **fail2ban iptables chain** `f2b-shieldwall-*` (INPUT) runs first. A banned IP is rejected here, before nginx.
3. **nginx TLS termination**: `listen 9443 ssl` (`default.conf.template:72`), TLS 1.2/1.3, HTTP/2 decoded.
4. **ModSecurity phase 1** (request headers): e.g. scanner User-Agent rules 913100 / 10200.
   - Measured: on `/setup.php` with a sqlmap UA the response is **403**, so phase 1 runs before the location `return`.
5. **Location routing**: hidden paths `location ~* ^/(setup\.php|phpinfo\.php|…)` return **404** (line 119).
   - Measured: `/setup.php?x=' OR 1=1--` gives **404**, so phase-2 rules never see it.
6. **ModSecurity phase 2** (arguments and body): CRS rules add anomaly scores, then **949110** denies at inbound score ≥ 5. The Shield Wall virtual patches 10100/10110/10120 run after CRS.
7. **nginx rate limiting** (`limit_req` / `limit_conn`).
   - Measured: with the login bucket already empty, a scanner-UA POST and a SQLi POST still get **403**, and only a clean POST gets **429**. So `limit_req` runs after ModSecurity.
8. **Proxy**: `proxy_pass http://dvwa_backend` (`shieldwall_proxy.conf:16`) over the `backend` network, HTTP/1.1 with keepalive, to `dvwa` 10.66.20.20:80 (Apache + PHP).
9. **DVWA** → `db` 10.66.20.30:3306.
10. **Response path**:
    - ModSecurity phases 3/4: response rules. On nginx these are effectively detect-only (see 5.7).
    - nginx adds HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy and `X-Request-ID`.
    - `proxy_cookie_flags` adds Secure, HttpOnly and SameSite=Lax to the app's cookies.
11. **Logging**: nginx writes `access.json` and `error.log`, and ModSecurity writes `audit.json` (host `logs/`). Vector merges these into `logs/central/events.ndjson`.

**1.4 Which host port is published, which container port does it map to, and why may those two numbers differ?**

- `127.0.0.1:9443 → 9443/tcp` (HTTPS) and `127.0.0.1:9080 → 9080/tcp` (HTTP redirect).
- They *may* differ because Docker DNATs `host_ip:host_port` to `container_ip:container_port`. These are separate sockets in separate network namespaces, e.g. `9443:443` would be valid.
- We deliberately keep them **equal**, set from `.env` (`HTTP_PORT=9080`, `HTTPS_PORT=9443`). The HTTP→HTTPS redirect (`return 301 https://$host:${PUBLIC_HTTPS_PORT}$request_uri`, line 64) then points to a port that is correct from both the host and the lab network.
- We used 9080/9443 because host port 8080 was already taken by another project on this machine.
- The ports are bound to **127.0.0.1 only**, so nothing on the venue LAN can reach the lab.

**1.5 Is the vulnerable app's port published to the host? Show the Compose line that proves it. If it is exposed, what bypass does that create?**

**No.**
- The `dvwa` service (lines 43–61) has **no `ports:` key**, and `docker port shieldwall-dvwa-1` prints nothing.
- It sits only on `backend`, which is `internal: true` (line 202): no host route and no outbound route.
- Tested: from the attacker container, `curl http://10.66.20.20/` times out (curl exit 28).

**Exception:** the demo-only `dvwa-direct` service publishes `"127.0.0.1:${UNPROTECTED_PORT:-8081}:8081"` (line 185) when `make unprotected-up` is run.
- That *is* a full WAF bypass: no TLS, no ModSecurity, no rate limit, no logs. It is the intended "before" view.
- It is closed with `make unprotected-down`. Both states are captured in `runtime_containers.txt`.

**1.6 Which Docker network connects the proxy/WAF to the app? Can the app be reached from outside that network?**

`shieldwall_backend`, 10.66.20.0/24, `internal=true` (verified with `docker network inspect`).
- `waf` is attached as 10.66.20.10, `dvwa` as 10.66.20.20 and `db` as 10.66.20.30.
- The app cannot be reached from the frontend network or the host. `internal: true` gives the bridge no gateway or NAT, and the attacker test above timed out.
- Only containers attached to `backend` can reach it: `waf`, `db`, and the profile-gated `attacker-direct` / `dvwa-direct`.

**1.7 What happens to a request if the proxy container stops? If the application container stops?**

Both were tested (`failure_modes.txt`):

- **Proxy stopped:** the host gets **connection refused** (curl exit 7), because the published port disappears with the container. The attacker container gets a **timeout** (exit 28), because 10.66.10.10 no longer answers.
  - Nothing reaches the app, because there is no other path to it. The design fails closed.
  - `attack.sh` aborts with `ABORT: … is not reachable (timeout …)` instead of counting the requests as blocked.
- **App stopped:** nginx waits `proxy_connect_timeout 5s` (`shieldwall_proxy.conf:13`), then returns **HTTP 504** (measured: `HTTP 504 after 5.01 s`). The error log shows `upstream timed out (110: Connection timed out) while connecting to upstream … upstream: "http://10.66.20.20:80/login.php"`.
  - CRS also logged a phase-4 event on the 5xx page, but it could not change the response ("header already sent").
  - After `docker compose start dvwa` the next request returned 200. nginx resolved `dvwa` at startup, and the static IP 10.66.20.20 keeps that valid.

**1.8 How do you confirm the running containers and their actual port mappings, rather than relying only on the YAML?**

```bash
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
docker port shieldwall-waf-1            # 9080/tcp -> 127.0.0.1:9080, 9443/tcp -> 127.0.0.1:9443
docker port shieldwall-dvwa-1           # (empty)
docker inspect shieldwall-dvwa-1 --format '{{json .NetworkSettings.Networks}}'
docker network inspect shieldwall_backend --format 'internal={{.Internal}}'
ss -ltn | grep -E ':(9080|9443|8081) '  # host listeners
```
The output of all of these is in `runtime_containers.txt`.

---

## 2. Docker Compose details you actually configured

**2.1 For each service, which image/tag did you select, and why is it preferable to an unpinned `latest`?**

| Service | Image reference | Notes |
|---|---|---|
| waf | `owasp/modsecurity-crs:4.30.0-nginx-202611160811` | Fully pinned: CRS version + build date. Floating `nginx` / `4-nginx` tags would silently change the rule set, and with it our block/allow results. |
| dvwa | `ghcr.io/digininja/dvwa:latest@sha256:61167ec2…` | Upstream publishes only `latest`, so it is **pinned by digest** to the exact build we tested (2026-11-17, PHP 8.5). The digest equals the image ID of the container that passed all tests. |
| db | `mariadb:10.11` | Pinned to the LTS minor version (receives patch updates). Its digest is recorded in our notes for a fully frozen build. |
| fail2ban | `crazymax/fail2ban:1.1.1` | Exact version. |
| vector | `timberio/vector:0.62.0-alpine` | Exact version. VRL syntax differs between versions, so this matters. |
| tools | `python:3.13-alpine` base; `sqlmap==1.10.11` pinned via pip | Built locally as `shieldwall-tools:1.0`. |

Why not `latest`: test results must be reproducible. A new CRS release changes rule IDs and scoring, and a new DVWA build changes forms and pages, either of which can turn a PASS into a FAIL without any change on our side. A digest or exact tag makes `make test` reproducible and lets a reviewer verify which code was tested.

**2.2 Which environment variables configure the vulnerable app? Where are they set, and which are secrets?**

`docker-compose.yml` lines 47–49:
- `DB_SERVER: db`: configuration.
- `DEFAULT_SECURITY_LEVEL: low`: configuration. This keeps DVWA fully vulnerable ("cannot be patched this week").

DVWA's other settings use the image defaults (`config/config.inc.php`: `getenv('DB_PASSWORD') ?: 'p@ssw0rd'` and similar). The DB side is set in the `db` service (lines 28–32):
- `MARIADB_DATABASE` and `MARIADB_USER`: configuration.
- **`MARIADB_PASSWORD` and `MARIADB_ROOT_PASSWORD`: secrets.**

These are throw-away lab values written in plain text in Compose. That is acceptable only because the DB is on an internal network with no published port. In production we would use Docker secrets or a git-ignored env file.

The DVWA login `admin/password` is DVWA's built-in default. The TLS private key is also a secret: it is mounted read-only and excluded from `make zip` and git (`.gitignore: certs/*.key`).

**2.3 Which volumes are mounted? For each, give the host path, container path and whether it is read-only.**

All mounts are **bind mounts** (no named volumes).

| Service | Host path | Container path | Mode |
|---|---|---|---|
| waf | `./waf/nginx/default.conf.template` | `/etc/nginx/templates/conf.d/default.conf.template` | ro |
| waf | `./waf/nginx/logging.conf.template` | `/etc/nginx/templates/conf.d/logging.conf.template` | ro |
| waf | `./waf/nginx/shieldwall_proxy.conf` | `/etc/nginx/shieldwall/shieldwall_proxy.conf` | ro |
| waf | `./waf/modsec/setup.conf.template` | `/etc/nginx/templates/modsecurity.d/setup.conf.template` | ro |
| waf | `./waf/modsec/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | `/etc/modsecurity.d/shieldwall/…` | ro |
| waf | `./waf/modsec/SHIELDWALL-CUSTOM-RULES.conf` | `/etc/modsecurity.d/shieldwall/…` | ro |
| waf | `./waf/modsec/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` | `/etc/modsecurity.d/shieldwall/…` | ro |
| waf | `./certs/server.crt`, `./certs/server.key` | `/etc/nginx/certs/` | ro |
| waf | `./logs/nginx` | `/var/log/shieldwall/nginx` | **rw** (nginx writes) |
| waf | `./logs/modsec` | `/var/log/shieldwall/modsec` | **rw** (ModSecurity writes) |
| fail2ban | `./fail2ban` | `/data` (jail.d, filter.d, db/) | rw |
| fail2ban | `./logs/nginx` | `/var/log/shieldwall/nginx` | ro (reads only) |
| fail2ban | `./logs/fail2ban` | `/var/log/fail2ban` | rw |
| vector | `./vector/vector.yaml` | `/etc/vector/vector.yaml` | ro |
| vector | `./logs` | `/logs` | rw (writes `central/`) |
| attacker / client / attacker-direct | `./scripts`, `./logs`, `./certs/ca.crt` | `/work/...` | ro |
| attacker / client / attacker-direct | `./evidence`, `./reports` | `/work/...` | rw |

**2.4 Which `depends_on` entries exist? What do they guarantee, and what do they not guarantee about readiness?**

All of them use `condition: service_healthy`:
- `dvwa → db` (line 50). db's healthcheck is `healthcheck.sh --connect --innodb_initialized`.
- `waf → dvwa` (106). dvwa's healthcheck is `curl -fsS http://localhost/login.php`.
- `fail2ban → waf` (136) and `vector → waf` (149). waf's healthcheck is `curl -fsk https://localhost:9443/healthz`.
- `dvwa-direct → dvwa`.

**Guaranteed:** at `docker compose up`, a service is only started after its dependency's healthcheck has passed. This matters because nginx resolves `dvwa` in `upstream dvwa_backend` at start; if dvwa didn't exist yet, nginx would fail with "host not found in upstream".

**Not guaranteed:**
- Health *after* startup. If dvwa dies later, the waf keeps running and returns 504.
- Restarting a service does not restart its dependents. If `waf` is recreated, `fail2ban` (sharing its namespace) must be recreated too, which is why `make reset` recreates `waf fail2ban vector` together.
- That the DVWA *database* has been initialized. That is a separate step: `make setup`.

**2.5 Which restart policy is configured, and what behaviour does it produce?**

`restart: unless-stopped` for db, dvwa, waf, fail2ban and vector. If the process exits or crashes, Docker restarts it, including after a daemon or host reboot, unless it was explicitly stopped (`docker compose stop`). That is why the stop tests in 1.7 stayed stopped until started.

The traffic generators (attacker, client) have **no** restart policy (`no`), as verified by `docker inspect`.

**2.6 How would you rebuild or recreate only the proxy/WAF service without recreating the vulnerable app?**

```bash
docker compose up -d --no-deps --force-recreate waf fail2ban
```
- `--no-deps` stops Compose from also starting or recreating `dvwa`/`db`.
- fail2ban is included because it lives in the WAF's network namespace.

Which command to use depends on what changed:
- **A ModSecurity rule file changed** in place: `docker compose exec waf nginx -t && docker compose exec waf nginx -s reload` is enough.
- **A `*.template` file changed:** a recreate is needed, because templates are rendered by envsubst only at container start.
- **Gotcha we hit:** an editor that writes a new inode (e.g. `sed -i`) is not seen through a single-file bind mount, so recreate after such edits.

**2.7 Which commands would you use to inspect a container's logs, processes and network attachments?**

```bash
docker compose logs --tail 50 waf
docker compose top waf
docker compose exec waf nginx -T
docker inspect shieldwall-waf-1 --format '{{json .NetworkSettings.Networks}}'
docker compose exec fail2ban iptables -S
docker compose exec fail2ban fail2ban-client status shieldwall-bruteforce
make status
```

---

## 3. Nginx: directives in your configuration

File: `waf/nginx/default.conf.template`, rendered to `/etc/nginx/conf.d/default.conf`; verified with `nginx -T` in `runtime_waf_config.txt`.

**3.1 Which server block listens for HTTP, and which for HTTPS?**

- **HTTP:** the server at lines 52–66, `listen ${PORT} default_server;`, which renders to `listen 9080`. It only serves `/healthz` and `return 301 https://$host:9443$request_uri`.
- **HTTPS:** the server at lines 71–126, `listen ${SSL_PORT} ssl default_server;`, which renders to `listen 9443 ssl`.

**3.2 Which directive sets the hostname/server name for the lab?**

`server_name ${SERVER_NAME};` (lines 54 and 73), with `SERVER_NAME: "shieldwall.local localhost waf"` (compose line 68). The certificate SANs match: `shieldwall.local, localhost, waf, 127.0.0.1, 10.66.10.10`.

**3.3 Which location block forwards requests to the app, and what exact `proxy_pass` value does it use?**

`location / { include …/shieldwall_proxy.conf; }` (line 123), plus `location = /login.php` (105) and `location ^~ /vulnerabilities/brute/` (112). The latter two add rate limits.

All three include `shieldwall_proxy.conf`, whose line 16 is **`proxy_pass http://dvwa_backend;`**. The upstream is defined at lines 44–47: `upstream dvwa_backend { server dvwa:80; keepalive 16; }`.

**3.4 How does nginx preserve or set the Host header and client-IP forwarding headers?**

`shieldwall_proxy.conf` lines 4–11:
```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, not $proxy_add_x_forwarded_for
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Request-ID      $request_id;
```

**3.5 What do Host, X-Real-IP and X-Forwarded-For do here, and which downstream component actually trusts each header?**

- **`Host $host`** passes the client's requested hostname (e.g. `shieldwall.local`) instead of `dvwa_backend`. DVWA/Apache use it for any absolute URLs. DVWA mostly redirects relatively, but the session cookie path and host stay consistent.
- **`X-Real-IP` / `X-Forwarded-For`** carry the real client IP. We *overwrite* rather than append, so a client cannot inject a fake earlier hop.
- **Who trusts them: nobody in this stack.**
  - Apache in DVWA does not load `mod_remoteip` (checked: `apache2ctl -M`), so its access log shows the TCP peer **10.66.20.10** (the WAF) for every proxied request.
  - The WAF itself has **no `real_ip`/`set_real_ip_from`** directives in the active config (`nginx -T` checked), so nginx's `$remote_addr` is always the TCP peer.
  - This matters because rate limits, fail2ban and the logs all key on `$remote_addr`, which a client cannot spoof with a header.
- **`X-Request-ID`** lets app-side logs be correlated with the WAF audit log.

**3.6 Where are request timeouts configured, and what timeout behaviour are you trying to prevent?**

- `proxy_connect_timeout 5s` and `proxy_read_timeout 30s` (`shieldwall_proxy.conf:13–14`).
- `client_body_timeout 10s` and `keepalive_timeout 60s` (from the image's `nginx.conf` via env `CLIENT_BODY_TIMEOUT` / `KEEPALIVE_TIMEOUT`; `nginx -T` lines 16–17).
- `client_max_body_size 1m` (line 93).

They prevent:
1. Workers hanging on a dead upstream (the image default is a 36000 s read timeout). With these values a dead app gives a 504 after 5 s, as measured.
2. Slow-body ("slowloris-style") clients holding connections open.
3. Oversized bodies.

The 30 s read timeout still allows DVWA's `ping -c 4` (~3 s) and our 3-second SLEEP test against the unprotected app.

**3.7 Which access-log and error-log paths are configured? Are they inside the container or mounted on the host?**

- `access_log /var/log/shieldwall/nginx/access.json shieldwall_json;` and `error_log /var/log/shieldwall/nginx/error.log warn;` (`logging.conf.template:20–21`, from env `ACCESSLOG`, `ERRORLOG`, `LOGLEVEL`).
- They are bind-mounted to the host at **`./logs/nginx/`** (compose line 101).
- The image's default `/var/log/nginx/*.log` are symlinks to stdout/stderr, and we don't use them.

**3.8 How does nginx distinguish the app's routes? Does the config forward all paths or only a subset?**

It forwards **all paths except a deny-list**:
- `location = /healthz` is answered by nginx itself.
- `location ~* ^/(setup\.php|phpinfo\.php|\.git|\.env|config/|database/|docs/|tests/)` returns **404** (line 119).
- `/login.php` and `/vulnerabilities/brute/` are forwarded with extra rate limits.
- Everything else goes through `location /`.

There is no per-route allow-list in nginx; per-route positive validation is done in ModSecurity (virtual patches).

**3.9 If a request receives a 502 or 504, which config and upstream health would you inspect first?**

1. **`logs/nginx/error.log`:**
   - `connect() failed (111: Connection refused)` → 502: the app container is up but Apache is not listening.
   - `upstream timed out (110…) while connecting` → 504: the container or IP is gone; this is what we observed.
   - `no live upstreams` → the upstream is marked failed.
2. **`docker compose ps dvwa`**: health status, then `docker compose logs dvwa`.
3. **The `upstream dvwa_backend` block** (`server dvwa:80`): does `dvwa` still resolve to 10.66.20.20? nginx resolves it only at start.
4. **`proxy_connect_timeout` / `proxy_read_timeout`**: a 504 with a long upstream time points to a slow app response, e.g. a SLEEP payload against the unprotected path.
5. **Is `waf` still attached to `shieldwall_backend`?** Check with `docker inspect`.

**3.10 What changes if `proxy_pass` goes from a trailing-slash form to a non-trailing-slash form in your location?**

Our directive is `proxy_pass http://dvwa_backend;`, with **no URI part**, so nginx forwards the original request URI unchanged (`/vulnerabilities/brute/?username=…` stays the same).

If we wrote `proxy_pass http://dvwa_backend/;` (a URI part of `/`), nginx would **replace the matched location prefix with `/`**:
- In `location /` this makes no difference.
- In `location ^~ /vulnerabilities/brute/`, a request to `/vulnerabilities/brute/?Login=…` would reach DVWA as `/?Login=…`, which breaks the page.
- In `location = /login.php` it would forward `/`.

That is why the no-URI form is used in a shared include.

---

## 4. TLS: how it is configured in this lab

**4.1 Where are the certificate and private key mounted, and what paths does nginx reference?**

- Host `./certs/server.crt` → `/etc/nginx/certs/server.crt:ro`, and `./certs/server.key` → `/etc/nginx/certs/server.key:ro` (compose lines 99–100).
- nginx: `ssl_certificate ${SSL_CERT_FILE}; ssl_certificate_key ${SSL_CERT_KEY_FILE};` (lines 75–76), with the env vars set to those paths (compose lines 73–74).

**4.2 Is the certificate self-signed or from a trusted CA, and how does that affect client warnings?**

It is issued by **our own lab CA** (`certs/gen-certs.sh`):
- CA: "Shield Wall Lab Root CA", ECDSA P-256, 825 days.
- Server certificate: ECDSA P-256, 397 days, SANs as in 3.2.

It is not publicly trusted, so a browser warns unless `certs/ca.crt` is imported. Our scripts pass `--cacert /work/certs/ca.crt`, and `openssl s_client -CAfile` reports **`Verification: OK`** (`evidence/tls/tls_checks.txt`). Because it is a CA-signed leaf rather than a bare self-signed certificate, clients can genuinely validate the chain and hostname instead of using `-k`.

**4.3 Which TLS protocol versions are enabled or disabled?**

`ssl_protocols TLSv1.2 TLSv1.3;` (line 77), with ECDHE + AEAD ciphers only (line 78).

Verified two ways:
- `nmap --script ssl-enum-ciphers` lists only TLSv1.2 and TLSv1.3 suites, all graded **A** (`evidence/tls/nmap_ssl_enum_ciphers.txt`).
- `openssl s_client -tls1_1 -cipher DEFAULT:@SECLEVEL=0` (the client *willing* to use TLS 1.1) gets **`tlsv1 alert protocol version … alert number 70`** from the server, and the same for TLS 1.0.

**4.4 At what exact point is TLS decrypted, and why must the WAF inspect traffic after that point?**

TLS is decrypted in the **`waf` container's nginx**, at the `listen 9443 ssl` socket. The HTTP/2 frames are decoded there into an HTTP request, and the ModSecurity connector receives the plaintext request in the same process.

The WAF must inspect after decryption because SQLi, XSS and traversal signatures match on URI, arguments, headers and body. Before decryption these are opaque ciphertext. A network IDS in front of the TLS listener would see nothing.

**4.5 Does nginx → app use HTTP or HTTPS? Why is that acceptable here, and what risk remains?**

**Plain HTTP** (`proxy_pass http://dvwa_backend`, HTTP/1.1). This is acceptable here because:
- The hop crosses only the `internal: true` Docker bridge `shieldwall_backend`.
- That bridge has no host route and no outbound route.
- Its only members are waf, dvwa and db.

**Remaining risk:** any container attached to `backend` could reach DVWA directly, bypassing the WAF, or observe that traffic if it were privileged. In our lab that is only the profile-gated `attacker-direct` and `dvwa-direct`. In production, use upstream TLS (`proxy_ssl_*`, which the image supports via `PROXY_SSL`) or mTLS, and keep the backend network members minimal.

**4.6 Which command/output demonstrates that the HTTPS listener and certificate work?**

```bash
docker compose exec client sh -c 'echo | openssl s_client -connect shieldwall.local:9443 \
   -servername shieldwall.local -CAfile /work/certs/ca.crt -brief'
```
Output: `Protocol version: TLSv1.3 · Ciphersuite: TLS_AES_256_GCM_SHA384 · Peer certificate: CN=shieldwall.local · Signature type: ecdsa_secp256r1_sha256 · Verification: OK`.

The full output, the TLS 1.2 handshake, the TLS 1.0/1.1 refusals, the HTTP 301 redirect and the security headers are in `evidence/tls/tls_checks.txt`. Acceptance check **A1** automates this.

---

## 5. ModSecurity and OWASP CRS: your active settings

**5.1 How is ModSecurity loaded or enabled in the nginx build/image?**

- The dynamic module is loaded in `/etc/nginx/nginx.conf` line 1: `load_module modules/ngx_http_modsecurity_module.so;`.
- It is enabled in `/etc/nginx/conf.d/modsecurity.conf`: `modsecurity on; modsecurity_rules_file /etc/modsecurity.d/setup.conf;`.
- nginx reports at start: `ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 0/863/0)`, libmodsecurity 3.0.17.

**5.2 Which file sets `SecRuleEngine`, and what is its active value in the final tests?**

`/etc/modsecurity.d/modsecurity.conf` line 5: **`SecRuleEngine On`** (blocking, not `DetectionOnly`). It is rendered from env `MODSEC_RULE_ENGINE: "On"` (compose line 79). Verified in the running container (`runtime_waf_config.txt`).

**5.3 Where is the OWASP CRS included, and in what order?**

Our `waf/modsec/setup.conf.template`, rendered to `/etc/modsecurity.d/setup.conf`:
```
6  Include /etc/modsecurity.d/modsecurity.conf                    # engine (SecRuleEngine, audit, body limits)
7  Include /etc/modsecurity.d/modsecurity-override.conf           # empty
9  Include /etc/modsecurity.d/owasp-crs/crs-setup.conf           # CRS setup (PL, thresholds)
10 Include /etc/modsecurity.d/shieldwall/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf   # tuning (1000/1010/1020)
12 Include /etc/modsecurity.d/owasp-crs/rules/*.conf              # CRS rules 901…980
14 Include /etc/modsecurity.d/shieldwall/SHIELDWALL-CUSTOM-RULES.conf                  # virtual patches 10100-10200
15 Include /etc/modsecurity.d/shieldwall/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf   # (empty)
```

**5.4 Which CRS version is used, and how did you establish it rather than assume it?**

**4.30.0**, from four independent sources:
1. Every rule carries `ver:'OWASP_CRS/4.30.0'` (grep of `REQUEST-942-…conf`).
2. `crs-setup.conf` header: `# OWASP CRS ver.4.30.0`, and `setvar:tx.crs_setup_version=4300`.
3. The audit log `producer.components` field: `"OWASP_CRS/4.30.0"`.
4. The image tag `4.30.0-nginx-202611160811`.

**5.5 Where is the CRS setup file, and which paranoia level and thresholds are active?**

`/etc/modsecurity.d/owasp-crs/crs-setup.conf`. The image's entrypoint (`95-configure-rules.sh`) uncomments and sets the values from env. Active lines, from `runtime_waf_config.txt`:
- line 191: `setvar:tx.blocking_paranoia_level=2`
- line 219: `setvar:tx.detection_paranoia_level=2`
- line 341: `setvar:tx.inbound_anomaly_score_threshold=5`
- line 342: `setvar:tx.outbound_anomaly_score_threshold=4`

The source is `.env` `PARANOIA=2` → compose `BLOCKING_PARANOIA: "${PARANOIA:-1}"` and `ANOMALY_INBOUND: "5"`, `ANOMALY_OUTBOUND: "4"`.

**5.6 Are inbound and outbound anomaly thresholds configured separately? What values, and why?**

Yes, separately: **inbound 5** and **outbound 4** (the CRS defaults). We deliberately did not raise them.
- With inbound = 5, a single CRITICAL match (5 points) is enough to block, so no attack is let through to "save" a false positive. False positives were fixed with scoped exclusions instead (see 5.10).
- Outbound 4 = one ERROR-level response match. On nginx outbound blocking is ineffective once headers are sent (see 5.7), so it acts as detection.

**5.7 How does the config decide whether a matching rule merely logs, contributes to a score, or blocks?**

- **CRS rules** use the action `block`, which resolves to `SecDefaultAction "phase:1,pass,log"` / `"phase:2,pass,log"` (`crs-setup.conf` lines 97–98). So a match **logs and adds to the anomaly score** (`tx.inbound_anomaly_score_pl1/pl2 += critical(5) | error(4) | warning(3) | notice(2)`) but **does not stop the request**.
- **The blocking decision** is made by **949110** (`REQUEST-949-BLOCKING-EVALUATION.conf:226`: `phase:2, deny`) when `TX:BLOCKING_INBOUND_ANOMALY_SCORE @ge 5`. Outbound uses **959100** (phase 4, deny, `@ge 4`).
- **Shield Wall custom rules** carry an explicit **`deny,status:403`**, so they are immediate blocks without scoring: 10200 in phase 1; 10100, 10110 and 10120 in phase 2.
- **Exclusion rules 1000/1010/1020** are `pass,nolog` + `ctl:`. They only change what is inspected.
- **Nuance:** phase-4 (response) denies cannot change a response that nginx has already started sending. We observed `[alert] header already sent while sending to client`, and the client got the full page. Response rules are therefore effectively detect-only on nginx.

**5.8 Where are ModSecurity audit logs written, and which format/parts are enabled?**

`SecAuditLog /var/log/shieldwall/modsec/audit.json`, on the host as `./logs/modsec/audit.json`.
- `SecAuditLogFormat JSON` and `SecAuditLogType Serial`: one JSON object per line.
- `SecAuditEngine RelevantOnly` with `SecAuditLogRelevantStatus "^(?:5|4(?!04))"`: only 4xx (except 404) and 5xx transactions are logged.
- `SecAuditLogParts ABIFHZ`:

| Part | Meaning |
|---|---|
| A | Header: time, client IP/port, unique_id |
| B | Request headers |
| I | Request body without files. Empirically libmodsecurity 3 did not emit bodies, and `grep password=` over the audit log returns 0 |
| F | Response headers |
| H | Messages / matched rules |
| Z | End |

Parts C/E (raw request and response bodies) are deliberately excluded, so POSTed passwords are not stored.

**5.9 Which rule IDs appear in the attack test logs? For each blocked category, give the rule IDs and explain the evidence.**

From `request_traces.txt` (audit entries joined to the script's CSV by request ID) and `alert_summary_clean_test_run.md`:

| Category | Rule IDs in the audit log (example request) | Evidence |
|---|---|---|
| SQLi (`1' OR '1'='1`) | 942100 (libinjection `s&sos`), 942130, 942180, 942330, 942370, 942390, 942520, also 932240 → **949110 "Total Score: 40"** | `Matched Data: ' OR '1'='1 found within ARGS:id` |
| XSS reflected (`<script>alert(document.cookie)</script>`) | 941100 (libinjection), 941110, 941160, 941180, 941320, 941390, also 942131 → 949110 (35) | `found within ARGS:name` |
| XSS stored (`<img src=x onerror=alert(1)>`) | 941100, 941120, 941150, 941160, 941320, 941390 → 949110 (30) | `found within ARGS:mtxMessage` (form body) |
| Path traversal (`../../../../../../etc/passwd`) | 930100, 930110 (×2, ARGS and REQUEST_URI_RAW), 930120, also 932160, 932236 → 949110 (35) | `/../ found within ARGS:page` |
| Command injection (`127.0.0.1; cat /etc/passwd`) | 932236 (`; cat`), 932160 (`etc/passwd`), 930120 → 949110 (15) | `found within ARGS:ip` (form body) |
| Command injection, newline bypass (`127.0.0.1%0aid`) | **10100 only** (our virtual patch) | `virtual_patch_test.txt` |
| Scanner UA (sqlmap) | 913100 (CRS, scoring) **+ 10200 (deny)** | `sqlmap found within REQUEST_HEADERS:user-agent` |
| Brute force | No ModSecurity rule: nginx `limit_req` zone `login` (429), then fail2ban | `bruteforce_trace.txt` |

**5.10 Did you disable or exclude any CRS rules? List each exclusion, its scope, and why.**

No CRS rule is disabled globally, and no threshold was raised. File: `waf/modsec/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`. Details and before/after evidence are in `docs/tuning-notes.md`.

| ID | Scope | What it does | Why |
|---|---|---|---|
| **1000** | All requests | `setvar:tx.allowed_methods=GET HEAD POST` | Hardening, not an exclusion. Narrows the CRS default. |
| **1010** | `REQUEST_FILENAME @streq /instructions.php` only | `ctl:ruleRemoveById` = 951230, 951250, 953100, 953110 (response leakage rules) | DVWA's README page quotes MySQL/PHP error strings (`ERROR 1045 (28000)`, `Fatal error:`, `fopen`), giving outbound score 18. This was a false positive on every page view: a fake "blocked" alert that nginx couldn't even enforce. |
| **1020** | `REQUEST_FILENAME @streq /vulnerabilities/xss_s/` **and** only `ARGS:mtxMessage` | `ctl:ruleRemoveTargetById` = 942200, 942440, 932200 | At PL2, normal guestbook prose (`I'll be back at 5 o'clock`, `Can't wait -- see you…; …`) triggered these SQLi/RCE heuristics. All XSS rules (941xxx), libinjection SQLi (942100) and everything else still inspect the field, and the stored-XSS attack is still blocked. |

`RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` is empty.

**5.11 What is the difference between a CRS rule match and the final blocking decision in your actual log entry?**

In the SQLi audit entry (`request_traces.txt`), eight rules match: 942100, 942130, …, each with `severity: 2` (CRITICAL, 5 points). Each match is a *message* only, and none of them stops the request.

The block is the separate message **`949110 "Inbound Anomaly Score Exceeded (Total Score: 40)"`**, the evaluation rule with the `deny` action. Together with `"is_interrupted": true` and `"response": {"http_code": 403}`, this shows the disruptive decision.

The nginx error log shows the same decision as `ModSecurity: Access denied with code 403 (phase 2) … [id "949110"]`. A rule *match* with a total below 5 would appear in the audit log with `is_interrupted:false`, i.e. logged but allowed.

---

## 6. Trace individual requests through your implementation

All traces are in `evidence/worksheet/request_traces.txt` (clean run, 2026-11-21 06:10:57 UTC).

**6.1 Take one SQLi test request: what exact URL, method, headers and payload does it send?**

`scripts/attack.sh` lines 101–103:
- **Method:** `GET`.
- **URL:** `https://shieldwall.local:9443/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit`. The payload `1' OR '1'='1` is URL-encoded with `jq @uri`.
- **Headers:**
  - `Host: shieldwall.local:9443`
  - `User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0` (`UA_BROWSER` in `lib.sh`), deliberately not a scanner UA, so the SQLi rules have to do the blocking
  - `Cookie: PHPSESSID=…; security=low` (from the setup login)
- **Transport:** HTTP/2 over TLS 1.3. **Payload location:** query parameter `id`.

**6.2 Trace that SQLi request through nginx and ModSecurity: what log evidence proves it reached the proxy and was inspected?**

Request ID `c3868088b1bd9efaf29cd72be8f02e30`:
1. **Client CSV** (`evidence/attack_waf.csv`): `403 … BLOCKED, WAF 403 (ModSecurity, request-id c3868088…)`. The ID comes from the `X-Request-ID` response header.
2. **nginx access log:** `{"request_id":"c3868088…","client_ip":"10.66.10.66","method":"GET","uri":"/vulnerabilities/sqli/?id=1%27%20OR…","status":403,"upstream_status":"","tls":"TLSv1.3",…}`. An **empty `upstream_status`** proves it was never forwarded to DVWA.
3. **ModSecurity audit log:** `unique_id: c3868088…` (the same ID, via `modsecurity_transaction_id "$request_id"`, line 12), `is_interrupted: true`, `http_code: 403`, with the rule list from 5.9.
4. **Central log:** `{"source":"waf","action":"blocked_waf","attack_type":"SQL Injection","attack_families":["sqli","rce"],"rule_ids":[…,"949110"]}`.

**6.3 Which rule ID or anomaly score blocked the SQLi request, and what status did the client receive?**

Blocked by **949110** at inbound anomaly score **40** (8 critical matches × 5; threshold 5). The client received **HTTP 403**.

**6.4 Take one XSS test: which part of the request holds the test string, and what evidence shows the WAF blocked it?**

- **Reflected:** query parameter **`name`** (`GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E`). Evidence for request `b181d411…`: 941100 `XSS Attack Detected via libinjection … found within ARGS:name`, then 949110 at score 35, then 403 and an empty upstream status.
- **Stored:** **form body** field `mtxMessage` (POST `/vulnerabilities/xss_s/`, `txtName=guest&mtxMessage=<img src=x onerror=alert(1)>&btnSign=Sign+Guestbook`). Evidence for request `e053d9d5…`: 941120 `Event Handler Vector … within ARGS:mtxMessage`, then 949110 at score 30, then 403.

**6.5 Take one path-traversal test: what path/payload did the script use, and what detection evidence is recorded?**

`GET /vulnerabilities/fi/?page=../../../../../../etc/passwd` (`attack.sh:129–131`). Request `9c7ed5c7…`:
- 930100 and 930110: `/../ found within ARGS:page`, plus a second 930110 hit within `REQUEST_URI_RAW`.
- 930120: `OS File Access Attempt: etc/passwd`.
- 932160 and 932236 also matched.
- 949110 at score 35, then **403**.

The other two variants (`..%2f` encoded, absolute `/etc/passwd`) are in the same CSV, also 403.

**6.6 Take one command-injection test: which parameter holds the payload, and how did the WAF respond?**

Form body parameter **`ip`**: `POST /vulnerabilities/exec/` with `ip=127.0.0.1; cat /etc/passwd&Submit=Submit` (`attack.sh:143–145`). Request `cbed2746…`:
- 932236: `; cat  found within ARGS:ip`.
- 932160 and 930120 also matched.
- 949110 at score 15, then **403**.

The `uri` in the access log is just `/vulnerabilities/exec/`, because the payload is in the body. This is why the audit log's `data` field ("found within ARGS:ip") is needed to see it.

**6.7 How does the scanner User-Agent test differ from the other attacks, and what exact header does the script send?**

It carries **no malicious parameter at all**: it is a normal `GET /index.php`. The only signal is the header, sent with curl `-A` (`attack.sh:157`):
- `User-Agent: sqlmap/1.10.11#stable (https://sqlmap.org)`
- `User-Agent: Mozilla/5.00 (Nikto/2.6.0) (Evasions:None) (Test:000001)`
- `User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`

So it tests reconnaissance detection (T1595.002), not exploit detection.

**6.8 Does the scanner test rely on a specific User-Agent rule, or only on a suspicious signal? Show the log evidence.**

Both fire, but **the block comes from our specific rule**. Request `db72bf1a…` shows:
- `913100 "Found User-Agent associated with security scanner"` (CRS, phase 1, action `block` → *scoring only*, +5)
- `10200 "Shield Wall: attack tool / vulnerability scanner user agent"` (phase 1, **`deny`**)

**There is no 949110 in that entry.** Rule 10200 stopped the request in phase 1, before CRS's phase-2 evaluation ever ran. Without 10200, CRS alone would still block, because 913100's score of 5 meets the threshold at 949110.

Limitation: UA rules are trivially evaded. sqlmap `--random-agent` and nikto 2.6 send real browser UAs, so those tools are caught by their payloads and behaviour (403s, the 429 flood limit, the fail2ban `shieldwall-waf` jail) instead.

**6.9 For each attack test, distinguish the HTTP response seen by the script from the ModSecurity decision in the audit log.**

| Test | Script saw (`attack_waf.csv`) | ModSecurity decision (audit log) |
|---|---|---|
| 3× SQLi, 3× XSS, 3× traversal, 3× cmd-injection | 403 | `is_interrupted:true`, final message 949110 (phase 2 deny) |
| 3× scanner UA | 403 | `is_interrupted:true`, final message 10200 (phase 1 deny), no 949110 |
| Brute attempts 1–2 | 302 to `login.php` (DVWA "Login failed") | No audit entry: not relevant, not a 4xx |
| Brute attempts 3–12 | 429 | **No ModSecurity rule.** Decided by nginx `limit_req` (the access log shows `limit_req:"REJECTED"`). nginx's 429 does create a rule-less audit entry, which Vector drops (`vector.yaml:69`). |
| Post-burst ban check | HTTP 000, curl exit 7 (connection refused) | Nothing: the packet was rejected by iptables before nginx |

The script's status is what the *client* experienced. The audit log tells *which layer and which rule* decided it. A 403 from ModSecurity and a 403 from the application would look identical without it.

**6.10 Can you correlate one test request across proxy and WAF logs? Which fields do you use?**

Yes. Each request gets a single **request ID**:
- nginx's `$request_id`, written to the access log as `request_id`.
- Set as the ModSecurity transaction ID (`modsecurity_transaction_id "$request_id"`, `default.conf.template:12`), so it appears as the audit log's `transaction.unique_id` and as `[unique_id "…"]` in the error-log line.
- Returned to the client in the **`X-Request-ID`** response header (line 90), which the scripts record.
- Forwarded to the app as the `X-Request-ID` request header.
- Kept by Vector as `request_id` in the central log.

Every trace in `request_traces.txt` was produced by grepping this one ID across all four sources. Timestamps line up as well (06:10:57).

---

## 7. Rate limiting and brute-force protection: exact behaviour

**7.1 Which nginx directive defines the rate-limit zone, and what key identifies a client?**

`default.conf.template` lines 26–38:
```nginx
map $request_method $login_limit_key { POST $binary_remote_addr; default ""; }
map $arg_Login     $brute_limit_key { ""   "";                   default $binary_remote_addr; }
limit_req_zone $binary_remote_addr zone=general:10m rate=20r/s;
limit_req_zone $login_limit_key    zone=login:10m   rate=6r/m;
limit_req_zone $brute_limit_key    zone=brute:10m   rate=6r/m;
limit_conn_zone $binary_remote_addr zone=perip:10m;
```
The key is the **client IP** (`$binary_remote_addr`, the TCP peer, not spoofable via headers; see 3.5). The `map`s make the key **empty** for requests that shouldn't count, and nginx does not account empty keys:
- the `login` zone counts only POST requests;
- the `brute` zone counts only requests carrying `?Login=`.

**7.2 What rate and burst values are configured, and what do they mean in your time window?**

| Zone | Rate | Burst | Meaning |
|---|---|---|---|
| `login` | 6r/m | 3, `nodelay` | The leaky bucket refills one slot every **10 s**. Up to 1 + 3 = **4 immediate** password submissions; every further attempt is rejected until slots refill. Sustained maximum: 6 per minute. |
| `brute` | 6r/m | 3, `nodelay` | Same, for DVWA's brute-force exercise page. |
| `general` | 20r/s | 40, `nodelay` | Normal page loads with assets pass; floods are trimmed. |
| `perip` (limit_conn) | — | — | At most 20 simultaneous connections per IP. |

**7.3 Which location block applies the limit? Is it applied to all traffic or only the login endpoint?**

Both, in layers:
- `general` + `perip` at server level (lines 94–95), for all HTTPS traffic.
- `login` only in `location = /login.php` (lines 105–108), which repeats `general`, because a location-level `limit_req` replaces the inherited one.
- `brute` only in `location ^~ /vulnerabilities/brute/` (lines 112–115).

**7.4 What response does nginx return when the limit is exceeded, and how does the test script recognize it?**

**HTTP 429** (`limit_req_status 429; limit_conn_status 429;`, lines 40–41). Each rejection is also logged at error level: `limiting requests, excess: 3.683 by zone "login", client: 10.66.10.66 …`.

The scripts read `curl -w '%{http_code}'`, and `is_blocked()` in `scripts/lib.sh` treats `429` as a block. `attack.sh` labels it `"nginx rate limit 429"`, and `rate_limit_test.sh` counts 429s per test.

**7.5 How does the brute-force replay script generate repeated login attempts (endpoint, method, request body)?**

`attack.sh` lines 179–207: 12 passwords (`123456 password1 letmein qwerty admin welcome monkey dragon iloveyou abc123 111111 password`), **the correct one last**. For each:
1. `GET /login.php` to obtain DVWA's anti-CSRF `user_token`.
2. **`POST /login.php`** with form body `username=admin&password=<pw>&user_token=<token>&Login=Login`.
3. Success = `302` with `Location: index.php`; failure = `302` to `login.php`.

The cookie jar is cleared first (a fresh session, like a tool). Afterwards it probes `GET /login.php` for up to 15 s to confirm the ban.

**7.6 How many login attempts pass before limiting begins? Demonstrate with test output.**

At most **4** with a fresh bucket (1 + burst 3).
- `make ratelimit` T3: `4 reached the app, 6 x 429`.
- In `make attack`, the script's own setup login already used one slot, so **2** passed (`bruteforce_trace.txt`): attempts 1–2 got `302 PASSED`, attempts 3–12 got `429 REJECTED`, and the correct password (attempt 12) **never reached DVWA** (no `upstream_status`).
- 1.4 s later, fail2ban banned the IP.

**7.7 Does the limit count per IP, per route, or by another key? What limitation does that create for users sharing an IP?**

**Per client IP, per zone**: `login` and `brute` are separate buckets, and `general` covers everything.

All users behind one NAT or proxy share one bucket and one ban. In this lab, every request from the host browser arrives from the Docker gateway **10.66.10.1**, so a judge brute-forcing from the browser would also lock out any other host traffic. That is why we use separate attacker and client containers, and why `make unban` exists.

In production, behind a CDN or load balancer, you must restore the real client IP with a *trusted* `real_ip` configuration, or the whole internet becomes "one IP".

**7.8 Is the implementation a rate limiter, a temporary IP blocker, or both? Identify each.**

**Both.**
- **Rate limiter:** nginx `limit_req` / `limit_conn` (7.1–7.3). It throttles individual requests and doesn't remember offenders beyond the bucket.
- **Temporary IP blocker:** **fail2ban** (`fail2ban/jail.d/shieldwall.local`):
  - Jail `shieldwall-bruteforce`: filter `shieldwall-limit-req.conf` matches `limiting requests … by zone "(login|brute)", client: <HOST>` in the nginx error log. `maxretry 5` within `findtime 60` gives `bantime 600` (10 min).
  - Jail `shieldwall-waf`: 100 phase-1/2 ModSecurity denies within 120 s gives a 900 s ban.
  - Action: `iptables-allports` with `REJECT --reject-with icmp-port-unreachable`, inside the WAF's network namespace. Evidence: `-A f2b-shieldwall-bruteforce -s 10.66.10.66/32 -j REJECT …`.

**7.9 How do you reset or clear test state between brute-force runs so results are comparable?**

- **`make unban`**: `fail2ban-client unban --all`, which removes the iptables entries.
- **`make reset`**:
  - Stops waf, fail2ban and vector.
  - Deletes all logs and the fail2ban DB, so bans are not restored.
  - Recreates waf, which **clears the nginx shared-memory buckets**, then fail2ban and vector.
  - Re-initializes the DVWA DB.
- `rate_limit_test.sh` itself starts with `unban --all` + `sleep 12` so the `login` bucket drains (10 s per slot).
- `make test` always begins with `make reset`.

**7.10 How would a distributed brute-force attempt behave against your IP-based limit, and what protection is missing?**

Each source IP gets its own bucket and ban counter. N attacking IPs get ~4N immediate guesses plus 6N per minute, and a slow attacker (≤ 6/min per IP, < 5 rejections per minute) never triggers fail2ban at all. Credential stuffing over a botnet would largely pass.

**Missing:**
- per-**account** lockout or exponential backoff (needs app changes);
- MFA (M1032);
- CAPTCHA after N failures;
- a global or per-username rate limit on `/login.php` (e.g. a `limit_req` key on the POSTed username via njs/Lua, or ModSecurity collections);
- breached-password checks;
- alerting on many failed logins across IPs.

---

## 8. Attack and benign replay scripts: inspect your own code

**8.1 Where is the attack replay script, how many test cases does it contain, and how are they named?**

`scripts/attack.sh` (run via `make attack` in the attacker container). It has **16 scored test cases** in 6 classes:
- 15 single-request tests: SQLi ×3, XSS ×3, PathTraversal ×3, CmdInjection ×3, ScannerUA ×3.
- 1 brute-force test, made of 12 attempts plus an auto-ban check.

Each test is named in the CSV `test` column, e.g. `tautology  1' OR '1'='1`, `UNION dump of password hashes`, `time-based blind SLEEP(3)`, `reflected <script> cookie theft`, `stored <img onerror> guestbook`, `../ sequence to /etc/passwd`, `URL-encoded ..%2f traversal`, `; cat /etc/passwd`, `| id`, `UA: sqlmap/…`, `attempt 7 pw=monkey`, `auto-ban check`.

There is also a companion `scripts/judge_variations.sh` with 44 extra evasion payloads.

**8.2 Show the exact request construction for each attack category. Which tests use query parameters, form bodies, or headers?**

| Category | Construction (attack.sh line) | Carrier |
|---|---|---|
| SQLi | `http GET "${SQLI}?id=$(jq -rn --arg v "$P" '$v\|@uri')&Submit=Submit"` (102, 106, 110) | **query** `id` |
| XSS reflected | `http GET "${XSSR}?name=$(… @uri)"` (116, 120) | **query** `name` |
| XSS stored | `http POST "$XSSS" --data-urlencode "txtName=guest" --data-urlencode "mtxMessage=$P" --data "btnSign=Sign+Guestbook"` (124) | **form body** |
| Traversal | `http GET "${FI}?page=${P}"` (130, 134, 138). Sent raw (`..%2f` is pre-encoded on purpose) | **query** `page` |
| Cmd injection | `http POST "$EXEC" --data-urlencode "ip=$P" --data "Submit=Submit"` (144, 148, 152) | **form body** `ip` |
| Scanner | `UA="$ua" http GET "/index.php"` (157–160) → curl `-A` | **header** `User-Agent` |
| Brute force | `http POST /login.php --data-urlencode username/password/user_token --data Login=Login` (183–207) | **form body** |

All of them go through `http()` in `scripts/lib.sh` (curl with cookie jar, `--cacert`, `--max-time 20`, `--connect-timeout 5`).

**8.3 How does the script record HTTP status, response body snippet and timing?**

`http()` uses `curl -w '%{http_code} %{time_total}'`, stores the body in `$BODY` and the headers in `$HDRS`, and sets `CODE`, `TIME_S`, `LOCATION`, `NET` and `CURL_ERR`. `record()` writes the CSV `timestamp,mode,class,technique,test,method,request,http_code,time_s,verdict,evidence`. The *evidence* column holds:

- **waf mode:** which layer blocked it (`WAF 403 (ModSecurity, request-id …)`, `nginx rate limit 429`, or `connection refused (fail2ban ban): <curl error>`).
- **direct mode:** the **matched body snippet** that proves exploitation (`First name: Hack`, `Surname: 5f4dcc3b…`, `root:x:0:0:`, `uid=33(www-data)`) or the delay (`response delayed 3.005s`).

Full response bodies are not saved in waf mode (they are nginx's 146-byte 403 page). The request ID is the pointer to the full WAF evidence.

**8.4 Does the script follow redirects, and why does that matter when interpreting a blocked request's status?**

**No.** There is no `-L` in `curl_opts`.
- The status recorded is exactly what the edge returned.
- A WAF 403 cannot be masked by a followed redirect.
- A login *success* (`302 → index.php`) is distinguishable from a *failure* (`302 → login.php`) and from a block (`403/429`).

With `-L`, a blocked brute-force attempt and a failed one could both end as "200 login page" and become indistinguishable.

**8.5 How does the script handle connection errors or timeouts, so that failing to reach the proxy isn't counted as a successful block?**

Fixed during this review. `http()` (`lib.sh`) now classifies a non-response (`CODE=000`) by **curl's exit code**:
- `7` → `refused` (TCP connect actively rejected: the fail2ban REJECT rule)
- `28` → `timeout`
- `6` → `dns`
- `35/60` → `tls`
- anything else → `other`

`is_blocked()` returns true **only** for `403`, `429`, or `000 + refused`. A timeout, DNS failure, TLS error or 5xx is recorded as **`FAIL-ERROR`** (or `ERROR-<net>` in `judge_variations.sh`) and counts **against** the run.

Additional safeguards:
1. A **pre-flight** `GET /login.php` aborts the run if the proxy is unreachable: "not reachable (timeout)" or "refuses connections … still banned → make unban". This means a later refusal can only be the ban.
2. **Verified by test:** with the WAF container stopped, `attack.sh` printed `ABORT: … not reachable (timeout: curl: (28) …)` (`failure_modes.txt`).
3. Acceptance check A4 independently confirms the ban via `fail2ban-client status`.

The benign script is conservative the other way: **any** 000 counts as *not allowed*.

**8.6 How are the 20+ benign requests generated, and which endpoints and methods do they exercise?**

`scripts/benign.sh` sends a **fixed list of 41 requests**, through `step` and `login_step`, from the client container:

| Area | Requests |
|---|---|
| Landing and login | GET `/` (→302 login), GET `/login.php`, **POST `/login.php` with the correct credentials (admin/password + CSRF token)** |
| Browsing | GET `/index.php`, `/about.php`, `/instructions.php`, `?doc=readme`, `?doc=changelog`, `/security.php` |
| Search / user lookup | GET `/vulnerabilities/sqli/` + `?id=1..5&Submit=Submit` (5) |
| Name search | GET `/vulnerabilities/xss_r/?name=` with `Alice`, `O'Brien`, `Anne-Marie Smith`, `José García`, `Tom & Jerry`, `Dr. Jane Doe, PhD` (6) |
| Guestbook | GET page + **2 POSTs** with real prose containing `'`, `--`, `;`, `@`, `&`, `/` |
| Ping tool | GET page + POST `ip=127.0.0.1`, POST `ip=localhost` |
| File viewer | GET `?page=include.php`, `file1.php`, `file2.php` |
| Other pages | `/vulnerabilities/brute/` (page) + one correct credential check, `/vulnerabilities/csrf/` |
| Static assets | `main.css`, `dvwaPage.js`, `logo.png`, `favicon.ico`, `robots.txt` |
| Logout and re-login | GET `/logout.php`, POST `/login.php` again, GET `/index.php` |

Methods: GET and POST. Each step also checks **functional correctness**: an expected text, a 302 target, or a Content-Type.

**8.7 Are the benign tests repeatable? Fixed list or random generation?**

**Fixed list**, with no randomness. Only the CSRF tokens and session IDs differ between runs, because DVWA issues them. Results were identical across every run: 41/41 allowed and 41/41 functional (`make test` runs, including the final one). The guestbook accumulates entries across runs, but `make reset` re-initializes the DB.

**8.8 How does the script distinguish "blocked" from "request failed"? Which statuses count as blocked?**

`is_blocked()` (`lib.sh`):

| Observation | Classified as |
|---|---|
| `403` | blocked by the WAF |
| `429` | blocked by the rate limit |
| `000` + curl exit 7 (refused) | blocked by the fail2ban ban |
| `000` + timeout / DNS / TLS / other | **request failed** (`FAIL-ERROR`), not a block |
| `5xx` | **not** a block: an upstream failure |
| `302/200` | reached the app (in waf mode this is `FAIL-ALLOWED`, except the 2 brute attempts inside the burst, labelled `ALLOWED-BURST`) |

**8.9 How do you ensure both scripts target only the local lab URL rather than an arbitrary host?**

Fixed during this review:
1. The default `TARGET` is `https://shieldwall.local:9443`, which `extra_hosts` pins to 10.66.10.10, the WAF.
2. `TARGET` *can* be overridden by env, and the attacker container *does* have outbound internet (frontend is not internal). So **`lib.sh` lines 9–18** check the target's host against an allow-list: `shieldwall.local|waf|dvwa|localhost|127.0.0.1|10.66.10.10|10.66.20.20`. Anything else exits with `REFUSED: TARGET host '…' is not part of the Shield Wall lab` (tested with `TARGET=https://example.com`: exit 2, for both scripts).
3. Every script that sends traffic sources `lib.sh`.
4. `make` targets never pass a target.
5. Host ports bind to 127.0.0.1 only.

**8.10 What output from each script is saved and used in the final results?**

| Script | Saved output | Used for |
|---|---|---|
| `attack.sh --mode direct` | `evidence/attack_direct.csv`, `evidence/baseline_direct_output.txt` | Proof that every attack works without the WAF |
| `attack.sh --mode waf` | `evidence/attack_waf.csv` | A2 (16/16) |
| `attack.sh --mode waf --tools` | `evidence/attack_waf_tools.csv`, `evidence/tools/` | Real-tool results |
| `benign.sh` | `evidence/benign_waf.csv` | A3 (41/41) |
| `judge_variations.sh` | `evidence/judge_variations.csv` | 44/44 |
| `rate_limit_test.sh` | `evidence/rate_limit_test.csv`, `rate_limit_evidence.txt` | 7.x |
| `acceptance_test.sh` | `evidence/acceptance_test_output.txt` | Final scoreboard |
| `alert_summary.py` | `reports/alert_summary.{md,csv,json}`, `reports/dashboard.html` | 10.x |
| `collect_evidence.sh` | `evidence/tls/`, `evidence/fail2ban/`, `evidence/logs/` | TLS and ban proof |

---

## 9. Metrics calculated from your actual run

Source: the clean `make reset` + `make test` run (`metrics_and_trace.txt`).

**9.1 How many attack requests were sent, and how many were blocked under your definition?**

- **Test-case level (the definition we score by):** 16 test cases, **16 blocked**.
- **Request level:** 27 attack requests (15 payload requests + 12 brute-force attempts):
  - 15 → **403** (ModSecurity)
  - 10 → **429** (rate limit)
  - **2 → 302**: the first two wrong-password attempts, inside the burst allowance and allowed by design
- Plus 1 post-burst probe → refused by the ban.
- Plus the evasion set: **44/44 blocked** (all 403).

**9.2 Calculate the attack-block rate. Which response/log evidence is in the numerator?**

| Definition | Rate |
|---|---|
| Test cases | 16/16 = **100%** |
| Malicious payload requests (SQLi/XSS/LFI/RCE/scanner + variations) | (15 + 44)/(15 + 44) = **100%** |
| All 27 attack requests, including the 2 burst attempts | 25/27 = **92.6%** |

The burst definition is stated in `docs/report.md`: the brute-force *attack* is defeated because the correct password never reached the app, but per-IP rate limiting can't refuse the first guesses.

**Numerator evidence:** the client CSV's 403/429 rows. These were cross-checked against the raw logs:
- the nginx access log shows **60** `status:403` from 10.66.10.66 (15 attack + 44 variations + 1 manual virtual-patch test);
- the audit log shows exactly **60** transactions with `is_interrupted:true`;
- the access log shows **10** `status:429` with `limit_req:"REJECTED"`.

**9.3 How many benign requests were sent and allowed? Calculate the benign allow rate.**

41 sent, **41 allowed**, so the allow rate is **100%**; functional correctness is also 41/41. The raw access log for 10.66.10.20 shows only 200 (40) and 302 (4) statuses (the 44 includes token-fetch GETs), and **0** ModSecurity audit entries for that IP.

**9.4 Which benign requests were blocked? List them with the responsible rule or rate limit.**

**None** in the final, tuned configuration.

Before tuning, at PL2, two were blocked (`evidence/tuning/benign_pl2_untuned.csv`):
- #23 guestbook `"Great site, thanks! I'll be back at 5 o'clock."` → **942200**
- #24 `"Can't wait -- see you @ 5pm; …"` → **942440 + 932200**

Both are fixed by exclusion 1020.

**9.5 Do you count connection failures, timeouts, 5xx and 403/429 the same way? Justify the definition.**

No:
- **403** (WAF), **429** (rate limit) and **connection refused after a successful pre-flight** (ban) are *edge decisions*, so they count as **blocked**.
- **Timeouts, DNS/TLS errors and other failures** are counted as **errors**, which *fail* the attack test, because the edge's decision is unknown.
- **5xx** is an upstream failure and not a block.
- For benign traffic, *any* non-response or 403/429 counts as **not allowed**, the strict direction.

The definitions are deliberately asymmetric: neither metric can be inflated by a broken stack.

**9.6 Are your metrics based on HTTP responses, WAF audit logs, or both? Why is relying on only one source misleading?**

**Both.** The scripts measure the client-side responses, and `metrics_and_trace.txt` cross-checks them against the access log, audit log and central log (counts match: 60/60, 10 × 429, 0 benign audit entries).

Relying on one source is misleading:
- **HTTP responses alone** can't tell an app 403 from a WAF 403, or a ban from a dead proxy.
- **Audit logs alone** miss nginx-level decisions (429s, `return 404`, bans). They also **overstate blocks**: we saw phase-4 "403, interrupted" audit entries for responses that were actually delivered intact (FP-1). And `RelevantOnly` logging omits allowed requests entirely, so they can't measure the benign allow rate.

**9.7 Did you run the suite before and after tuning? What changed in the counts and rules?**

Yes (`docs/tuning-notes.md`, `evidence/tuning/`):

| Stage | Benign | Attack | Variations |
|---|---|---|---|
| PL1, untuned | 40/40 HTTP-allowed, but response false positives on `/instructions.php` (951230/951250/953100/953110) | 16/16 | **43/44**: `ip=127.0.0.1%0aid` reached the app |
| PL1 + virtual-patch anchor fix (`^…$` → `\A…\z`) | 40/40 | 16/16 | 44/44 |
| PL2, untuned | **39/41 (95.1%)**: 942200, 942440, 932200 | 16/16 | 44/44 |
| **PL2, tuned (final)**: exclusions 1010 and 1020 | **41/41** | **16/16** | **44/44** |

**9.8 Can your results be reproduced from a clean start? Give the exact commands and order.**

```bash
cd shield-wall
make up          # certs, build tools image, start stack (depends_on healthy), init DVWA DB
make baseline    # BEFORE: attacks direct to DVWA -> 16/16 succeed; then DB reset
make test        # reset -> TLS check -> benign -> variations -> unban -> attack -> summary (6/6 PASS)
make evidence    # TLS / nmap / fail2ban / log evidence
make ratelimit   # dedicated rate-limit test (5/5 PASS)
make unban && make attack-tools && make summary   # optional: real sqlmap/nikto/ffuf
```

Verified from a cold `make down` → `make up`, and again in this review. All checks passed; the counts vary by ±1–2 only in the burst/429 numbers, depending on bucket timing.

---

## 10. Logs and alert summary: exact fields and evidence

**10.1 Which log files hold nginx access events, nginx errors and ModSecurity audit events?**

| Log | Container path | Host path |
|---|---|---|
| nginx access | `/var/log/shieldwall/nginx/access.json` | `logs/nginx/access.json` |
| nginx error (includes `limit_req` rejections and ModSecurity interventions) | `/var/log/shieldwall/nginx/error.log` | `logs/nginx/error.log` |
| ModSecurity audit | `/var/log/shieldwall/modsec/audit.json` | `logs/modsec/audit.json` |
| fail2ban | `/var/log/fail2ban/fail2ban.log` | `logs/fail2ban/fail2ban.log` |
| Central, merged | — | `logs/central/events.ndjson` (Vector) |

**10.2 Which access-log fields identify client IP, method, URI, status, response size and duration?**

From the `log_format shieldwall_json` (`logging.conf.template`):

| Field | nginx variable |
|---|---|
| `client_ip` | `$remote_addr` |
| `method` | `$request_method` |
| `uri` | `$request_uri` (raw, with query) |
| `status` | `$status` |
| `bytes_sent` | `$body_bytes_sent` (response size) |
| `request_time` | `$request_time` (duration, seconds) |
| `request_id` | correlation ID |
| `upstream_status` | empty means it never reached the app |
| `limit_req` | `$limit_req_status`: PASSED / REJECTED |
| `tls` | protocol |
| `user_agent` | |
| `ts` | timestamp |

**10.3 Which audit-log fields identify the matched rule, message, severity, anomaly score and disruptive action?**

All in the JSON:
- `transaction.messages[].details.ruleId`: the matched rule.
- `transaction.messages[].message`: the description.
- `…details.severity`: syslog scale; `2` = CRITICAL (5 points), `3` = ERROR (4).
- `…details.data`: `Matched Data: … found within ARGS:id`.
- `…details.tags`: `attack-sqli`, `capec/…`, `paranoia-level/1`.
- **Anomaly score:** the 949110 / 959100 message text, e.g. `"Inbound Anomaly Score Exceeded (Total Score: 40)"`. The per-variable TX scores are not logged separately.
- **Disruptive action:** `transaction.is_interrupted: true` + `transaction.response.http_code: 403`. The error-log twin reads `Access denied with code 403 (phase 2)`.

**10.4 Are logs persisted through bind mounts or Docker volumes? What survives a container recreate?**

**Bind mounts** to `./logs/{nginx,modsec,fail2ban,central}`. Everything survives a container restart or recreate. Only `make reset` and `make clean` delete them on purpose.

Caveat: Vector's file-position checkpoints live in the container (`data_dir: /var/lib/vector`). If you **recreate** Vector *without* clearing `logs/central`, it re-reads the source files from the beginning and writes duplicates. A plain restart keeps the checkpoints, and `make reset` clears both together, so the scripted flows never duplicate.

**10.5 How do you aggregate the logs into the alert summary: a script, a pipeline or manual analysis?**

A two-stage automated pipeline:
1. **Vector** (`vector/vector.yaml`) tails the four logs. VRL transforms (`norm_access`, `norm_waf`, `norm_error`, `norm_fail2ban`) map every event to one schema (`ts, source, event_type, client_ip, method, uri, status, request_id, action, attack_type, attack_families, mitre, rule_ids, rules, detail`) and append it to `logs/central/events.ndjson`.
2. **`scripts/alert_summary.py`** (Python standard library only; `make summary`) reads the central file and writes `reports/alert_summary.md/.csv/.json` and `reports/dashboard.html`.

**10.6 How does the summary group events by SQLi, XSS, traversal, command injection, scanner and brute force?**

- **WAF events** (`vector.yaml` lines 70–101) count matching rules per CRS tag family:
  - `attack-sqli` → SQL Injection
  - `attack-xss` → Cross-Site Scripting
  - `attack-lfi` / `attack-rfi` → Path Traversal / File Inclusion
  - `attack-rce` → Command Injection
  - `attack-php`

  The **family with the most matches wins** (ties break in that order). Scanner tags or a 913xxx ID always win, giving Scanner / Recon (T1595.002). Our custom rules carry the same tags (e.g. 10100: `attack-rce`). Every matched family is kept in `attack_families`.
- **Brute force** comes from `rate_limit` events (nginx error-log lines for zones `login`/`brute`) plus fail2ban `ban` events. The `general` zone becomes "Flood / Rate Limit".
- Each attack type is mapped to ATT&CK / CWE / CAPEC in `alert_summary.py` (`TAXONOMY`).

**10.7 How do you avoid counting the same request twice when it appears in both proxy and WAF logs?**

Each category is counted from **exactly one source**:
- **WAF categories** come only from `waf_alert` events. That is one audit entry per transaction, keyed by `request_id`. The duplicate ModSecurity lines in the nginx error log are dropped in Vector (`vector.yaml:136`: `if contains(m, "ModSecurity: ") { abort }`).
- **Brute force** comes only from `rate_limit` events (the error log). The matching 429 lines in the access log are used only for the totals row. ModSecurity's rule-less audit entries for those 429s are dropped (`vector.yaml:69`).
- **Proxy access events** feed only the "requests / allowed / 403 / 429" totals and are never added to the per-type counts.

Result: the "Path Traversal" row (10) equals the number of distinct request IDs (see 10.8).

**10.8 Show one alert-summary row and trace it back to the raw log evidence.**

From `alert_summary_clean_test_run.md`:
```
| Path Traversal / File Inclusion | 10 | 0 | 0 | 1 | T1190 | CWE-22 | CAPEC-126 | 930110, 930120, 930100, 932160 | 06:10:55 | 06:10:57 |
```
- **Recount from the central log:** `jq 'select(.event_type=="waf_alert" and .attack_type=="Path Traversal / File Inclusion" and .action=="blocked_waf")'` gives **10** distinct `request_id`s (3 from the attack script + 7 from the evasion variants).
- **Follow the IDs into the raw audit log**, for example:
  - `068417fb…` → `uri: /vulnerabilities/fi/?page=..%5c..%5c..%5c..%5cetc%5cpasswd`, `interrupted: true`, rules `930100, 930110, 930110, 930120, 932240, 949110`
  - `f5956ec6…` → `?page=%252e%252e%252f…` (double-encoded), rules `920230, 930100, 930110, 930120, 949110`
- **Same IDs in the nginx access log:** `status 403`, empty `upstream_status`.

All of this is in `metrics_and_trace.txt`.

---

## 11. Your custom virtual-patching rule (implemented)

File: `waf/modsec/SHIELDWALL-CUSTOM-RULES.conf`. The main rule discussed is **10100**. Siblings 10110 (`sqli/ id` numeric) and 10120 (`fi/ page` allow-list) follow the same pattern; 10200 is the scanner UA rule.

**11.1 Which vulnerability/pattern does the rule mitigate, and why was CRS alone insufficient?**

OS command injection in `/vulnerabilities/exec/`. DVWA runs `shell_exec('ping -c 4 ' . $_REQUEST['ip'])` (CWE-78).

The evasion payload **`ip=127.0.0.1%0aid`** (a newline as the command separator, then `id`) **got through CRS at PL1 *and* PL2** and returned `uid=33(www-data)` from the bare app. CRS deliberately skips very short Unix commands such as `id` to avoid false positives.

Measured in this review at PL2 (`virtual_patch_test.txt`): the only rule that fires is **10100**, giving HTTP 403.

**11.2 Where is the custom rule file included, and at what point in rule processing?**

`setup.conf` line 14, **after** `owasp-crs/rules/*.conf`. The rule is `phase:2` (request body / ARGS).
- Within phase 2 it runs after the CRS rules *and after 949110*. So if CRS already blocks a request, 10100 never runs; it acts as a backstop for exactly what CRS misses.
- 10200 is `phase:1`, so it runs before any phase-2 rule.

**11.3 What rule ID did you assign, and how do you ensure it doesn't conflict with CRS IDs?**

**10100** (10110, 10120, 10200 for the siblings).
- The ModSecurity ID registry reserves **1–99,999 for local rules**, and CRS uses **900,000–999,999**.
- Our tuning rules use 1000–1099, and our custom rules 10000–10999.
- The rules were renumbered from 100100+ during this review, because 100,000–199,999 is reserved for a third-party vendor in the registry.

Duplicate IDs make ModSecurity refuse to load. nginx's start-up line `rules loaded … 0/863/0` and `nginx -t` passing confirm there is no clash.

**11.4 Which variable does the rule inspect, and why is it appropriate?**

```
SecRule REQUEST_FILENAME "@beginsWith /vulnerabilities/exec/"  "id:10100,phase:2,deny,status:403,…,chain"
    SecRule ARGS:ip "!@rx \A(?:<IPv4>|<RFC-1123 hostname>)\z" "t:none"
```
- **`REQUEST_FILENAME`** (the path without the query) scopes the rule to the one vulnerable endpoint.
- **`ARGS:ip`** covers the exact parameter PHP reads. `ARGS` includes query *and* POST body values, matching `$_REQUEST`, and every value is checked if the parameter is repeated.

This is a **positive (allow-list) model**: it describes the only legal value (an IPv4 address or hostname) instead of trying to enumerate attacks.

**11.5 What transformations or normalization are applied before matching, and what evasions could remain?**

- **Path:** `t:urlDecodeUni,t:normalizePath` on `REQUEST_FILENAME`, so `/vulnerabilities/./exec/`, `//exec` and `%2e` variants still match the scope.
- **`ARGS:ip`:** `t:none`. ModSecurity has already URL-decoded the argument once, which is exactly what PHP sees. A double-encoded payload stays `%…` and fails the allow-list, so it is **blocked**.
- **Anchors:** `\A … \z`, because libmodsecurity compiles `@rx` with PCRE2 `MULTILINE`, where `^…$` match at every newline. That was exactly how `%0aid` first bypassed our original `^…$` rule.

**Remaining evasions:**
- Legitimate-looking hostnames that resolve somewhere unexpected: ping to an attacker host (SSRF-like reconnaissance, not command execution).
- A case-different path (`/Vulnerabilities/exec/`) is a different, non-existent file on Linux/Apache, so not a bypass.
- Content types PHP doesn't parse into `$_REQUEST` (JSON) aren't a bypass either.
- If DVWA added a second route into `shell_exec`, the rule wouldn't cover it, because it is endpoint-scoped.

**11.6 What action does the rule take, and how can you verify it?**

**`deny,status:403,log`**: an immediate block, not scoring. Verify with:

```bash
docker compose exec attacker bash -c 'source /work/scripts/lib.sh; dvwa_login admin password; \
  http POST /vulnerabilities/exec/ --data "ip=127.0.0.1%0aid&Submit=Submit"; echo $CODE'   # 403
```
Then grep the response's `X-Request-ID` in `audit.json`: the only message is `10100 "Shield Wall virtual patch: command injection in exec/ …"` with `is_interrupted: true`.

**11.7 What legitimate request did you test to make sure the rule isn't too broad?**

`ip=127.0.0.1`, `ip=localhost` and `ip=db` all returned **HTTP 200**, with no rule firing and real ping output (`PING 127.0.0.1`, `PING localhost`, `PING db`) in `virtual_patch_test.txt`. The benign script also posts `127.0.0.1` and `localhost` on every run (41/41).

**11.8 How would you remove or roll back the rule quickly if it caused false positives?**

The fastest options, fully reversible:
1. Comment out rule 10100 in `SHIELDWALL-CUSTOM-RULES.conf`, then `docker compose exec waf nginx -t && docker compose exec waf nginx -s reload` (zero downtime). Recreate the WAF instead if the file was replaced by an editor; see 2.6.
2. Switch it to monitor-only: change `deny,status:403` to `pass` and keep `log`, so you still see what it would have blocked.
3. Add `SecRuleRemoveById 10100` to `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` (loaded after the rule).

The file is in git, so `git revert` also works. CRS still protects the endpoint in the meantime.

---

## 12. Troubleshooting based on your running stack

**12.1 The app works when accessed directly but fails through nginx. What would you check?**

1. **Upstream:**
   - `nginx -T | grep -A2 'upstream dvwa_backend'` → `server dvwa:80`.
   - Does `waf` resolve and reach it? `docker compose exec waf curl -sI http://dvwa/login.php`.
   - The error log shows `connect() failed` or `upstream timed out`.
2. **Headers:**
   - `Host` (`$host`).
   - Cookie flags: `proxy_cookie_flags … secure` breaks plain-HTTP access; the app must be used over HTTPS.
   - Redirect `Location` targets: `proxy_redirect off`, and DVWA uses relative redirects.
3. **Path:**
   - Which `location` matched?
   - Is it one of the 404'd paths (`setup.php`, `config/`, …)?
   - `proxy_pass` URI rewriting (see 3.10).
4. **Logs:**
   - Access log `status` / `upstream_status` / `limit_req` for the request ID.
   - A 403 → audit log by ID. A 429 → rate limit. A 000 → ban (`make status`).

**12.2 Every request is blocked. How do you tell CRS from your custom rule from rate limiting?**

Look at one blocked request's status and ID:
- **403:** check the audit log by `X-Request-ID`.
  - Final message **949110** → CRS anomaly score (look at the contributing rule IDs).
  - **10100–10200** → our custom rule.
  - **1xxx** wouldn't block, since those are pass/ctl rules.
- **429:** the access log shows `limit_req:"REJECTED"` and the error log shows `limiting requests … by zone "<zone>"`. It's the rate limit, and the zone name says which one.
- **Connection refused (000):** fail2ban. Check `fail2ban-client status shieldwall-bruteforce|shieldwall-waf` and `iptables -S`.
- **404 on admin paths:** the edge location rule.

To isolate, temporarily:
- set `MODSEC_RULE_ENGINE=DetectionOnly` (logs but never blocks), or
- run `make unban`, or
- test from the other container (separate IP buckets).

**12.3 An attack reaches the app: is ModSecurity disabled, in DetectionOnly, misconfigured, or just missing a rule?**

1. **Disabled / not loaded:** `nginx -T | grep -E 'load_module.*modsecurity|modsecurity on'`. The access log line exists, but the audit log has **no entry at all**, even for an obvious `<script>`.
2. **DetectionOnly:** `grep SecRuleEngine /etc/modsecurity.d/modsecurity.conf`. The audit log has entries with rule matches and even 949110, but `is_interrupted:false` and the response is 200.
3. **Misconfigured:**
   - `nginx -t` shows a `rules loaded` count far below 863 → the CRS include is missing.
   - Paranoia or threshold wrong: grep `blocking_paranoia_level` / `inbound_anomaly_score_threshold` in `crs-setup.conf`.
   - An exclusion too broad: review the `ctl:` rules.
4. **No matching rule:** the engine is On and an obvious test payload is blocked, but this payload's audit entry is absent or below threshold. That's a detection gap, like our `%0aid` (no rule matched at all). The fix is a virtual patch, a higher PL, or a custom signature.

**12.4 Audit logs are empty but requests appear in access logs. What config and permissions would you check?**

- **Config:**
  - `SecAuditEngine` (`RelevantOnly` only logs 4xx/5xx except 404, so allowed 200s are *expected* to be absent).
  - `SecAuditLogRelevantStatus`.
  - `SecAuditLog` path.
  - `SecRuleEngine` / `modsecurity on`.
  - The image's default `MODSEC_AUDIT_LOG=/dev/stdout`, i.e. check that our env override is present.
- **Permissions:** nginx runs as **uid 101**, so it must be able to write `./logs/modsec`. That is why `make up` runs `chmod 1777 logs/*`.
  - Check with `docker compose exec waf touch /var/log/shieldwall/modsec/x`.
  - A bind mount from a root-owned host directory silently blocks writes.
- **Mount:** `docker inspect` the waf mounts to confirm `./logs/modsec` is attached.

**12.5 The rate limit never triggers. What do you verify about the location, key, zone and timing?**

- **Location:** is the request matched by `location = /login.php`? An exact match with no query difference. A path like `/login.php/` would fall to `location /`.
- **Key:** the `login` key is empty for non-POST requests, so GETs **never** count (by design: T1 shows 20 × 200). The `brute` key needs a `Login` argument.
- **Zone:** `nginx -T | grep limit_req` must show both `limit_req_zone … zone=login` and `limit_req zone=login burst=3` in that location. Remember a location-level `limit_req` replaces inherited ones.
- **Timing:** the bucket refills every 10 s, so a test sending 1 request per 10 s never trips it. Send them back-to-back.
- **Shared IP:** the client IP seen by nginx (`client_ip` in the access log) must be the one you think it is.
- **Order:** a request already blocked by ModSecurity never reaches `limit_req` (measured, 1.3).

**12.6 nginx cannot resolve the upstream service name. What Docker networking evidence would you inspect?**

1. Is `waf` attached to `shieldwall_backend`? `docker inspect shieldwall-waf-1 --format '{{json .NetworkSettings.Networks}}'` should show `backend=10.66.20.10`.
2. Is `dvwa` on the same network and running? `docker network inspect shieldwall_backend`.
3. Is the name right? `dvwa` is the service name; a container name or an alias may differ.
4. Embedded DNS: `docker compose exec waf getent hosts dvwa` should return 10.66.20.20.
5. Timing: nginx resolves `server dvwa:80` once, at startup. If dvwa wasn't up, nginx fails with `host not found in upstream`. `depends_on: service_healthy` prevents this, and static IPs prevent stale addresses after a recreate.

**12.7 The proxy is bypassed by connecting directly to the app port. What Compose/network change closes that path?**

- Remove any `ports:` from `dvwa` (we have none).
- Keep `dvwa` **only** on a network marked `internal: true` that the outside can't reach (`shieldwall_backend`).
- Make the WAF the only container attached to both networks.
- In our stack the only bypass is the deliberate demo service `dvwa-direct` (profile `unprotected`). Close it with `make unprotected-down`, or remove the service.

Optionally, the app could also accept traffic only from 10.66.20.10 (an Apache `Require ip` rule) as defense in depth.

---

## 13. Final implementation review and demo

**13.1 Explain every service, port, network, volume and dependency that affects the security boundary.**

- **Public boundary:** only `waf` publishes ports, on **127.0.0.1:9080/9443**. HTTP only redirects to HTTPS.
- **Networks:**
  - `frontend` (10.66.10.0/24): waf, attacker, client.
  - `backend` (10.66.20.0/24, **internal**): waf, dvwa, db.
  - The **WAF is the only bridge between them.**
- **Volumes:** configuration and certs are mounted **read-only**; only the log directories are writable.
- **fail2ban** shares the WAF's network namespace, so its bans sit *in front of* nginx without touching the host firewall.
- **Vector** has no network (`none`).
- **Dependencies:** `db → dvwa → waf → {fail2ban, vector}`, all `service_healthy`.
- **Boundary exceptions:** `attacker-direct` (baseline) and `dvwa-direct` (demo), both opt-in profiles.

See section 1 for line-level detail.

**13.2 Explain the exact reverse-proxy route and the security-relevant nginx directives.**

See 1.3 and 3.x. Security-relevant directives:
- `ssl_protocols TLSv1.2 TLSv1.3` + AEAD `ssl_ciphers`
- `limit_req` / `limit_conn` zones and statuses
- the 404 location for admin paths
- `client_max_body_size 1m`
- proxy timeouts
- overwriting `X-Forwarded-For` / `X-Real-IP`
- `modsecurity_transaction_id "$request_id"`
- HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy, `X-Request-ID`
- `proxy_cookie_flags ~ secure httponly samesite=lax`
- `server_tokens off` + a custom `Server` header
- `proxy_hide_header X-Powered-By`

**13.3 Identify the active engine mode, CRS version, thresholds and exclusions.**

| Setting | Value |
|---|---|
| Engine | `SecRuleEngine On` |
| CRS version | **4.30.0** |
| Paranoia level | blocking/detection **2** |
| Anomaly thresholds | inbound **5**, outbound **4** |
| Exclusions | 1010 (4 response rules, `/instructions.php` only); 1020 (942200/942440/932200 on `ARGS:mtxMessage` at `/vulnerabilities/xss_s/` only) |
| Hardening | 1000 (allowed methods) |
| Custom rules | 10100, 10110, 10120, 10200 |
| Rules loaded | 863 |

See section 5 and `runtime_waf_config.txt`.

**13.4 Run the attack replay and explain each request's outcome using client output and WAF logs.**

`make unban && make attack`: **16/16 blocked**. Each line prints its request ID, which gives the audit rule list (section 6, `request_traces.txt`):
- the 12 exploit payloads end in 949110 (scores 15–40);
- the 3 scanner UAs end in 10200 (phase 1);
- the burst shows 2 × `ALLOWED-BURST`, 10 × 429, then `BANNED` after about 2 s.

**13.5 Run the benign replay and show the allowed-request target is met; explain any benign blocks.**

`make benign` gives **41/41 allowed (100%) and 41/41 functional**, against a target of ≥ 95%. There are no benign blocks in the final configuration: zero audit entries for 10.66.10.20. Historical false positives and their fixes are in 9.4 and 9.7.

**13.6 Demonstrate rate limiting with the brute-force replay and identify the exact response and log evidence.**

`make ratelimit`, final run, 5/5 PASS:

| Test | Result |
|---|---|
| T1: 20 × GET `/login.php` | 20 × 200 |
| T2: flood | 39 × 200 / 81 × 429 |
| T3: 10 wrong-password POSTs | 4 reached the app, 6 × 429 |
| T4: auto-ban | banned after 1 s |
| T5: benign client | 200 |

Evidence lines:
- Access log: `"status":429,"limit_req":"REJECTED"`.
- Error log: `limiting requests, excess: 3.683 by zone "login", client: 10.66.10.66 …`.
- fail2ban: `NOTICE [shieldwall-bruteforce] Ban 10.66.10.66`.
- iptables: `-A f2b-shieldwall-bruteforce -s 10.66.10.66/32 -j REJECT --reject-with icmp-port-unreachable`.
- Files: `bruteforce_trace.txt`, `evidence/rate_limit_evidence.txt`.

**13.7 Show the alert summary and trace at least one grouped alert back to a raw event.**

`reports/alert_summary.md` and `reports/dashboard.html`. Final totals across all runs including the real tools:

| Attack type | Count |
|---|---|
| SQL Injection | 113 |
| Flood (rate limit) | 74 |
| Command Injection | 18 |
| Brute Force | 16 × 429 + 2 bans |
| XSS | 14 |
| Scanner | 14 |
| Path Traversal | 12 |
| Automated-attack ban | 1 |

Benign false positives: **0**. The trace of the "Path Traversal" row back to central → audit → access log entries by request ID is in 10.8.

**13.8 State the residual risks: what the edge layer doesn't fix, and what still needs source-code remediation.**

**The application is still vulnerable.** The WAF is a compensating control:

| Vulnerable code | Needed fix |
|---|---|
| `sqli/` concatenates `$id` into SQL | parameterized queries (CWE-89) |
| `xss_r` / `xss_s` echo input unencoded | output encoding + CSP (CWE-79) |
| `fi/` passes `page` to `include()` | allow-list in code (CWE-22/98) |
| `exec/` passes `ip` to `shell_exec` | validate, `escapeshellarg`, or remove (CWE-78) |
| Login has no lockout | per-account throttling, MFA (CWE-307) |
| CSRF / file upload / weak session IDs (not covered by our tests) | code changes; CRS gives only generic protection |

**Edge limitations:**
- A new evasion that matches neither a CRS signature nor a virtual-patch allow-list gets through. Only 4 endpoints have positive allow-lists.
- Response-phase rules on nginx are detect-only.
- Per-IP controls are weak against distributed or slow brute force and against shared-IP users.
- The backend hop is plain HTTP.
- The lab CA is not publicly trusted.
- DVWA's brute page puts credentials in the query string, so they appear in the access-log URIs.

**Required source fixes, in priority order:**
1. Command injection
2. SQL injection
3. File inclusion
4. XSS (+ CSP)
5. Login lockout + MFA

Then keep the WAF at PL2 as defense in depth, and move each virtual patch to log-only once its fix is verified.
