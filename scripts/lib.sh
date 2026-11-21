#!/usr/bin/env bash
# Shared helpers for the Shield Wall replay scripts (sourced, not executed).
# Runs inside the shieldwall-tools container (bash, curl, jq).

: "${TARGET:=https://shieldwall.local:9443}"
: "${CACERT:=/work/certs/ca.crt}"
: "${UA_BROWSER:=Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0}"

# ---- Safety: these scripts may only ever target this lab ---------------------
# TARGET can be overridden, so the host part is checked against the lab allow-list.
# The attacker container has outbound internet access (frontend is not "internal"),
# so this guard is what stops a typo or a copy-paste from attacking a real host.
_tgt_host="${TARGET#*://}"; _tgt_host="${_tgt_host%%[:/]*}"
case "$_tgt_host" in
  shieldwall.local|waf|dvwa|localhost|127.0.0.1|10.66.10.10|10.66.20.20) ;;
  *) echo "REFUSED: TARGET host '$_tgt_host' is not part of the Shield Wall lab (allowed: shieldwall.local, waf, dvwa, localhost, 127.0.0.1, 10.66.10.10, 10.66.20.20)" >&2
     exit 2 ;;
esac

WORKDIR_TMP="$(mktemp -d)"
JAR="$WORKDIR_TMP/cookies.txt"
BODY="$WORKDIR_TMP/body.html"
HDRS="$WORKDIR_TMP/headers.txt"
trap 'rm -rf "$WORKDIR_TMP"' EXIT

curl_opts() {
  local -a o=(-s -o "$BODY" -D "$HDRS" -b "$JAR" -c "$JAR" --max-time 20 --connect-timeout 5)
  if [[ "$TARGET" == https://* ]]; then o+=(--cacert "$CACERT"); fi
  printf '%s\0' "${o[@]}"
}

# http METHOD PATH [extra curl args...]
#   sets globals: CODE, LOCATION, TIME_S, NET, CURL_ERR. Response body ends up in $BODY.
#   CODE is 000 when no HTTP response was received. NET then says why:
#     refused  : curl exit 7, TCP connect actively rejected (what the fail2ban REJECT rule produces;
#                every script first checks the proxy is reachable, so a later refusal = the ban)
#     timeout  : connect/read timeout        dns : name resolution failed
#     tls      : TLS handshake/cert error    other : anything else
#   Only "refused" may be counted as a block (see is_blocked); the rest are ERRORS.
http() {
  local method="$1" path="$2"; shift 2
  local -a base; mapfile -d '' base < <(curl_opts)
  : > "$BODY"; : > "$HDRS"
  local out errf="$WORKDIR_TMP/curl.err"
  out=$(curl "${base[@]}" -S -X "$method" -A "${UA:-$UA_BROWSER}" \
        -w '%{http_code} %{time_total}' "$@" "${TARGET}${path}" 2>"$errf")
  CURL_RC=$?
  CODE="${out%% *}"; TIME_S="${out##* }"
  [[ -z "$CODE" ]] && CODE="000"
  CURL_ERR=$(tr '\n' ' ' < "$errf" | cut -c1-160)
  NET="ok"
  if [[ "$CODE" == "000" ]]; then
    # classified by curl's exit code (message wording differs between curl versions)
    case "$CURL_RC" in
      7)      NET="refused" ;;   # TCP connect actively rejected (fail2ban REJECT -> ICMP port-unreachable)
      28)     NET="timeout" ;;   # no answer at all (host down / filtered)
      6)      NET="dns" ;;
      35|60)  NET="tls" ;;
      *)      NET="other" ;;
    esac
  fi
  LOCATION=$(grep -i '^location:' "$HDRS" 2>/dev/null | tail -1 | tr -d '\r' | sed 's/^[Ll]ocation: *//')
}

# is_blocked: true only for a real edge decision
#   403 = ModSecurity deny, 429 = nginx rate limit, 000+refused = fail2ban ban (REJECT).
#   A timeout, DNS failure, TLS error or 5xx is NOT a block. It is an error/inconclusive.
is_blocked() {
  [[ "$CODE" == "403" || "$CODE" == "429" ]] && return 0
  [[ "$CODE" == "000" && "$NET" == "refused" ]] && return 0
  return 1
}

# DVWA puts a per-session anti-CSRF token in every form
get_token() {
  sed -n "s/.*name='user_token' value='\([0-9a-f]*\)'.*/\1/p" "$BODY" | head -1
}

# dvwa_login USER PASS  -> returns 0 when DVWA redirects to index.php
dvwa_login() {
  local user="$1" pass="$2" token
  http GET /login.php
  token=$(get_token)
  http POST /login.php --data-urlencode "username=$user" --data-urlencode "password=$pass" \
       --data-urlencode "user_token=$token" --data "Login=Login"
  [[ "$CODE" == "302" && "$LOCATION" == *index.php* ]]
}

# CSV helpers
csv_escape() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
csv_row() {  # fields...
  local first=1 f
  for f in "$@"; do
    [[ $first -eq 1 ]] || printf ','
    csv_escape "$f"; first=0
  done
  printf '\n'
}

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_rst=$'\e[0m'
[[ -t 1 ]] || { c_red=""; c_grn=""; c_ylw=""; c_rst=""; }
