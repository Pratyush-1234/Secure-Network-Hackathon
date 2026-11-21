#!/usr/bin/env bash
# Creates or resets the DVWA database. setup.php is deliberately NOT reachable
# through the WAF (nginx answers 404 for it), so this runs from the
# attacker-direct container, which sits on the internal backend network.
#   docker compose run --rm attacker-direct bash /work/scripts/dvwa_setup.sh
set -uo pipefail
TARGET="${1:-http://dvwa}"
source "$(dirname "$0")/lib.sh"

for i in $(seq 1 30); do
  http GET /setup.php
  [[ "$CODE" == "200" ]] && break
  sleep 2
done
token=$(get_token)
[[ -n "$token" ]] || { echo "[setup] could not read user_token from setup.php (HTTP $CODE)"; exit 1; }

http POST /setup.php --data-urlencode "user_token=$token" --data "create_db=Create+%2F+Reset+Database"
# DVWA answers the create_db POST with a 302 back to setup.php (or a 200 page)
if [[ "$CODE" == "302" || "$CODE" == "200" ]]; then
  echo "[setup] DVWA database created/reset (HTTP $CODE)"
else
  echo "[setup] WARNING: setup POST returned HTTP $CODE; verifying with a login"
fi

if dvwa_login admin password; then
  echo "[setup] login admin/password OK, DVWA ready (security level: ${DEFAULT_SECURITY_LEVEL:-low})"
else
  echo "[setup] ERROR: login failed after setup (HTTP $CODE, Location: $LOCATION)"; exit 1
fi
