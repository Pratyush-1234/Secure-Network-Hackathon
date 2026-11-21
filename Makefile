# Shield Wall (PS6): lab control. Run `make help` for the list of targets.
SHELL := /bin/bash
DC    := docker compose
TOOLS := shieldwall-tools:1.0

.DEFAULT_GOAL := help
.PHONY: help certs build up setup unprotected-up unprotected-down baseline attack attack-tools benign variations ratelimit summary evidence test demo unban status logs reset down clean zip

help:  ## show this help
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

certs:  ## generate the lab CA + TLS server certificate (once)
	@./certs/gen-certs.sh

build:  ## build the attacker/client toolbox image
	@$(DC) build -q attacker

up: certs build  ## start the whole lab and initialise DVWA
	@mkdir -p logs/nginx logs/modsec logs/fail2ban logs/central evidence reports
	@chmod 1777 logs/nginx logs/modsec logs/fail2ban logs/central
	@$(DC) up -d --wait
	@$(MAKE) --no-print-directory setup
	@echo "Lab up:  https://localhost:9443  (DVWA login admin / password; trust certs/ca.crt to avoid the browser warning)"

setup:  ## create/reset the DVWA database (runs on the internal backend network)
	@$(DC) --profile baseline run --rm -T attacker-direct bash /work/scripts/dvwa_setup.sh

baseline:  ## BEFORE: run the attack script straight at the app (no WAF), then reset the DB
	@set -o pipefail; $(DC) --profile baseline run --rm -T attacker-direct bash /work/scripts/attack.sh --mode direct 2>&1 | grep -v Container | tee >(sed 's/\x1b\[[0-9;]*m//g' > evidence/baseline_direct_output.txt)
	@$(MAKE) --no-print-directory setup

unprotected-up:  ## DEMO: expose the bare app (no WAF) at http://127.0.0.1:8081 for a browser "before" view
	@$(DC) --profile unprotected up -d dvwa-direct
	@echo "UNPROTECTED DVWA (no WAF): http://127.0.0.1:8081   |   PROTECTED: https://localhost:9443"

unprotected-down:  ## DEMO: remove the unprotected entry point again
	@$(DC) --profile unprotected rm -sf dvwa-direct >/dev/null && echo "unprotected entry point removed"

attack:  ## AFTER: attack replay through the WAF (from attacker 10.66.10.66)
	@$(DC) exec -T attacker bash /work/scripts/attack.sh --mode waf

attack-tools:  ## attack replay + real sqlmap / nikto / ffuf through the WAF
	@$(DC) exec -T attacker bash /work/scripts/attack.sh --mode waf --tools --out /work/evidence/attack_waf_tools.csv

benign:  ## benign replay through the WAF (from client 10.66.10.20)
	@$(DC) exec -T client bash /work/scripts/benign.sh

variations:  ## extra evasion payloads (judge-style variations) through the WAF
	@$(DC) exec -T attacker bash /work/scripts/judge_variations.sh

ratelimit:  ## dedicated rate-limit + auto-ban test (page views, flood, login burst, ban, client unaffected)
	@./scripts/rate_limit_test.sh

summary:  ## build the alert summary + dashboard from the centralized logs
	@sleep 3   # let Vector flush its file sink
	@$(DC) exec -T client python3 /work/scripts/alert_summary.py --events /work/logs/central/events.ndjson --out /work/reports

evidence:  ## collect TLS / fail2ban / log evidence into evidence/
	@./scripts/collect_evidence.sh

test:  ## full acceptance test from a clean state (reset, benign, variations, attack, summary)
	@set -o pipefail; ./scripts/acceptance_test.sh 2>&1 | tee >(sed 's/\x1b\[[0-9;]*m//g' > evidence/acceptance_test_output.txt)

demo: test evidence  ## everything needed for the live demo

unban:  ## lift all fail2ban bans
	@$(DC) exec -T fail2ban fail2ban-client unban --all >/dev/null && echo "all bans lifted"

status:  ## container health, jails and current bans
	@$(DC) ps --format 'table {{.Service}}\t{{.Status}}'
	@$(DC) exec -T fail2ban fail2ban-client status shieldwall-bruteforce | grep -E "Currently|Banned"
	@$(DC) exec -T fail2ban fail2ban-client status shieldwall-waf | grep -E "Currently|Banned"

logs:  ## follow the centralized event stream
	@tail -f logs/central/events.ndjson

reset:  ## wipe logs, bans and rate-limit state, recreate the edge, reset the DVWA DB
	@$(DC) stop fail2ban vector waf >/dev/null 2>&1 || true
	@docker run --rm -v "$(CURDIR)/logs:/logs" -v "$(CURDIR)/fail2ban:/f2b" $(TOOLS) \
	  sh -c 'rm -f /logs/nginx/* /logs/modsec/* /logs/fail2ban/* /logs/central/*; rm -rf /f2b/db'
	@$(DC) up -d --wait --force-recreate waf fail2ban vector
	@$(MAKE) --no-print-directory setup
	@echo "reset complete"

down:  ## stop the lab (keeps logs, evidence and reports)
	@$(DC) --profile baseline --profile unprotected down

clean: down  ## stop the lab and delete runtime logs
	@docker run --rm -v "$(CURDIR)/logs:/logs" -v "$(CURDIR)/fail2ban:/f2b" $(TOOLS) \
	  sh -c 'rm -f /logs/nginx/* /logs/modsec/* /logs/fail2ban/* /logs/central/*; rm -rf /f2b/db'

zip:  ## package the submission (configs, scripts, evidence, reports, docs) into ../shield-wall-ps6.zip
	@cd .. && rm -f shield-wall-ps6.zip && zip -qr shield-wall-ps6.zip shield-wall \
	  -x 'shield-wall/certs/*.key' 'shield-wall/fail2ban/db/*' 'shield-wall/logs/*/*' 'shield-wall/.git/*' && \
	  echo "wrote $$(pwd)/shield-wall-ps6.zip" && unzip -l shield-wall-ps6.zip | tail -1
