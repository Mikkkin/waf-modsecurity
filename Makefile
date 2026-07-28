SHELL := /bin/bash

# Узлы стенда. Переопределяются из командной строки:
#   make deploy WAF_HOST=user@10.0.0.5
WAF_HOST      ?= user@192.168.122.10
ATTACKER_HOST ?= user@192.168.122.30
SSH_KEY       ?= ~/.ssh/waf-lab
SSH           := ssh -i $(SSH_KEY) -o BatchMode=yes
RSYNC         := rsync -a -e 'ssh -i $(SSH_KEY) -o BatchMode=yes'

WAF_URL    ?= http://waf.lab
REMOTE     ?= /opt/waf-lab
LOG        ?= /var/log/modsec/audit.log
RULES_DIR  ?= /etc/crs4/rules
MODSEC_DIR ?= /etc/nginx/modsec
WITH_TOOLS ?= 0
RUN_ID     ?=
RUN        ?=

.DEFAULT_GOAL := help
.PHONY: help ping deploy deploy-waf deploy-attacker detect block pl1 pl2 \
        harden-on harden-off traffic legit attack reset-log \
        top fp score unmatched cases logs check test lint clean

help:
	@echo "Стенд WAF на базе ModSecurity - управление в один клик"
	@echo ""
	@echo "  make ping             проверить доступность узлов по SSH"
	@echo "  make deploy           разложить конфигурацию на waf и трафик на attacker"
	@echo "  make deploy-waf       только конфигурация WAF"
	@echo "  make deploy-attacker  только генератор трафика"
	@echo ""
	@echo "  make detect           режим мониторинга (SecRuleEngine DetectionOnly)"
	@echo "  make block            режим блокировки (SecRuleEngine On)"
	@echo "  make pl1 / make pl2   уровень паранойи"
	@echo "  make harden-on        включить правило 12001 против обхода на GLOB/MATCH/COLLATE"
	@echo "  make harden-off       отключить правило 12001"
	@echo ""
	@echo "  make traffic          прогнать оба набора  (RUN_ID=detect-01 WITH_TOOLS=1)"
	@echo "  make legit            только легитимный трафик"
	@echo "  make attack           только вредоносный трафик"
	@echo "  make reset-log        очистить audit-лог перед прогоном"
	@echo ""
	@echo "  make top              наиболее часто срабатывающие правила   (RUN=detect-01)"
	@echo "  make fp               класс трафика | случай | запрос | правило | код"
	@echo "  make score            итоговый счет аномалии по транзакциям"
	@echo "  make unmatched        легитимные запросы без единого срабатывания"
	@echo "  make cases            сводка класс трафика на код ответа"
	@echo "  make logs             хвост audit-лога"
	@echo ""
	@echo "  make check            nginx -t и проверка набора правил на узле waf"
	@echo "  make test             регрессионные тесты go-ftw против живого стенда"
	@echo "  make lint             shellcheck и yamllint локально"

ping:
	@for h in $(WAF_HOST) $(ATTACKER_HOST); do \
	  printf "%-28s " "$$h"; \
	  $(SSH) $$h hostname 2>/dev/null || echo "НЕДОСТУПЕН"; \
	done

deploy: deploy-waf deploy-attacker

deploy-waf:
	$(RSYNC) waf/ $(WAF_HOST):/tmp/waf-conf/
	$(SSH) $(WAF_HOST) 'set -e; \
	  sudo install -d $(MODSEC_DIR) /var/log/modsec; \
	  sudo cp /tmp/waf-conf/modsecurity.conf   $(MODSEC_DIR)/modsecurity.conf; \
	  sudo cp /tmp/waf-conf/crs-setup-lab.conf $(MODSEC_DIR)/crs-setup-lab.conf; \
	  sudo cp /tmp/waf-conf/modsec-main.conf   $(MODSEC_DIR)/main.conf; \
	  sudo cp /tmp/waf-conf/rules/*.conf       $(RULES_DIR)/; \
	  sudo cp /tmp/waf-conf/nginx/waf.conf     /etc/nginx/sites-available/waf.conf; \
	  sudo ln -sf /etc/nginx/sites-available/waf.conf /etc/nginx/sites-enabled/waf.conf; \
	  sudo nginx -t && sudo systemctl reload nginx'

deploy-attacker:
	$(SSH) $(ATTACKER_HOST) "sudo install -d -o \$$(id -un) $(REMOTE)"
	$(RSYNC) traffic/ $(ATTACKER_HOST):$(REMOTE)/traffic/
	$(SSH) $(ATTACKER_HOST) "chmod +x $(REMOTE)/traffic/*.sh"

detect:
	$(SSH) $(WAF_HOST) 'sudo sed -i "s/^SecRuleEngine .*/SecRuleEngine DetectionOnly/" $(MODSEC_DIR)/modsecurity.conf && sudo nginx -t && sudo systemctl reload nginx'

block:
	$(SSH) $(WAF_HOST) 'sudo sed -i "s/^SecRuleEngine .*/SecRuleEngine On/" $(MODSEC_DIR)/modsecurity.conf && sudo nginx -t && sudo systemctl reload nginx'

pl1:
	$(SSH) $(WAF_HOST) 'sudo sed -i "s/_paranoia_level=[0-9]/_paranoia_level=1/g" $(MODSEC_DIR)/crs-setup-lab.conf && sudo nginx -t && sudo systemctl reload nginx'

pl2:
	$(SSH) $(WAF_HOST) 'sudo sed -i "s/_paranoia_level=[0-9]/_paranoia_level=2/g" $(MODSEC_DIR)/crs-setup-lab.conf && sudo nginx -t && sudo systemctl reload nginx'

harden-on:
	$(SSH) $(WAF_HOST) 'sudo mv -f $(RULES_DIR)/REQUEST-948-LAB-SQLITE-OPERATORS.conf.disabled $(RULES_DIR)/REQUEST-948-LAB-SQLITE-OPERATORS.conf 2>/dev/null; sudo nginx -t && sudo systemctl reload nginx'

harden-off:
	$(SSH) $(WAF_HOST) 'sudo mv -f $(RULES_DIR)/REQUEST-948-LAB-SQLITE-OPERATORS.conf $(RULES_DIR)/REQUEST-948-LAB-SQLITE-OPERATORS.conf.disabled 2>/dev/null; sudo nginx -t && sudo systemctl reload nginx'

traffic:
	$(SSH) $(ATTACKER_HOST) 'cd $(REMOTE)/traffic && WAF=$(WAF_URL) RUN_ID=$(RUN_ID) WITH_TOOLS=$(WITH_TOOLS) ./run-all.sh'

legit:
	$(SSH) $(ATTACKER_HOST) 'cd $(REMOTE)/traffic && WAF=$(WAF_URL) RUN_ID=$(RUN_ID) ./legit.sh'

attack:
	$(SSH) $(ATTACKER_HOST) 'cd $(REMOTE)/traffic && WAF=$(WAF_URL) RUN_ID=$(RUN_ID) WITH_TOOLS=$(WITH_TOOLS) ./attack.sh'

reset-log:
	$(SSH) $(WAF_HOST) 'sudo truncate -s 0 $(LOG)'

top fp score cases:
	$(SSH) $(WAF_HOST) 'cd $(REMOTE)/analysis && sudo RUN=$(RUN) ./analyze.sh $@'

unmatched:
	$(SSH) $(WAF_HOST) 'cd $(REMOTE)/analysis && sudo RUN=$(RUN) ./analyze.sh clean'

logs:
	$(SSH) $(WAF_HOST) 'sudo tail -n 40 $(LOG)'

check:
	$(SSH) $(WAF_HOST) 'sudo nginx -t && sudo /usr/lib/x86_64-linux-gnu/libexec/modsec-rules-check $(MODSEC_DIR)/main.conf'

test:
	ftw check -d tests/regression
	ftw run -d tests/regression --config tests/ftw.yaml --show-failures-only

lint:
	shellcheck -x -e SC2016 -P traffic traffic/*.sh analysis/*.sh deploy.sh
	yamllint -d relaxed tests .github

clean:
	rm -rf traffic/results
