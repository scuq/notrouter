.DEFAULT_GOAL := help

BINARY      := notrouter
PKG         := ./cmd/notrouter
CONFIG      := config.yaml
BUILD_DIR   := bin

VERSION     ?= dev
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS     := -X github.com/scuq/notrouter/internal/version.Version=$(VERSION) \
               -X github.com/scuq/notrouter/internal/version.Commit=$(COMMIT)

export CGO_ENABLED := 0

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: deps
deps: ## download deps
	go mod download

.PHONY: build
build: ## build static binary
	mkdir -p $(BUILD_DIR)
	go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY) $(PKG)

.PHONY: run
run: build ## build and run with config.yaml
	./$(BUILD_DIR)/$(BINARY) -config $(CONFIG)

.PHONY: dev
dev: ## go run with config.yaml
	go run -ldflags '$(LDFLAGS)' $(PKG) -config $(CONFIG)

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: fmt
fmt: ## gofmt -s -w
	gofmt -s -w .

.PHONY: test
test: ## go test -race
	go test -race ./...

.PHONY: clean
clean: ## remove build artifacts
	rm -rf $(BUILD_DIR)

.PHONY: docker
docker: ## build docker image
	docker build -t notrouter:$(VERSION) .

.PHONY: smoke-webhook
smoke-webhook: ## send a test webhook event
	curl -sS -X POST -H 'Content-Type: application/json' \
	  -d '{"entity":"router-1","state":"DOWN","type":"host"}' \
	  http://localhost:8080/webhook/generic

.PHONY: smoke-syslog
smoke-syslog: ## send a test syslog UDP message
	echo '<134>Oct 11 22:14:15 myhost myapp: test message' | nc -u -w1 localhost 5514

.PHONY: metrics
metrics: ## fetch /metrics
	curl -sS http://localhost:9090/metrics | grep notrouter_

.PHONY: health
health: ## hit /healthz
	curl -sS http://localhost:9090/healthz && echo

# ---- pass 2 smoke targets ----
.PHONY: smoke-syslog-rfc3164
smoke-syslog-rfc3164: ## RFC3164 syslog
	echo '<134>Oct 11 22:14:15 router-fra-01 sshd[1234]: Failed login' | nc -u -w1 localhost 5514

.PHONY: smoke-syslog-rfc5424
smoke-syslog-rfc5424: ## RFC5424 syslog
	echo '<165>1 2026-05-02T08:00:00Z router-fra-01 sshd 1234 ID47 - Failed login attempt' | nc -u -w1 localhost 5514

.PHONY: smoke-nagios
smoke-nagios: ## Nagios-shaped webhook (uses $.host -> entity)
	curl -sS -X POST -H 'Content-Type: application/json' \
	  -d '{"host":"router-fra-01","type":"host","state":"DOWN"}' \
	  http://localhost:8080/webhook/nagios

.PHONY: smoke-syslog-tcp-lf
smoke-syslog-tcp-lf: ## LF-terminated syslog over TCP
	echo '<134>Oct 11 22:14:15 router-fra-01 sshd[1234]: Failed login' | nc -w1 localhost 5514

.PHONY: smoke-all
smoke-all: smoke-webhook smoke-nagios smoke-syslog-rfc3164 smoke-syslog-rfc5424 smoke-syslog-tcp-octet smoke-syslog-tcp-lf smoke-tcp-json smoke-tcp-json-ansible smoke-tcp-json-multi ## fire every smoke target


# ---- v0.3.5 tcp_json smoke targets ----
# These send synthetic newline-delimited JSON to the tcp_json receiver
# on port 5044. Requires receivers.tcp_json.port_5044.enabled=true in
# config.yaml and 5044 published from the container.

.PHONY: smoke-tcp-json
smoke-tcp-json: ## bare-bones tcp_json: one JSON line, exits on TCP close
	@command -v python3 >/dev/null || (echo "python3 required for smoke-tcp-json"; exit 1)
	@python3 -c '\
import socket, json; \
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); \
s.connect(("localhost", 5044)); \
event = {"ansible_type":"finish","host":"smoke-test-host","@timestamp":"2026-06-02T00:00:00Z"}; \
s.sendall((json.dumps(event) + "\n").encode("utf-8")); \
s.close(); \
print("sent one tcp_json event to localhost:5044")'

.PHONY: smoke-tcp-json-ansible
smoke-tcp-json-ansible: ## simulated Ansible logstash callback finish event
	@command -v python3 >/dev/null || (echo "python3 required for smoke-tcp-json-ansible"; exit 1)
	@python3 -c '\
import socket, json; \
inner_meta = {"title":"Smoke Test Playbook","uri":"https://example.com/runs/smoke","repo":"https://gitlab.example.com/smoke"}; \
inner_result = {"localhost":{"ok":3,"changed":0,"failures":0,"unreachable":0},"smoke-host-1":{"ok":12,"changed":2,"failures":0,"unreachable":0}}; \
event = {"ansible_type":"finish","ansible_playbook":"smoke-test.yml","ansible_playbook_duration":7.42,"ansible_pre_command_output":json.dumps(inner_meta),"ansible_result":json.dumps(inner_result),"host":"ansible-controller-1","@timestamp":"2026-06-02T00:00:00Z","@version":"1"}; \
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); \
s.connect(("localhost", 5044)); \
s.sendall((json.dumps(event) + "\n").encode("utf-8")); \
s.close(); \
print("sent one simulated ansible finish event to localhost:5044")'

.PHONY: smoke-tcp-json-multi
smoke-tcp-json-multi: ## persistent connection sending 5 events back-to-back
	@command -v python3 >/dev/null || (echo "python3 required for smoke-tcp-json-multi"; exit 1)
	@python3 -c '\
import socket, json, time; \
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); \
s.connect(("localhost", 5044)); \
[s.sendall((json.dumps({"ansible_type":"task","ansible_task":"task-"+str(i),"host":"persistent-test","seq":i}) + "\n").encode("utf-8")) for i in range(5)]; \
time.sleep(0.5); \
s.close(); \
print("sent 5 events on a single persistent connection to localhost:5044")'

# ---- v0.3.5 real Ansible end-to-end ----
# This actually runs ansible-playbook with community.general.logstash
# callback. Opt-in because it needs ansible + python-logstash installed
# on the host running make.

.PHONY: smoke-tcp-json-ansible-real
smoke-tcp-json-ansible-real: ## run a real ansible-playbook against notrouter (requires ansible, community.general)
	@command -v ansible-playbook >/dev/null || (echo "ansible-playbook required - install ansible-core"; exit 1)
	@python3 -c 'import logstash' 2>/dev/null || (echo "python-logstash required - pip install python-logstash"; exit 1)
	@ansible-galaxy collection list community.general >/dev/null 2>&1 || (echo "community.general collection required - ansible-galaxy collection install community.general"; exit 1)
	@rm -rf /tmp/notrouter-ansible-smoke
	@mkdir -p /tmp/notrouter-ansible-smoke
	@printf '%s\n' \
	  '[defaults]' \
	  'callback_whitelist = community.general.logstash' \
	  'callbacks_enabled = logstash' \
	  'host_key_checking = False' \
	  'stdout_callback = default' \
	  '' \
	  '[callback_logstash]' \
	  'server = localhost' \
	  'port = 5044' \
	  'type = ansible' \
	  'pre_command = cat meta.json | tr -d "\\n"' \
	  > /tmp/notrouter-ansible-smoke/ansible.cfg
	@printf '%s\n' \
	  '{' \
	  '  "title": "Notrouter Smoke Test",' \
	  '  "uri": "https://example.com/runs/smoke",' \
	  '  "repo": "https://gitlab.example.com/smoke"' \
	  '}' \
	  > /tmp/notrouter-ansible-smoke/meta.json
	@printf '%s\n' \
	  '---' \
	  '- name: notrouter tcp_json smoke test' \
	  '  hosts: localhost' \
	  '  connection: local' \
	  '  gather_facts: false' \
	  '  tasks:' \
	  '    - name: pretend to do work' \
	  '      ansible.builtin.debug:' \
	  '        msg: "tcp_json smoke task ran"' \
	  '    - name: pretend to do more work' \
	  '      ansible.builtin.command: /bin/true' \
	  '      changed_when: false' \
	  > /tmp/notrouter-ansible-smoke/smoke.yml
	@cd /tmp/notrouter-ansible-smoke && ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i localhost, smoke.yml
	@echo ""
	@echo "Ansible playbook ran. Check notrouter audit log for finish event:"
	@echo "  docker exec notrouter tail -1 /var/log/notrouter/audit.jsonl | python3 -m json.tool | grep -E 'topic|entity|source|ansible_type'"


# ---- pass 3 smoke targets ----
.PHONY: smoke-syslog-tcp-octet
smoke-syslog-tcp-octet: ## RFC6587 octet-counted syslog (correct 59-byte length)
	printf '59 <134>Oct 11 22:14:15 router-fra-01 sshd[1234]: Failed login' | nc -w1 localhost 5514

.PHONY: smoke-failer
smoke-failer: ## event that hits the test_failer plugin (route via test-failure-paths group)
	curl -sS -X POST -H 'Content-Type: application/json' \
	  -d '{"entity":"failtest-1","state":"DOWN","type":"host"}' \
	  http://localhost:8080/webhook/generic

.PHONY: smoke-nagios-rich
smoke-nagios-rich: ## Nagios webhook with output -> attribute extraction
	curl -sS -X POST -H 'Content-Type: application/json' \
	  -d '{"host":"router-fra-01","type":"host","state":"DOWN","output":"PING CRITICAL - 100% packet loss","service":"ping"}' \
	  http://localhost:8080/webhook/nagios

# ---- pass 4 operational targets ----
.PHONY: loadtest
loadtest: ## fire 1000 msg/s for 30s at the webhook receiver
	go run ./cmd/loadtest -url http://localhost:8080/webhook/generic -qps 1000 -duration 30s -concurrency 50

.PHONY: loadtest-light
loadtest-light: ## gentle 100 msg/s for 10s
	go run ./cmd/loadtest -url http://localhost:8080/webhook/generic -qps 100 -duration 10s -concurrency 10

.PHONY: admin-state
admin-state: ## fetch /admin/state (basic auth required)
	curl -sS -u admin:adminadmin http://localhost:9090/admin/state | python3 -m json.tool

.PHONY: admin-deliveries
admin-deliveries: ## fetch recent deliveries
	curl -sS -u admin:adminadmin http://localhost:9090/admin/deliveries | python3 -m json.tool

.PHONY: admin-dedup-clear
admin-dedup-clear: ## panic-button: clear the dedup map
	curl -sS -X POST -u admin:adminadmin http://localhost:9090/admin/dedup/clear

.PHONY: docker-multiarch
docker-multiarch: ## build linux/amd64 + linux/arm64 image
	docker buildx build --platform linux/amd64,linux/arm64 -t notrouter:$(VERSION) .

.PHONY: docker-load
docker-load: ## build local-arch image and load it into docker
	docker buildx build --load -t notrouter:$(VERSION) .

# ---- inner-loop dev workflow (final) ----
# Detects the available container runtime + compose flavor at make time.
# Override either at invocation:  make dev-docker CONTAINER_CMD="podman compose"
#
# Precedence: docker compose -> podman-compose -> podman compose ->
#             docker-compose -> error.
CONTAINER_CMD ?= $(shell \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		echo "docker compose"; \
	elif command -v podman-compose >/dev/null 2>&1; then \
		echo "podman-compose"; \
	elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then \
		echo "podman compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		echo "docker-compose"; \
	else \
		echo "NONE"; \
	fi)

# Containerfile (Podman-native) takes precedence over Dockerfile if both
# exist. Override:  make dev-docker DEV_DOCKERFILE=Dockerfile
DEV_DOCKERFILE ?= $(shell \
	if [ -f Containerfile ]; then echo Containerfile; \
	elif [ -f Dockerfile ]; then echo Dockerfile; \
	else echo Dockerfile; fi)

DEV_SERVICE ?= notrouter
DEV_COMPOSE ?= $(shell \
	if [ -f compose.yaml ]; then echo compose.yaml; \
	elif [ -f docker-compose.yml ]; then echo docker-compose.yml; \
	elif [ -f docker-compose.yaml ]; then echo docker-compose.yaml; \
	else echo compose.yaml; fi)

.PHONY: _dev-docker-preflight
_dev-docker-preflight:
	@if [ "$(CONTAINER_CMD)" = "NONE" ]; then \
		echo "ERROR: no container compose runtime found."; \
		echo "  install one of: docker (with 'docker compose'), podman-compose, podman 4.4+"; \
		echo "  or override:  make dev-docker CONTAINER_CMD=\"podman compose\""; \
		exit 1; \
	fi
	@if [ ! -f "$(DEV_COMPOSE)" ]; then \
		echo "ERROR: no compose file found (looked for compose.yaml, docker-compose.yml, docker-compose.yaml)"; \
		echo "  generate a default with:  make dev-docker-init"; \
		exit 1; \
	fi
	@if [ ! -f "$(DEV_DOCKERFILE)" ]; then \
		echo "ERROR: $(DEV_DOCKERFILE) not found"; \
		exit 1; \
	fi

.PHONY: dev-docker-init
dev-docker-init: ## generate a default compose.yaml if missing
	@set -e; \
	if [ -f compose.yaml ] || [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then \
		echo "compose file already present - skipping"; \
		exit 0; \
	fi; \
	echo "writing compose.yaml (using $(DEV_DOCKERFILE))"; \
	{ \
		echo 'services:'; \
		echo '  notrouter:'; \
		echo '    build:'; \
		echo '      context: .'; \
		echo "      dockerfile: $(DEV_DOCKERFILE)"; \
		echo '    image: notrouter:dev'; \
		echo '    container_name: notrouter'; \
		echo '    restart: unless-stopped'; \
		echo '    ports:'; \
		echo '      - "8080:8080"'; \
		echo '      - "5514:5514/udp"'; \
		echo '      - "5514:5514/tcp"'; \
		echo '      - "9090:9090"'; \
		echo '    volumes:'; \
		echo '      - ./config.yaml:/etc/notrouter/config.yaml:ro'; \
		echo '      - notrouter-creds:/var/lib/notrouter'; \
		echo '      - notrouter-audit:/var/log/notrouter'; \
		echo '    healthcheck:'; \
		echo '      test: ["CMD", "/notrouter", "-version"]'; \
		echo '      interval: 30s'; \
		echo '      timeout: 5s'; \
		echo '      retries: 3'; \
		echo ''; \
		echo 'volumes:'; \
		echo '  notrouter-creds:'; \
		echo '  notrouter-audit:'; \
	} > compose.yaml; \
	echo "wrote compose.yaml"

.PHONY: dev-docker
dev-docker: vet _dev-docker-preflight ## rebuild + recreate container + tail logs (docker or podman)
	@echo ">>> using: $(CONTAINER_CMD), compose=$(DEV_COMPOSE), file=$(DEV_DOCKERFILE)"
	@echo ">>> rebuilding container image..."
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) build $(DEV_SERVICE)
	@echo ">>> recreating container..."
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) up -d --force-recreate $(DEV_SERVICE)
	@echo ">>> tailing logs (ctrl+c stops tailing; container keeps running)"
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) logs -f $(DEV_SERVICE)

.PHONY: dev-docker-restart
dev-docker-restart: _dev-docker-preflight ## recreate without rebuilding the image
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) up -d --force-recreate $(DEV_SERVICE)
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) logs -f $(DEV_SERVICE)

.PHONY: dev-docker-clean
dev-docker-clean: _dev-docker-preflight ## DESTRUCTIVE: stop and remove volumes
	@echo "this will delete creds.json, config-backups/, and audit logs"
	@read -p "type 'yes' to confirm: " ans && [ "$$ans" = "yes" ] || (echo aborted; exit 1)
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) down -v

.PHONY: dev-logs
dev-logs: _dev-docker-preflight ## tail logs of the running container (no recreate)
	$(CONTAINER_CMD) -f $(DEV_COMPOSE) logs -f $(DEV_SERVICE)

# v0.3.0 SMTP smoke test. Sends a synthetic email to localhost:2525
# using stdlib python smtplib. Requires:
#   - notrouter running with receivers.smtp.port_25.enabled = true
#   - listen: ":2525" in the SMTP config
#   - localhost in the allowed_ips list (e.g. "127.0.0.1/32")
#   - "alerts@notrouter.local" in allowed_rcpt_to
.PHONY: smoke-smtp
smoke-smtp:
	@command -v python3 >/dev/null || (echo "python3 required for smoke-smtp"; exit 1)
	@python3 -c '\
import smtplib; \
from email.message import EmailMessage; \
msg = EmailMessage(); \
msg["From"] = "smoke-test@local"; \
msg["To"] = "alerts@notrouter.local"; \
msg["Subject"] = "smoke test from python smtplib"; \
msg.set_content("This is a smoke test body sent via stdlib smtplib.\nLine two.\nLine three."); \
s = smtplib.SMTP("localhost", 2525, timeout=5); \
s.send_message(msg); \
s.quit(); \
print("sent OK to localhost:2525")'

# Multipart variant - sends an HTML+plaintext email like real monitoring
# tools would. Tests the MIME walker in smtp_parse.go.
.PHONY: smoke-smtp-multipart
smoke-smtp-multipart:
	@command -v python3 >/dev/null || (echo "python3 required for smoke-smtp-multipart"; exit 1)
	@python3 -c '\
import smtplib; \
from email.message import EmailMessage; \
msg = EmailMessage(); \
msg["From"] = "checkmk@example.com"; \
msg["To"] = "alerts@notrouter.local"; \
msg["Subject"] = "PROBLEM: Service Filesystem /var WARNING"; \
msg.set_content("Plain text version: filesystem /var is at 89% used.\nThis is the plain part."); \
msg.add_alternative("<html><body><h1>Filesystem WARNING</h1><p>/var is at <b>89%</b> used.</p></body></html>", subtype="html"); \
s = smtplib.SMTP("localhost", 2525, timeout=5); \
s.send_message(msg); \
s.quit(); \
print("sent multipart OK")'
