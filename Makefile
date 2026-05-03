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
smoke-all: smoke-webhook smoke-nagios smoke-syslog-rfc3164 smoke-syslog-rfc5424 smoke-syslog-tcp-octet smoke-syslog-tcp-lf ## fire every smoke target

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
	curl -sS -u admin:admin http://localhost:9090/admin/state | python3 -m json.tool

.PHONY: admin-deliveries
admin-deliveries: ## fetch recent deliveries
	curl -sS -u admin:admin http://localhost:9090/admin/deliveries | python3 -m json.tool

.PHONY: admin-dedup-clear
admin-dedup-clear: ## panic-button: clear the dedup map
	curl -sS -X POST -u admin:admin http://localhost:9090/admin/dedup/clear

.PHONY: docker-multiarch
docker-multiarch: ## build linux/amd64 + linux/arm64 image
	docker buildx build --platform linux/amd64,linux/arm64 -t notrouter:$(VERSION) .

.PHONY: docker-load
docker-load: ## build local-arch image and load it into docker
	docker buildx build --load -t notrouter:$(VERSION) .
