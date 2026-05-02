# notrouter

A small notification router in Go: receive events from one or more sources, dispatch them to one or more sinks based on topic and severity rules.

## Build & run

```sh
make build               # → bin/notrouter (embeds VERSION + COMMIT)
make build VERSION=v1.0  # tag a build
make run                 # go run ./cmd/notrouter
make test                # go test -race ./...
make docker              # build container image
./bin/notrouter -version
./bin/notrouter -config=./config.yaml
```

A multi-stage `Dockerfile` produces a distroless image; `make docker` builds `notrouter:$(VERSION)`. `.github/workflows/ci.yml` runs `vet`/`build`/`test -race` on every push and PR. Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`, which runs `goreleaser` to build cross-platform archives + checksums and publish a GitHub Release.

## Concepts

- **Source** — accepts events. Currently: `http` (POST `/notify` with JSON `{topic, message, severity?, time?}`), `stdin` (one JSON event per line; closing stdin shuts the router down).
- **Sink** — delivers events. Currently: `stdout`, `file`, `webhook`, `smtp`.
- **Route** — a topic glob (`alert.*`) plus optional `min_severity`, mapping to a list of sink names.
- **Worker** — every sink runs behind a buffered queue + goroutine, so a slow sink can't block its peers.
- **Metrics** — Prometheus-style counters and a delivery-latency histogram at `/metrics`. `/healthz` returns 503 with JSON `{status: "degraded", queues: [...]}` if any sink queue is ≥90% full.

If no routes are defined, every event fans out to every sink (fallback). Otherwise, events that match no route are counted as `unmatched` and dropped.

## Config

```yaml
listen: ":8080"          # default HTTP source listen address (used if `sources:` is empty)

admin:
  listen: ":9090"        # /metrics + /healthz; omit to disable

sources:
  - name: public
    type: http
    listen: ":8080"
  - name: internal
    type: http
    listen: ":8081"
    bearer_token: "s3cret"          # require Authorization: Bearer s3cret
    tls_cert: "/etc/notrouter/tls/server.crt"
    tls_key:  "/etc/notrouter/tls/server.key"
    allowed_topics: ["audit.*"]     # 403 for any topic outside the allowlist

sinks:
  - name: console
    type: stdout
  - name: log
    type: file
    path: ./notrouter.log
  - name: oncall
    type: smtp
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: alerts@example.com
    smtp_pass: "..."
    from: alerts@example.com
    to: [oncall@example.com]
    subject: "[{{.Severity}}] {{.Topic}}"   # optional template
    body: |                                  # optional template
      Topic: {{.Topic}}
      Severity: {{.Severity}}
      Message: {{.Message}}

  - name: hook
    type: webhook
    url: "https://example.com/hook"
    auth_token: "secret"      # sent as Authorization: Bearer <token>
    hmac_secret: "topsecret"  # body is HMAC-SHA256 signed
    hmac_header: "X-Hub-Signature-256"   # default "X-Signature"
    content_type: "application/json"
    template: |               # optional Go text/template; default is the full Event JSON
      {"text":"[{{.Severity}}] {{.Topic}}: {{.Message}}"}
    max_retries: 3            # exponential backoff up to 5s
    queue_size: 128           # default 64

routes:
  - topic: "alert.*"          # path.Match glob
    dedup_window: "30s"       # suppress identical {topic,message} within this window
    sinks: [console, log, hook]
  - topic: "*"
    min_severity: "error"     # debug < info < warn < error/high < critical
    rate_per_sec: 5           # token bucket; events over this rate are dropped
    rate_burst: 5             # default = int(rate_per_sec)
    sinks: [hook]
  - topic: "info.*"
    sinks: [console]
  - topic: "noisy.*"
    group_window: "30s"        # batch events sharing group_by into a digest
    group_by: "{{.Topic}}"     # default; templated against the Event
    sinks: [console]
```

## Sending events

```sh
# HTTP source
curl -X POST http://localhost:8080/notify \
  -d '{"topic":"alert.fire","message":"server on fire","severity":"critical"}'

# stdin source
printf '%s\n' \
  '{"topic":"alert.fire","message":"FIRE","severity":"critical"}' \
  '{"topic":"info.boot","message":"ready"}' \
  | notrouter -config=stdin-only.yaml
```

Webhook sinks receive the full event JSON (`topic`, `message`, `severity`, `time`) by default, or whatever the configured `template:` renders.

## Operational notes

- **Graceful shutdown** — on SIGINT/SIGTERM, sources stop accepting new events, the router drains pending events, then sink workers drain their queues before exit.
- **Backpressure** — sink queues are bounded; `Submit` is non-blocking and increments `notrouter_failed_total{sink=...}` on full. HTTP source returns 503 when its accept buffer is full.
- **Durability** — none. Events are in-memory only; on crash, in-flight events are lost.
- **HTTP source limits** — incoming `/notify` request bodies are capped at 1 MiB; over-sized requests get HTTP 400.
- **TLS** — set `tls_cert:` + `tls_key:` on an HTTP source to terminate TLS.
- **Topic allowlist** — `allowed_topics:` (path-glob list) on a source rejects events outside the list with HTTP 403.
- **Outbound webhook signing** — set `hmac_secret:` on a webhook sink to attach an HMAC-SHA256 of the request body in `X-Signature` (or `hmac_header:`).
- **Silencing** — POST/GET `/silences` on the admin listener:
  ```sh
  curl -X POST localhost:9090/silences -d '{"topic":"alert.*","duration":"30m"}'
  curl localhost:9090/silences
  ```
  Matching events are dropped before routing and counted as `notrouter_silenced_total{topic=...}`. Silences expire by TTL; no manual delete.

## Layout

```
cmd/notrouter/        # main
internal/admin/       # /metrics + /healthz HTTP server
internal/config/      # YAML loading + validation
internal/metrics/     # atomic counters + text rendering
internal/router/      # topic + severity dispatch
internal/sink/        # Sink interface, stdout/file/webhook + per-sink Worker
internal/source/      # Source interface, HTTP source, fan-in
```
