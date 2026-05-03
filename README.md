# notrouter

Multi-protocol notification router. Receives events from webhooks and syslog,
attributes them to a sending entity, normalizes them into a canonical shape,
deduplicates, suppresses, routes by group rules, and dispatches to compile-time
output plugins (Webex, generic webhook, file, stdout).

Single Go binary. Two external dependencies (`gopkg.in/yaml.v3`,
`prometheus/client_golang`). Designed to handle 1000 messages/second sustained
on modest hardware.

## Status

**v0.1.0** — feature-complete for the original brief. End-to-end pipeline
working, validated at 100 msg/s with sub-millisecond p99. Production use is
fine for a single team; multi-tenant features (per-team RBAC, persistent
config UI) are intentionally out of scope.

## Pipeline

```
receivers → entity-resolver → normalizer → dedup → suppressor → router → dispatcher → plugin instances
                                                                                            │
                                                                                       tracker (30m TTL)
```

Each stage runs in its own goroutine pool, communicating through buffered
channels. No persistence — restart wipes in-flight events and dedup state by
design.

## Quick start

```sh
# build & run
make tidy
make dev

# in another terminal: send a test event
make smoke-webhook
make metrics
```

The shipped `config.yaml` accepts events on:
- `:8080` — HTTP webhook receiver (paths `/webhook/nagios`, `/webhook/generic`)
- `:5514/udp` — syslog UDP (RFC3164 + RFC5424)
- `:5514/tcp` — syslog TCP (RFC6587 octet-counted + LF framing, auto-detected)
- `:9090` — admin/metrics (basic auth: `admin`/`admin`)

Events are routed to the `noc-team` group, which delivers to `stdout_debug`
and `file_audit` (writes to `/tmp/notrouter-audit.jsonl`).

## Concepts

### Event — the canonical shape

```go
{
  ID         string             // generated UUID-ish
  Source     string             // "webhook:nagios" | "syslog-udp" | ...
  Entity     string             // who sent this (resolved from profile)
  EntityIP   net.IP             // optional, for CIDR matching
  Topic      string             // what it's about
  Urgency    info|low|medium|high|critical
  Timestamp  time.Time
  Attributes map[string]string  // extracted by profile rules
  Raw        []byte             // original payload
}
```

### Profile — receiver-side parsing rules

Tells the entity resolver and normalizer how to extract data from a specific
source format. Webhook endpoints bind to a named profile; syslog has an
implicit `syslog` profile.

### Group — a named bucket of subscribers

A group like `noc-team` contains a list of plugin instance names. Routing
rules match against events and produce a set of groups; the dispatcher
fans out to each subscribed instance.

### Plugin instance vs plugin type

A *type* is the Go code (e.g. `webex`). An *instance* is a runtime object
configured from YAML (e.g. `webex_noc` pointing at a specific Webex room).
You can have multiple instances of the same type with different configs —
e.g. one Webex instance per team, each with its own webhook URL.

### Suppressor — drop events you never want

Same matcher engine as the router (CIDR / regex / topic / urgency /
attributes), evaluated before routing. Supports time-windowed activation
for maintenance windows. Events that match are dropped, counted, and
optionally logged (rate-limited per rule).

## Configuration

### Receivers and profiles

```yaml
listen:
  webhook: ":8080"
  syslog_udp: ":5514"
  syslog_tcp: ":5514"
  admin: ":9090"

receivers:
  webhook:
    endpoints:
      - path: /webhook/nagios
        profile: nagios
      - path: /webhook/grafana
        profile: grafana

profiles:
  nagios:
    entity:
      from_json: "$.host"            # JSONPath: $.foo.bar[0] supported
    normalize:
      topic: "nagios-{{.json.type}}-{{.json.state | lower}}"
      urgency:
        from_json: "$.state"
        map:
          OK: info
          WARNING: medium
          CRITICAL: critical
          DOWN: high
          UNREACHABLE: high
    attributes:
      msg:
        from_json: "$.output"        # extract Nagios output to Attributes.msg
      service:
        from_json: "$.service"
      source_kind:
        static: "nagios"             # always set this attribute
```

Entity resolution strategies, evaluated in order:
1. `from_json: "$.path"` — JSONPath against parsed body
2. `from_field: "hostname"` — copy from an existing attribute (e.g. parsed syslog hostname)
3. `from_regex: "..."` — regex with optional capture group
4. fallback to source IP

If no strategy succeeds, the event is dropped and logged with reason
`entity_unresolved` (visible in `notrouter_events_dropped_total` metric).

### Dedup

```yaml
dedup:
  ttl: 5m
  key_fields: [entity, topic]   # available: entity, topic, urgency, source, or any attribute name
```

Events with identical key fields seen within the TTL are silently dropped
(counted in metrics, logged at debug level).

### Suppressors

```yaml
suppressors:
  - name: ignore-test-hosts
    match:
      entity_regex: "^test-.*"

  - name: ignore-low-urgency-from-dev
    match:
      entity_ip_in: ["10.99.0.0/16"]
      urgency: ["info", "low"]

  - name: maintenance-db-2026-05-15
    match:
      entity_regex: "^db-prod-.*"
    active:
      from: 2026-05-15T22:00:00Z
      until: 2026-05-15T23:30:00Z   # inactive outside this window

logging:
  suppressor_log_throttle: 60s     # max one log line per rule per 60s
```

A predicate is `AND` across its match fields, `OR` across rules. The same
matcher engine is used by the router.

### Plugin instances

```yaml
plugin_instances:
  webex_noc:
    type: webex
    config:
      webhook_url: "https://webexapis.com/v1/webhooks/incoming/..."
      timeout: "15s"
      rate_limit_grace: "2s"     # added to Retry-After value
      # template: |              # optional - default uses urgency emoji
      #   **{{.Topic}}** on `{{.Entity}}`
    retry:
      attempts: 5                # override default of 3
      backoff: [2s, 5s, 10s, 30s, 60s]

  generic_hook:
    type: webhook
    config:
      webhook_url: "https://hooks.example.com/notify"
      content_type: "application/json"
      headers:
        X-Source: "notrouter"
      template: |
        {"text":"[{{.Urgency}}] {{.Topic}} on {{.Entity}}{{ if .Attributes.msg }} - {{.Attributes.msg}}{{ end }}"}

  file_audit:
    type: file
    config:
      path: /var/log/notrouter/audit.jsonl

  stdout_debug:
    type: stdout
    config: {}
```

Available plugin types (registered at compile time, no runtime loading):

| Type | Purpose |
|---|---|
| `webex` | POST to a Webex Incoming Webhook with markdown body, Retry-After-aware |
| `webhook` | Generic POST with templated body, configurable headers |
| `file` | Append JSON Lines to a file |
| `stdout` | Print JSON to stdout (debugging) |
| `failer` | Always errors (test plugin, exercises retry/partial-delivery paths) |

### Routing

```yaml
groups:
  noc-team:
    subscribers: [webex_noc, file_audit]
  db-admins:
    subscribers: [generic_hook, file_audit]

routing:
  - match:
      entity_ip_in: ["10.1.1.0/24", "10.1.2.0/24"]
    groups: [noc-team]
  - match:
      entity_regex: "^db-.*"
    groups: [db-admins]
  - match: {}                    # catch-all
    groups: [noc-team]
```

Multiple rules can match — group sets are unioned. If two groups subscribe
to the same plugin instance, it receives the event once (not duplicated).

### Dispatch & retries

```yaml
dispatch:
  global_delivery_ttl: 30m       # tracker gives up after this
  default_retry:
    attempts: 3
    backoff: [1s, 5s, 30s]       # last entry repeats if attempts > len
```

Retry semantics:
- **2xx** → success
- **429 with Retry-After** → wait header value + grace, retry (counts against budget)
- **5xx** → wait per backoff, retry
- **Other 4xx / template errors** → fail-fast, no retry
- **Network errors** → wait per backoff, retry

Each plugin instance has its own bounded queue, its own worker goroutine,
and its own retry budget — a slow Webex API never blocks file writes.

### Pipeline tuning

```yaml
pipeline:
  raw_buffer_size: 4096          # receivers → resolver
  normal_buffer_size: 2048       # between mid stages
  instance_buffer_size: 1024     # per-plugin queue
  resolver_workers: 4            # entity-resolver goroutine count
  normalizer_workers: 4          # normalizer goroutine count
```

## Sending events — usage examples

### Generic webhook

```sh
curl -X POST http://localhost:8080/webhook/generic \
  -H 'Content-Type: application/json' \
  -d '{"entity":"router-1","state":"DOWN","type":"host"}'
```

The `generic` profile extracts `entity` from `$.entity`. Topic and urgency
fall back to defaults (`unclassified`, `info`).

### Nagios via webhook (recommended Nagios integration)

In your Nagios `commands.cfg`:

```
define command {
  command_name notify-host-by-notrouter
  command_line /usr/bin/curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d '{"type":"host","host":"$HOSTNAME$","state":"$HOSTSTATE$","output":"$HOSTOUTPUT$","longoutput":"$LONGHOSTOUTPUT$","notification_type":"$NOTIFICATIONTYPE$"}' \
    http://notrouter:8080/webhook/nagios
}

define command {
  command_name notify-service-by-notrouter
  command_line /usr/bin/curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d '{"type":"service","host":"$HOSTNAME$","service":"$SERVICEDESC$","state":"$SERVICESTATE$","output":"$SERVICEOUTPUT$","longoutput":"$LONGSERVICEOUTPUT$"}' \
    http://notrouter:8080/webhook/nagios
}
```

Then bind these commands to your contacts. Same data shape that the
upstream `notify_webhook.py` expected from environment variables, just
delivered via HTTP.

### Syslog UDP (RFC3164 — BSD format)

```sh
echo '<134>Oct 11 22:14:15 router-fra-01 sshd[1234]: Failed login for root' \
  | nc -u -w1 notrouter 5514
```

`<134>` = priority 134 (facility 16, severity 6). The parser extracts:
- `Entity: router-fra-01` (hostname from header)
- `Attributes.app: sshd`, `Attributes.procid: 1234`
- `Attributes.msg: Failed login for root`
- `Topic: syslog-sshd` (default — overridable via profile)
- `Urgency: info` (severity 6 mapping)

### Syslog UDP (RFC5424 — structured format)

```sh
echo '<165>1 2026-05-02T08:00:00Z router-fra-01 sshd 1234 ID47 - Failed login attempt' \
  | nc -u -w1 notrouter 5514
```

Same extraction; additionally `Attributes.msgid: ID47`.

### Syslog TCP

```sh
# RFC6587 octet-counted (preferred for TCP)
printf '59 <134>Oct 11 22:14:15 router-fra-01 sshd[1234]: Failed login' \
  | nc -w1 notrouter 5514

# Or LF-terminated (also supported, auto-detected per message)
echo '<134>Oct 11 22:14:15 router-fra-01 sshd[1234]: Failed login' \
  | nc -w1 notrouter 5514
```

If a syslog message can't be parsed (no PRI, malformed header), it's still
forwarded as a normal event with `topic: syslog-malformed` and the raw
body in attributes — visibility-first, not strict.

## Operations

### Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | 200 ok / 503 + JSON if degraded |
| `GET /metrics` | none | Prometheus exposition |
| `GET /version` | none | build version + commit |
| `GET /admin/state` | basic | dedup size, queue depths, pending tracker entries |
| `GET /admin/deliveries` | basic | last 200 finalized deliveries with per-subscriber state |
| `POST /admin/dedup/clear` | basic | wipe dedup map (panic button after misconfig) |

`/healthz` reports `degraded` when:
- any plugin instance queue is ≥90% full
- the tracker has more than 10000 pending deliveries
- the dedup map has more than 1M entries

### Make targets

```sh
make build              # static binary in bin/
make dev                # go run with config.yaml
make test               # go test -race ./...
make vet
make docker             # local-arch image
make docker-multiarch   # buildx for linux/amd64+arm64
make clean

# admin shortcuts
make health             # /healthz
make metrics            # /metrics filtered to notrouter_*
make admin-state        # pretty-printed /admin/state
make admin-deliveries   # pretty-printed /admin/deliveries
make admin-dedup-clear  # POST /admin/dedup/clear

# smoke targets
make smoke-webhook              # generic webhook
make smoke-nagios               # nagios-shaped webhook
make smoke-nagios-rich          # nagios with output for attribute extraction
make smoke-syslog-rfc3164       # BSD-format syslog
make smoke-syslog-rfc5424       # structured syslog
make smoke-syslog-tcp-octet     # RFC6587 octet-counted TCP
make smoke-syslog-tcp-lf        # LF-terminated TCP
make smoke-failer               # routes to a group with the failer plugin
make smoke-all                  # fire every smoke target

# load testing
make loadtest                   # 1000 msg/s for 30s
make loadtest-light             # 100 msg/s for 10s
```

### Metrics

Prometheus metrics, all prefixed `notrouter_`:

| Metric | Labels | Meaning |
|---|---|---|
| `events_received_total` | `source` | Events arriving at any receiver |
| `events_resolved_total` | `source` | Events with successful entity resolution |
| `events_dropped_total` | `reason` | Drops by reason (`entity_unresolved`, `duplicate`, `no_subscribers`) |
| `events_dispatched_total` | — | Events that reached the dispatcher |
| `suppressed_total` | `rule` | Per-rule suppressor hit count |
| `delivery_outcomes_total` | `instance`, `state` | Per-plugin per-event outcomes |
| `delivery_final_total` | `state` | Per-event final state (`delivered`/`partial`/`failed`/`expired`) |
| `instance_queue_full_total` | `instance` | Times an event was dropped because plugin queue was full |

The `partial` state means some subscribers succeeded and others failed.
The `expired` state means the 30-min global TTL fired before all
subscribers reached terminal state.

### Logging

Structured logging via `slog`. Level configured via `logging.level` in YAML
(`debug` | `info` | `warn` | `error`). At `info` you get pipeline lifecycle
events, suppressor drops (rate-limited), and `delivery final` summaries.
At `debug` you also get per-event drops (dedup, suppressor) and per-extractor
miss reasons.

## Adding a new output plugin

1. Create `internal/plugins/myplugin/myplugin.go` implementing `plugins.Plugin`:

```go
package myplugin

import (
    "context"
    "github.com/scuq/notrouter/internal/event"
    "github.com/scuq/notrouter/internal/plugins"
)

type plugin struct{}

func (p *plugin) Type() string { return "myplugin" }

func (p *plugin) New(name string, cfg map[string]interface{}) (plugins.Instance, error) {
    return &instance{name: name}, nil
}

type instance struct{ name string }

func (i *instance) Name() string { return i.name }
func (i *instance) Send(ctx context.Context, ev *event.Event) error { /* ... */ }
func (i *instance) Close() error { return nil }

func init() { plugins.Register(&plugin{}) }
```

2. Add a blank import in `cmd/notrouter/main.go`:

```go
_ "github.com/scuq/notrouter/internal/plugins/myplugin"
```

3. Reference it in YAML:

```yaml
plugin_instances:
  my_instance:
    type: myplugin
    config: { ... }
```

For HTTP-based plugins, see `internal/plugins/httpsink/` for a reusable
client with Retry-After parsing, status classification (retryable vs
not), connection pooling, and proxy/TLS-skip support.

## Project layout

```
cmd/
  notrouter/main.go          binary entry point, pipeline wiring
  loadtest/main.go           QPS load tester
internal/
  admin/                     /healthz + /admin/* HTTP server, probe interfaces
  auth/                      basic auth helper
  config/                    YAML schema + load + validation
  dedup/                     in-memory TTL map + sweeper
  dispatch/                  fan-out, per-instance worker, retry, delivery tracker
  event/                     canonical Event type
  jsonpath/                  tiny JSONPath subset ($.foo.bar[0])
  logging/                   slog setup
  metrics/                   Prometheus counters
  parser/
    syslog.go                RFC3164 + RFC5424 parser
    entity.go                profile-driven entity resolver
    normalize.go             text/template + JSON-path normalizer
  pipeline/                  Stage interface, channel topology, predicate engine
  plugins/
    plugin.go                plugin registry
    template.go              shared template compiler/renderer
    httpsink/                shared HTTP client for webhook-style plugins
    webex/                   Webex with Retry-After
    webhook/                 generic webhook
    file/                    JSONL file writer
    stdout/                  stdout printer
    failer/                  always-fails test plugin
  receivers/                 webhook, syslog UDP, syslog TCP
  router/                    group resolution
  suppress/                  predicate-based suppression with throttled logging
  version/                   build-time injected version/commit
```

## Performance

Validated on an arm64 VM at 100 msg/s sustained:
- p50 latency: 433µs
- p95 latency: 732µs
- p99 latency: 1.09ms
- 0 failures, 0 producer overruns

Run `make loadtest` to validate 1000 msg/s on your hardware. The hot path
is in-memory only (parse, regex, map lookups, channel sends); the actual
ceiling is bound by network egress to plugins, not pipeline overhead.

## Limitations & non-goals

- **No persistence.** Events in flight at restart are lost. Dedup state is
  volatile. Acceptable for a notification router; if you need durability,
  put a persistent queue in front.
- **Single tenant.** No per-team RBAC or admin UI. Built for a single ops
  team operating one instance.
- **Compile-time plugins only.** No `.so` loading, no Lua, no scripting.
  Adding a plugin requires recompiling and redeploying the binary. This is
  intentional — runtime plugin loading has been a long source of pain in
  monitoring tools and we don't want to repeat it.
- **No SMTP receiver, no SNMP traps.** Both were in scope originally and
  deferred. The architecture supports adding them as new receiver types
  without touching the pipeline.
- **Static admin auth.** `admin:admin` by default, configurable in YAML.
  Suitable for an internal-network deployment behind a reverse proxy or
  service mesh; not suitable for direct internet exposure.

## License

[your choice]