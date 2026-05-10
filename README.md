# notrouter

Multi-protocol notification router. Receives events from webhooks, syslog, and
SMTP, attributes them to a sending entity, normalizes them into a canonical
shape, deduplicates, suppresses, routes by group rules, and dispatches to
compile-time output plugins (Webex, generic webhook, file, stdout).

Single Go binary. External dependencies kept minimal:
- `gopkg.in/yaml.v3` (config)
- `github.com/prometheus/client_golang` (metrics)
- `golang.org/x/crypto` (admin password hashing)
- `github.com/emersion/go-smtp` (SMTP receiver)

Designed to handle 1000 messages/second sustained on modest hardware.

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
- `:8080` — HTTP webhook receiver (paths `/webhook/nagios`, `/webhook/generic`, `/webhook/grafana`)
- `:5514/udp` — syslog UDP (RFC3164 + RFC5424)
- `:5514/tcp` — syslog TCP (RFC6587 octet-counted + LF framing, auto-detected)
- `:2525` — SMTP receiver (CheckMK and generic email-shaped notifications)
- `:9090` — admin/metrics web UI (basic auth seeded with `admin`/`admin`)

Out of the box, events route to a `test-channel` group containing a Webex
test space and a `file_audit` plugin (writes to
`/var/log/notrouter/audit.jsonl`). Replace the placeholder Webex webhook URL
with a real one before starting.

## Concepts

### Event — the canonical shape

```go
{
  ID         string             // generated UUID-ish
  Source     string             // "webhook:nagios" | "syslog-udp" | "smtp-25" | ...
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
implicit `syslog` profile; SMTP events go through an optional mail-parser
chain that selects a profile per message.

### Mail parser — vendor-aware SMTP parsing

For SMTP events, mail parsers run before profile selection. Each parser:
1. Matches on subject prefix (e.g. `Check_MK: `)
2. Runs a sequence of YAML-defined extractors against the email
3. Selects which profile to apply downstream

This is how vendor-specific shapes (CheckMK, future Grafana SMTP, etc.) get
turned into structured events without per-vendor Go code. Adding a new
vendor parser is a YAML edit, not a recompile.

### Origin ID and source aliases

Every event has an `origin_id` attribute identifying the sender:
- SMTP: the From: address (e.g. `cmk@2f4aa25ce51e`)
- Webhook: the client IP (post-XFF resolution if behind a trusted proxy)
- Syslog: the source IP

A `source_aliases` map turns raw origin IDs into human-readable names
(`cmk@2f4aa25ce51e` → `checkmk-prod`). Templates display the alias if
present, falling back to raw origin_id otherwise. Useful when running
multiple monitoring instances where the raw origin_id is a docker
container ID or random hostname.

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

### Strict YAML mode

By default, notrouter rejects unknown YAML fields at load time. This
catches typos that would otherwise silently disable rules
(`urgency.from_field` misspelled, profile name slightly off, etc.).

If you need to load a config with unknown fields (e.g. during a migration),
set `NOTROUTER_LAX_YAML=1` as an env var. The error message names which
field tripped the check, so fixing is usually a one-line edit.

### Receivers and profiles

```yaml
listen:
  webhook: ":8080"
  syslog_udp: ":5514"
  syslog_tcp: ":5514"
  admin: ":9090"

receivers:
  webhook:
    # Optional. When notrouter sits behind a reverse proxy, list the
    # proxy's network here so X-Forwarded-For headers are trusted and
    # walked to find the real client IP. Direct (non-proxied) connections
    # ignore XFF entirely - prevents spoofing.
    trusted_proxies:
      - "10.89.0.0/16"

    endpoints:
      - path: /webhook/nagios
        profile: nagios
      - path: /webhook/grafana
        profile: grafana

  smtp:
    port_25:
      enabled: true
      listen: ":2525"            # use 25 in production with appropriate caps
      hostname: "notrouter.example.com"
      allowed_ips:
        - "127.0.0.1/32"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
      allowed_rcpt_to:
        - "alerts@notrouter.example.com"
      allowed_from: []           # empty = no sender restriction
      max_message_bytes: 1048576

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
        from_json: "$.output"
      service:
        from_json: "$.service"
      source_kind:
        static: "nagios"
```

Entity resolution strategies, evaluated in order:
1. `from_json: "$.path"` — JSONPath against parsed body
2. `from_field: "hostname"` — copy from an existing attribute
3. `from_regex: "..."` — regex with optional capture group
4. fallback to source IP

If no strategy succeeds, the event is dropped and logged with reason
`entity_unresolved` (visible in `notrouter_events_dropped_total` metric).

### Mail parsers

Vendor-specific SMTP parsers. First match wins. If no parser matches, the
event flows through the `smtp_generic` profile.

```yaml
mail_parsers:
  - name: checkmk
    match:
      subject_prefix: "Check_MK: "
    profile: checkmk
    extract:
      # Body labeled fields - "Label: value" lines
      - type: from_body_kvline
        label: "Host"
        attribute: host
      - type: from_body_kvline
        label: "Service"
        attribute: service
      - type: from_body_kvline
        label: "Event"
        attribute: event_raw

      # Multi-line label - captures everything from "Perfdata:" to EOF
      - type: from_body_after_label
        label: "Perfdata"
        attribute: perfdata

      # Email headers
      - type: from_header
        header: "Message-Id"
        attribute: message_id

      # Try each alternative until one matches; first-match-wins
      - type: dispatch_first_match
        alternatives:
          - type: from_attribute_regex
            source: event_raw
            pattern: '^(?P<previous_state>\w+)\s+->\s+(?P<state>\w+)\s*$'
          - type: from_attribute_regex
            source: event_raw
            pattern: '^(?P<event_kind>.+?)\s+\((?P<state>\w+)\)\s*$'

      # Computed attribute via Go template
      - type: from_template
        attribute: type
        template: '{{ if .service }}service{{ else }}host{{ end }}'
```

Available extractor types:

| Type | Required fields | What it does |
|---|---|---|
| `from_subject_regex` | `pattern` | Regex with named captures against the email subject |
| `from_attribute_regex` | `source`, `pattern` | Regex against an existing attribute |
| `from_body_kvline` | `label`, `attribute` | Match a single `Label:` line, capture trimmed value |
| `from_body_after_label` | `label`, `attribute` | Capture everything after `Label:` to end of body (multi-line) |
| `from_header` | `header`, `attribute` | Lookup an RFC 5322 email header |
| `from_template` | `template`, `attribute` | Render a Go template against existing attributes |
| `dispatch_first_match` | `alternatives` | Try each sub-extractor; stop at first that matches |

Validation happens at load time. Bad regex, malformed templates, or
unknown extractor types fail the startup, not at request time.

### Source aliases

```yaml
source_aliases:
  # SMTP origin (From: address)
  "cmk@2f4aa25ce51e":   "checkmk-prod"
  "cmk@a1b2c3d4e5f6":   "checkmk-staging"

  # Webhook origin (real client IP, post-XFF resolution)
  "10.21.146.1":       "nagios-main"
  "10.21.146.2":       "nagios-edge"
```

When an event's `origin_id` matches a key here, `origin_alias` is set on
the event. Used by templates (e.g. the Webex source-line footer) and
visible in audit logs and the replay UI.

Optional. Missing section means no aliasing.

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
      until: 2026-05-15T23:30:00Z

logging:
  suppressor_log_throttle: 60s
```

A predicate is `AND` across its match fields, `OR` across rules. The same
matcher engine is used by the router.

### Trace mode (debug)

For diagnosing receiver issues, trace mode captures raw incoming events to
disk before any pipeline processing. Default disabled — when enabled,
notrouter logs a periodic warning to remind operators it's still on.

```yaml
trace:
  enabled: true
  output_dir: /var/log/notrouter/trace
  reminder_interval: 1h            # warn this often when enabled
  receivers:
    smtp:
      enabled: true
      max_files: 50                # one .eml per message; oldest deleted at limit
    syslog_udp:
      enabled: false
      max_bytes_per_file: 10485760 # 10 MiB rotation
      max_files: 3
    syslog_tcp:
      enabled: false
    webhook:
      enabled: false
```

SMTP traces are one .eml file per message. Syslog and webhook traces are
JSONL with size-based rotation. Output dir gets `0700` perms; files
`0600`. Sensitive data (auth headers, alert details) is written cleartext —
mount a separate volume and exclude from backups.

### Plugin instances

```yaml
plugin_instances:
  webex_noc:
    type: webex
    config:
      webhook_url: "https://webexapis.com/v1/webhooks/incoming/..."
      timeout: "15s"
      rate_limit_grace: "2s"     # added to Retry-After value
      template: |
        {{- if eq .Attributes.notiftype "RECOVERY" -}}✅
        {{- else if eq .Urgency "critical" -}}❌
        {{- else -}}ℹ️
        {{- end }} {{.Attributes.state}} · `{{.Entity}}`
        {{- if .Attributes.service }} · {{.Attributes.service}}{{ end }}
        {{- if .Attributes.msg }} · `{{.Attributes.msg}}`{{ end }}

        <small><i>via {{ .Attributes.source_kind }} ·
          {{- if .Attributes.origin_alias }} {{ .Attributes.origin_alias }}
          {{- else if .Attributes.origin_id }} {{ .Attributes.origin_id }}
          {{- end }} · {{ .Source }}</i></small>
    retry:
      attempts: 5
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
  test-channel:
    subscribers: [webex_test, file_audit]
  noc-team:
    subscribers: [webex_noc, file_audit]
  db-admins:
    subscribers: [generic_hook, file_audit]

routing:
  - match: {}                       # catch-all
    groups: [test-channel]

  - match:
      topic:
        - "nagios-host-down"
        - "nagios-host-up"
        - "checkmk-service-crit"
    groups: [noc-team]

  - match:
      entity_regex: "^db-.*"
    groups: [db-admins]
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
  resolver_workers: 4
  normalizer_workers: 4
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

### Nagios via webhook

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

Then bind these commands to your contacts.

### CheckMK via SMTP

CheckMK sends notifications via email by default. Point CheckMK's
notification rule at notrouter's SMTP receiver:

In CheckMK: Setup → Events → Notifications → add rule with method
"asciimail" → set the SMTP server to `notrouter:2525` and the recipient
to one of your `allowed_rcpt_to` values (e.g. `alerts@notrouter.local`).

Notrouter's CheckMK mail parser handles:
- Service state transitions (`OK -> CRIT`, `CRIT -> OK`, etc.)
- Host state transitions (`UP -> DOWN`, etc.)
- Lifecycle events: Acknowledged, Downtime Start/End, Flapping Start/Stop

Topic format: `checkmk-<service|host>-<state-lower>` (e.g.
`checkmk-service-crit`, `checkmk-host-down`).

### Generic SMTP

Any email sent to an `allowed_rcpt_to` address gets the `smtp_generic`
profile. Subject and body are extracted as attributes; topic is hardcoded
to `smtp` (filter via routing if you don't want these in your channels).

```sh
echo "test alert body" | mail -s "test alert" alerts@notrouter.local
```

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

### Admin web UI

`/admin/ui` exposes a small set of pages for runtime inspection and
configuration:

| Path | Purpose |
|---|---|
| `/admin/ui/` | Dashboard (queue depths, dedup size, instance status) |
| `/admin/ui/config` | YAML editor with validate/save/reload |
| `/admin/ui/logs` | Recent log lines (in-memory ring buffer) |
| `/admin/ui/test` | Send synthetic events through the pipeline |
| `/admin/ui/replay` | Browse audit log entries; analyze how routing/dedup/suppression would handle each |
| `/admin/ui/tokens` | Manage admin user passwords |
| `/admin/ui/webhook-keys` | Manage bearer tokens for webhook endpoints |

Initial credentials: `admin`/`admin`. The UI forces a password change on
first login. Sessions last `auth.admin.session_ttl` (default 2h).

### Replay UI / routing analyzer

The replay page is a debugging tool. Pick any event from the audit log and
see, without sending real traffic:

- Whether suppression would match (and which rule)
- Whether dedup would consider it a duplicate (read-only check)
- Which routing rules match, and what subscribers would receive it
- Final subscriber list

Useful when changing routing rules — verify against historical events
before going live.

The same logic is exposed via the API for scripting:

```sh
# Synthetic event
curl -s -u admin:PW -X POST http://localhost:9090/admin/api/routing/analyze \
  -H 'Content-Type: application/json' \
  -d '{"event":{"topic":"checkmk-host-down","entity":"TEST","urgency":"high","attributes":{"state":"DOWN","type":"host","source_kind":"checkmk"}}}'

# Real audit entry
curl -s -u admin:PW -X POST http://localhost:9090/admin/api/routing/analyze \
  -H 'Content-Type: application/json' \
  -d '{"audit_id":"20260509T084146-0f6509b80b55d594"}'
```

### HTTP endpoints

| Path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | 200 ok / 503 + JSON if degraded |
| `GET /metrics` | none | Prometheus exposition |
| `GET /version` | none | build version + commit |
| `GET /admin/state` | basic | dedup size, queue depths, pending tracker entries |
| `GET /admin/deliveries` | basic | last 200 finalized deliveries with per-subscriber state |
| `GET /admin/api/audit/recent` | basic | last N audit entries (`?limit=50&filter=substring`) |
| `POST /admin/api/routing/analyze` | basic | dry-run analyzer (synthetic event or audit_id) |
| `POST /admin/dedup/clear` | basic | wipe dedup map |

`/healthz` reports `degraded` when:
- any plugin instance queue is ≥90% full
- the tracker has more than 10000 pending deliveries
- the dedup map has more than 1M entries

### Audit log

The default config writes every dispatched event to
`/var/log/notrouter/audit.jsonl` via the `file_audit` plugin. Each line
is one JSON object containing the full normalized event.

Useful for postmortems, compliance review, and as the data source for
the replay UI. Recommended: rotate via your platform's tools (logrotate,
journald with size limits, or a sidecar log shipper).

### Make targets

```sh
make build              # static binary in bin/
make dev                # go run with config.yaml
make dev-docker         # build + restart container
make test               # go test -race ./...
make vet
make docker             # local-arch image
make docker-multiarch   # buildx for linux/amd64+arm64
make clean

# admin shortcuts
make health
make metrics
make admin-state
make admin-deliveries
make admin-dedup-clear

# smoke targets
make smoke-webhook
make smoke-nagios
make smoke-nagios-rich
make smoke-syslog-rfc3164
make smoke-syslog-rfc5424
make smoke-syslog-tcp-octet
make smoke-syslog-tcp-lf
make smoke-smtp                 # send a synthetic email through SMTP receiver
make smoke-failer
make smoke-all

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
client with Retry-After parsing, status classification, connection
pooling, and proxy/TLS-skip support.

## Adding a new mail parser (no Go required)

For a new SMTP source vendor, write a parser entry under `mail_parsers:`
in YAML. Pick a unique `subject_prefix` for matching, and chain the
extractor primitives to pull what you need from the email.

The CheckMK parser in the shipped config is a good reference. Common
patterns:

- `Label: value` body lines → `from_body_kvline`
- Multi-line tail values → `from_body_after_label`
- Subject parsing → `from_subject_regex` with named captures
- Branching on attribute shape → `dispatch_first_match` with two regex
  alternatives
- Computed attributes (e.g. derive `notiftype` from `state`) → `from_template`

Validation is at startup. A new parser config either loads cleanly or
notrouter refuses to start with an error pointing at the bad extractor.

## Project layout

```
cmd/
  notrouter/main.go          binary entry point, pipeline wiring
  loadtest/main.go           QPS load tester
internal/
  admin/                     /healthz + /admin/* HTTP server, web UI, probes
  analyzer/                  routing/suppress/dedup dry-run logic + audit reader
  auth/                      basic auth helper, session/credential store
  config/                    YAML schema + load + validation (strict by default)
  dedup/                     in-memory TTL map + sweeper
  dispatch/                  fan-out, per-instance worker, retry, delivery tracker
  event/                     canonical Event type
  jsonpath/                  tiny JSONPath subset ($.foo.bar[0])
  logging/                   slog setup, in-memory ring buffer for /admin/ui/logs
  metrics/                   Prometheus counters
  parser/
    syslog.go                RFC3164 + RFC5424 parser
    entity.go                profile-driven entity resolver
    normalize.go             text/template + JSON-path normalizer, alias resolver
  parsers/                   mail parser framework (CheckMK + future vendors)
  pipeline/                  Stage interface, channel topology, predicate engine
  plugins/
    plugin.go                plugin registry
    template.go              shared template compiler/renderer
    httpsink/                shared HTTP client for webhook-style plugins
    webex/                   Webex with Retry-After handling
    webhook/                 generic webhook
    file/                    JSONL file writer
    stdout/                  stdout printer
    failer/                  always-fails test plugin
  receivers/
    webhook.go               HTTP webhook receiver, XFF-aware origin extraction
    syslog_udp.go            UDP syslog receiver
    syslog_tcp.go            TCP syslog receiver (RFC6587 + LF, auto-detect)
    smtp.go                  SMTP receiver (port 25, allowlist-based)
    proxy_trust.go           trusted-proxy XFF walker
  router/                    group resolution
  suppress/                  predicate-based suppression with throttled logging
  trace/                     debug capture of raw incoming events to disk
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
- **Single tenant.** No per-team RBAC. Built for a single ops team
  operating one instance.
- **Compile-time plugins only.** No `.so` loading, no Lua, no scripting.
  Adding a plugin requires recompiling and redeploying the binary. This is
  intentional — runtime plugin loading has been a long source of pain in
  monitoring tools and we don't want to repeat it.
- **No SNMP traps.** Architecture supports adding SNMP as a new receiver
  type without touching the pipeline; not yet implemented.
- **SMTP receiver is plain port 25.** No STARTTLS, no AUTH yet. Suitable
  for an internal-network-only deployment. Port 587 + AUTH + STARTTLS is
  on the roadmap.
- **Admin auth is local-only.** Built-in user/password store with bcrypt;
  OIDC/SSO integration is on the roadmap.

## License

None.