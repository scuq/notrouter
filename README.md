# notrouter

Multi-protocol notification router.

## Pipeline

```
receivers -> entity-resolver -> normalizer -> dedup -> suppressor -> router -> dispatcher -> plugin instances
                                                                                                  |
                                                                                              tracker (30m TTL)
```

## Status: Pass 1 (scaffolding)

Pipeline runs end-to-end. Stub parsers and stub Webex plugin. File and stdout
plugins are functional. Real syslog/RFC parsing arrives in pass 2; real entity
resolution + normalization in pass 3; real Webex HTTP in pass 6.

## Quick start

```sh
make tidy
make dev

# in another terminal
make smoke-webhook
make smoke-syslog
make metrics
make health
```

## Adding a plugin

1. Create `internal/plugins/<name>/<name>.go` implementing `plugins.Plugin`.
2. Call `plugins.Register(&plugin{})` from the package's `init()`.
3. Blank-import the package in `cmd/notrouter/main.go`.

Plugins are compile-time only - no runtime loading.

## Dependencies

- `gopkg.in/yaml.v3` - config
- `github.com/prometheus/client_golang` - metrics
