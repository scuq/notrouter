package version

// Version is the human-readable build identifier; override at build time via:
//   go build -ldflags "-X github.com/scuq/notrouter/internal/version.Version=v1.2.3"
var Version = "dev"

// Commit is the git commit hash; override at build time the same way.
var Commit = "unknown"
