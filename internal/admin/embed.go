package admin

import "embed"

// uiFS embeds the entire UI tree into the binary. No external static
// directory means simpler ops: one binary, ships everywhere.
//
//go:embed ui/login.html ui/change-password.html ui/dashboard.html
//go:embed ui/static/style.css ui/static/app.js
var uiFS embed.FS
