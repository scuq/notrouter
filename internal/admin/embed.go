package admin

import "embed"

//go:embed ui/login.html ui/change-password.html ui/dashboard.html ui/config.html ui/logs.html ui/test.html ui/tokens.html ui/webhook_keys.html
//go:embed ui/static/style.css ui/static/app.js ui/static/logs.js ui/static/config.js ui/static/test.js ui/static/tokens.js ui/static/webhook_keys.js
var uiFS embed.FS
