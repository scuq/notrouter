package admin

import "embed"

//go:embed ui/login.html ui/change-password.html ui/dashboard.html ui/config.html ui/logs.html
//go:embed ui/static/style.css ui/static/app.js ui/static/logs.js
var uiFS embed.FS
