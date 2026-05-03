package admin

import (
	"crypto/subtle"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/logbuffer"
	"github.com/scuq/notrouter/internal/version"
)

type uiHandler struct {
	tmplLogin    *template.Template
	tmplDash     *template.Template
	tmplChangePw *template.Template
	tmplConfig   *template.Template
	tmplLogs     *template.Template
	staticFS     http.FileSystem
	store        *SessionStore
	creds        credsAccessor
	probes       Probes
	ttl          time.Duration
	log          *slog.Logger

	configPath string
	loadedHash string
	links      map[string]string
	logs       *logbuffer.Buffer
}

type credsAccessor interface {
	Verify(plain string) bool
	MustChange() bool
	UpdatedAt() time.Time
	SetPassword(newPlain string) error
}

func newUIHandler(
	store *SessionStore,
	creds credsAccessor,
	probes Probes,
	ttl time.Duration,
	log *slog.Logger,
	configPath, loadedHash string,
	links map[string]string,
	logs *logbuffer.Buffer,
) (*uiHandler, error) {
	loginTpl, err := template.ParseFS(uiFS, "ui/login.html")
	if err != nil {
		return nil, err
	}
	dashTpl, err := template.ParseFS(uiFS, "ui/dashboard.html")
	if err != nil {
		return nil, err
	}
	cpwTpl, err := template.ParseFS(uiFS, "ui/change-password.html")
	if err != nil {
		return nil, err
	}
	configTpl, err := template.ParseFS(uiFS, "ui/config.html")
	if err != nil {
		return nil, err
	}
	logsTpl, err := template.ParseFS(uiFS, "ui/logs.html")
	if err != nil {
		return nil, err
	}
	staticSub, err := fs.Sub(uiFS, "ui/static")
	if err != nil {
		return nil, err
	}
	return &uiHandler{
		tmplLogin:    loginTpl,
		tmplDash:     dashTpl,
		tmplChangePw: cpwTpl,
		tmplConfig:   configTpl,
		tmplLogs:     logsTpl,
		staticFS:     http.FS(staticSub),
		store:        store,
		creds:        creds,
		probes:       probes,
		ttl:          ttl,
		log:          log,
		configPath:   configPath,
		loadedHash:   loadedHash,
		links:        links,
		logs:         logs,
	}, nil
}

func (h *uiHandler) register(mux *http.ServeMux) {
	mux.Handle("/admin/ui/static/", http.StripPrefix("/admin/ui/static/", http.FileServer(h.staticFS)))
	mux.HandleFunc("/admin/ui/login", h.handleLoginPage)
	mux.HandleFunc("/admin/ui/change-password", h.requireSession(h.handleChangePasswordPage))
	mux.HandleFunc("/admin/ui/config", h.requireSession(h.handleConfigPage))
	mux.HandleFunc("/admin/ui/logs", h.requireSession(h.handleLogsPage))
	mux.HandleFunc("/admin/ui/", h.requireSession(h.handleDashboard))
	mux.HandleFunc("/admin/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/ui/", http.StatusFound)
	})

	mux.HandleFunc("/admin/api/login", h.handleLoginPost)
	mux.HandleFunc("/admin/api/logout", h.handleLogout)
	mux.HandleFunc("/admin/api/change-password", h.requireSession(h.handleChangePasswordPost))
	mux.HandleFunc("/admin/api/state", h.requireSession(h.handleAPIState))
	mux.HandleFunc("/admin/api/deliveries", h.requireSession(h.handleAPIDeliveries))
	mux.HandleFunc("/admin/api/config", h.requireSession(h.handleAPIConfig))
	mux.HandleFunc("/admin/api/logs", h.requireSession(h.handleAPILogs))
}

func (h *uiHandler) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := readSessionCookie(r)
		user, _, ok := h.store.Get(sid)
		if !ok {
			if strings.HasPrefix(r.URL.Path, "/admin/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/admin/ui/login", http.StatusFound)
			return
		}
		if h.creds.MustChange() &&
			r.URL.Path != "/admin/ui/change-password" &&
			r.URL.Path != "/admin/api/change-password" &&
			r.URL.Path != "/admin/api/logout" {
			http.Redirect(w, r, "/admin/ui/change-password", http.StatusFound)
			return
		}
		r.Header.Set("X-Notrouter-User", user)
		next(w, r)
	}
}

func (h *uiHandler) writeCSRFCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/admin/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// --- pages ---

func (h *uiHandler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if sid := readSessionCookie(r); sid != "" {
		if _, _, ok := h.store.Get(sid); ok {
			http.Redirect(w, r, "/admin/ui/", http.StatusFound)
			return
		}
	}
	csrf, _ := randomToken(16)
	h.writeCSRFCookie(w, r, csrf)
	h.renderTemplate(w, h.tmplLogin, map[string]interface{}{
		"CSRF":    csrf,
		"Error":   r.URL.Query().Get("err"),
		"Version": version.Version,
		"Commit":  version.Commit,
	})
}

func (h *uiHandler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	h.renderTemplate(w, h.tmplDash, map[string]interface{}{
		"User":    user,
		"CSRF":    csrf,
		"Version": version.Version,
		"Commit":  version.Commit,
		"Links":   h.links,
	})
}

func (h *uiHandler) handleChangePasswordPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	h.renderTemplate(w, h.tmplChangePw, map[string]interface{}{
		"User":       user,
		"CSRF":       csrf,
		"MustChange": h.creds.MustChange(),
		"Error":      r.URL.Query().Get("err"),
		"Success":    r.URL.Query().Get("ok"),
	})
}

func (h *uiHandler) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)

	body, readErr := os.ReadFile(h.configPath)
	var diskHash string
	var diskSize int64
	var driftErr string
	var drifted bool

	if readErr != nil {
		driftErr = readErr.Error()
	} else {
		diskHash, _ = config.HashFile(h.configPath)
		diskSize = int64(len(body))
		drifted = diskHash != h.loadedHash
	}

	data := map[string]interface{}{
		"User":       user,
		"CSRF":       csrf,
		"Version":    version.Version,
		"Commit":     version.Commit,
		"Links":      h.links,
		"ConfigPath": h.configPath,
		"LoadedHash": h.loadedHash,
		"DiskHash":   diskHash,
		"DiskSize":   diskSize,
		"Drifted":    drifted,
		"DriftError": driftErr,
	}
	if readErr != nil {
		data["ReadError"] = readErr.Error()
	} else {
		data["Body"] = string(body)
	}
	h.renderTemplate(w, h.tmplConfig, data)
}

func (h *uiHandler) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	h.renderTemplate(w, h.tmplLogs, map[string]interface{}{
		"User":    user,
		"CSRF":    csrf,
		"Version": version.Version,
		"Commit":  version.Commit,
		"Links":   h.links,
	})
}

// --- API: login ---

func (h *uiHandler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRF(r); err != nil {
		http.Redirect(w, r, "/admin/ui/login?err=invalid+csrf", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := r.FormValue("user")
	pass := r.FormValue("pass")

	if subtle.ConstantTimeCompare([]byte(user), []byte("admin")) != 1 || !h.creds.Verify(pass) {
		h.log.Warn("login failed", "user", user, "remote", r.RemoteAddr)
		http.Redirect(w, r, "/admin/ui/login?err=invalid+credentials", http.StatusFound)
		return
	}

	sid, csrf, err := h.store.Create("admin")
	if err != nil {
		http.Error(w, "session create", http.StatusInternalServerError)
		return
	}
	writeSessionCookie(w, r, sid, h.ttl)
	h.writeCSRFCookie(w, r, csrf)
	h.log.Info("login ok", "user", user, "remote", r.RemoteAddr)

	if h.creds.MustChange() {
		http.Redirect(w, r, "/admin/ui/change-password", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ui/", http.StatusFound)
}

func (h *uiHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRF(r); err != nil {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	if sid := readSessionCookie(r); sid != "" {
		h.store.Destroy(sid)
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/admin/ui/login", http.StatusFound)
}

// --- API: change password ---

func (h *uiHandler) handleChangePasswordPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRF(r); err != nil {
		http.Redirect(w, r, "/admin/ui/change-password?err=invalid+csrf", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	current := r.FormValue("current")
	new1 := r.FormValue("new1")
	new2 := r.FormValue("new2")

	if !h.creds.Verify(current) {
		http.Redirect(w, r, "/admin/ui/change-password?err=current+password+incorrect", http.StatusFound)
		return
	}
	if new1 != new2 {
		http.Redirect(w, r, "/admin/ui/change-password?err=new+passwords+do+not+match", http.StatusFound)
		return
	}
	if new1 == current {
		http.Redirect(w, r, "/admin/ui/change-password?err=new+password+must+differ", http.StatusFound)
		return
	}
	if err := h.creds.SetPassword(new1); err != nil {
		h.log.Error("password change failed", "err", err)
		http.Redirect(w, r, "/admin/ui/change-password?err="+template.URLQueryEscaper(err.Error()), http.StatusFound)
		return
	}
	h.log.Info("password changed", "user", r.Header.Get("X-Notrouter-User"))
	http.Redirect(w, r, "/admin/ui/change-password?ok=password+updated", http.StatusFound)
}

// --- API: state, deliveries, config, logs ---

func (h *uiHandler) handleAPIState(w http.ResponseWriter, r *http.Request) {
	state := map[string]interface{}{
		"version": map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		},
	}
	if h.probes.Dispatch != nil {
		state["queues"] = h.probes.Dispatch.QueueState()
	}
	if h.probes.Dedup != nil {
		state["dedup_size"] = h.probes.Dedup.Size()
	}
	if h.probes.Tracker != nil {
		state["tracker_pending"] = h.probes.Tracker.Pending()
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *uiHandler) handleAPIDeliveries(w http.ResponseWriter, r *http.Request) {
	if h.probes.Tracker == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"recent": []interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending": h.probes.Tracker.Pending(),
		"recent":  h.probes.Tracker.RecentFinal(),
	})
}

func (h *uiHandler) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	body, err := os.ReadFile(h.configPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"path":  h.configPath,
			"error": err.Error(),
		})
		return
	}
	diskHash, _ := config.HashFile(h.configPath)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"path":        h.configPath,
		"loaded_hash": h.loadedHash,
		"disk_hash":   diskHash,
		"size":        len(body),
		"drifted":     diskHash != h.loadedHash,
		"body":        string(body),
	})
}

// handleAPILogs returns ring-buffer entries newer than the ?since= param,
// optionally filtered by minimum level and a substring search. Designed
// for incremental polling - the UI tracks the highest seq it has and
// only fetches what's new each tick.
func (h *uiHandler) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	since := uint64(0)
	if s := r.URL.Query().Get("since"); s != "" {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			since = v
		}
	}
	level := r.URL.Query().Get("level")
	search := r.URL.Query().Get("search")
	entries := h.logs.Since(since, level, search)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"high_water": h.logs.HighWaterMark(),
		"entries":    entries,
	})
}

// --- helpers ---

func (h *uiHandler) checkCSRF(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ErrUnauthorized
	}
	form := r.FormValue("csrf")
	if form == "" {
		_ = r.ParseForm()
		form = r.FormValue("csrf")
	}
	if cookie.Value == "" || form == "" {
		return ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(form)) != 1 {
		return ErrUnauthorized
	}
	return nil
}

func (h *uiHandler) renderTemplate(w http.ResponseWriter, t *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.log.Error("template render", "err", err)
	}
}
