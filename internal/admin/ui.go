package admin

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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
	ttl          time.Duration
	log          *slog.Logger
	logs         *logbuffer.Buffer

	// rt holds the live reloader. Probes() and CurrentConfig() come from
	// the currently-running pipeline. Always go through these methods so
	// post-reload references update automatically.
	rtMu sync.RWMutex
	rt   reloaderAccessor

	credsPath string
}

// reloaderAccessor decouples admin from the runtime package - we don't
// import runtime here, runtime imports admin (for Probes type). This
// avoids the import cycle while letting us call into the reloader.
type reloaderAccessor interface {
	CurrentConfig() *config.Config
	LKGConfig() *config.Config
	Apply(newCfg *config.Config) ReloadResult
	Probes() Probes
}

// ReloadResult mirrors runtime.ReloadResult so we can return it as JSON
// without importing runtime. The runtime package wraps this.
type ReloadResult struct {
	OK              bool   `json:"ok"`
	AppliedHash     string `json:"applied_hash,omitempty"`
	Error           string `json:"error,omitempty"`
	RestoredFromLKG bool   `json:"restored_from_lkg,omitempty"`
	LKGHash         string `json:"lkg_hash,omitempty"`
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
	ttl time.Duration,
	log *slog.Logger,
	rt reloaderAccessor,
	credsPath string,
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
		ttl:          ttl,
		log:          log,
		rt:           rt,
		credsPath:    credsPath,
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

	// Editor endpoints. All POST, all CSRF-protected.
	mux.HandleFunc("/admin/api/config/validate", h.requireSession(h.handleAPIConfigValidate))
	mux.HandleFunc("/admin/api/config/save", h.requireSession(h.handleAPIConfigSave))
	mux.HandleFunc("/admin/api/config/reload", h.requireSession(h.handleAPIConfigReload))
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
	// CSRF cookie is intentionally readable from JavaScript (no HttpOnly).
	// The double-submit-cookie pattern relies on the JS being able to read
	// the cookie and put it in a request header; the security comes from
	// the same-origin policy preventing other origins from reading it.
	// The session cookie still uses HttpOnly - that's the one whose
	// secrecy matters.
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/admin/",
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// --- helpers for current state from reloader ---

func (h *uiHandler) currentCfg() *config.Config {
	h.rtMu.RLock()
	defer h.rtMu.RUnlock()
	return h.rt.CurrentConfig()
}

func (h *uiHandler) currentProbes() Probes {
	h.rtMu.RLock()
	defer h.rtMu.RUnlock()
	return h.rt.Probes()
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
		"Links":   h.currentCfg().Links,
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

	cfg := h.currentCfg()
	configPath := cfg.Path()
	loadedHash := cfg.LoadedHash()

	body, readErr := os.ReadFile(configPath)
	var diskHash string
	var diskSize int64
	var driftErr string
	var drifted bool

	if readErr != nil {
		driftErr = readErr.Error()
	} else {
		diskHash, _ = config.HashFile(configPath)
		diskSize = int64(len(body))
		drifted = diskHash != loadedHash
	}

	data := map[string]interface{}{
		"User":       user,
		"CSRF":       csrf,
		"Version":    version.Version,
		"Commit":     version.Commit,
		"Links":      h.currentCfg().Links,
		"ConfigPath": configPath,
		"LoadedHash": loadedHash,
		"DiskHash":   diskHash,
		"DiskSize":   diskSize,
		"Drifted":    drifted,
		"DriftError": driftErr,
		"CredsPath":  h.credsPath,
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
		"Links":   h.currentCfg().Links,
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

// --- API: state, deliveries, config (GET), logs ---

func (h *uiHandler) handleAPIState(w http.ResponseWriter, r *http.Request) {
	probes := h.currentProbes()
	state := map[string]interface{}{
		"version": map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		},
	}
	if probes.Dispatch != nil {
		state["queues"] = probes.Dispatch.QueueState()
	}
	if probes.Dedup != nil {
		state["dedup_size"] = probes.Dedup.Size()
	}
	if probes.Tracker != nil {
		state["tracker_pending"] = probes.Tracker.Pending()
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *uiHandler) handleAPIDeliveries(w http.ResponseWriter, r *http.Request) {
	probes := h.currentProbes()
	if probes.Tracker == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"recent": []interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending": probes.Tracker.Pending(),
		"recent":  probes.Tracker.RecentFinal(),
	})
}

func (h *uiHandler) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.currentCfg()
	configPath := cfg.Path()
	body, err := os.ReadFile(configPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"path":  configPath,
			"error": err.Error(),
		})
		return
	}
	diskHash, _ := config.HashFile(configPath)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"path":        configPath,
		"loaded_hash": cfg.LoadedHash(),
		"disk_hash":   diskHash,
		"size":        len(body),
		"drifted":     diskHash != cfg.LoadedHash(),
		"body":        string(body),
	})
}

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

// --- API: editor (validate / save / reload) ---

// editRequest is the JSON body shape the editor JS posts. Body is the
// proposed YAML; ExpectedDiskHash supports optimistic concurrency.
type editRequest struct {
	Body             string `json:"body"`
	ExpectedDiskHash string `json:"expected_disk_hash"`
}

// handleAPIConfigValidate parses+validates without touching disk or pipeline.
// Returns {ok:true} or {ok:false, error:"..."}.
func (h *uiHandler) handleAPIConfigValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRFHeader(r); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req, err := readEditRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	if err := config.ValidateBytes([]byte(req.Body)); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// handleAPIConfigSave writes the new YAML to disk atomically with a
// timestamped backup. Does NOT apply to the running pipeline. Returns
// 409 if disk hash changed since the user started editing.
func (h *uiHandler) handleAPIConfigSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRFHeader(r); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req, err := readEditRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	configPath := h.currentCfg().Path()
	res, err := config.Save(configPath, []byte(req.Body), req.ExpectedDiskHash)
	if err != nil {
		var conflict *config.ConflictError
		if errors.As(err, &conflict) {
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error":    conflict.Error(),
				"expected": conflict.Expected,
				"actual":   conflict.Actual,
			})
			return
		}
		h.log.Error("config save failed", "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	user := r.Header.Get("X-Notrouter-User")
	h.log.Info("config saved",
		"user", user,
		"new_hash", res.NewHash,
		"backup", res.BackupFile)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":          true,
		"new_hash":    res.NewHash,
		"backup_file": res.BackupFile,
		"backups":     res.Backups,
	})
}

// handleAPIConfigReload re-reads the disk file and tells the reloader to
// rebuild the pipeline. The reloader handles LKG fallback internally;
// we just translate the result into JSON.
func (h *uiHandler) handleAPIConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRFHeader(r); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	configPath := h.currentCfg().Path()
	body, err := os.ReadFile(configPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok":    false,
			"error": "read config: " + err.Error(),
		})
		return
	}
	newCfg, err := config.LoadFromBytes(body, configPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":    false,
			"error": "load: " + err.Error(),
		})
		return
	}

	user := r.Header.Get("X-Notrouter-User")
	h.log.Info("reload requested",
		"user", user,
		"new_hash", newCfg.LoadedHash(),
		"current_hash", h.currentCfg().LoadedHash())

	res := h.rt.Apply(newCfg)
	out := ReloadResult{
		OK:              res.OK,
		AppliedHash:     res.AppliedHash,
		Error:           res.Error,
		RestoredFromLKG: res.RestoredFromLKG,
		LKGHash:         res.LKGHash,
	}
	writeJSON(w, http.StatusOK, out)
}

// readEditRequest parses the JSON body and sanity-checks size. Hard
// cap at 1 MB so a user can't OOM us with a giant paste.
func readEditRequest(r *http.Request) (*editRequest, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	req := &editRequest{}
	if err := json.Unmarshal(b, req); err != nil {
		return nil, err
	}
	return req, nil
}

// --- helpers ---

// checkCSRF used by the legacy form-encoded handlers.
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

// checkCSRFHeader handles the JSON-body editor calls. The JS sends the
// CSRF token via X-CSRF-Token header (form bodies aren't being parsed).
func (h *uiHandler) checkCSRFHeader(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ErrUnauthorized
	}
	hdr := r.Header.Get("X-CSRF-Token")
	if cookie.Value == "" || hdr == "" {
		return ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(hdr)) != 1 {
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
