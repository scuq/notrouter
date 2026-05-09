package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/admin/creds"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/logbuffer"
	"github.com/scuq/notrouter/internal/version"
)

// authMethodKey records which auth path verified this request, so
// requireSession can know whether to enforce CSRF (cookie -> yes,
// bearer -> no).
type authMethodKey struct{}

const (
	authMethodCookie = "cookie"
	authMethodBearer = "bearer"
	authMethodBasic  = "basic"
)

func withAuthMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, authMethodKey{}, method)
}

func authMethodFrom(r *http.Request) string {
	if v, ok := r.Context().Value(authMethodKey{}).(string); ok {
		return v
	}
	return ""
}

type uiHandler struct {
	tmplLogin    *template.Template
	tmplDash     *template.Template
	tmplChangePw *template.Template
	tmplConfig   *template.Template
	tmplLogs     *template.Template
	tmplTest     *template.Template
	tmplTokens   *template.Template
	tmplWebhookKeys *template.Template
	tmplReplay   *template.Template
	staticFS     http.FileSystem
	store        *SessionStore
	creds        credsAccessor
	ttl          time.Duration
	log          *slog.Logger
	logs         *logbuffer.Buffer

	rtMu sync.RWMutex
	rt   reloaderAccessor

	credsPath  string
	httpClient *http.Client
}

type reloaderAccessor interface {
	CurrentConfig() *config.Config
	LKGConfig() *config.Config
	Apply(newCfg *config.Config) ReloadResult
	Probes() Probes
}

type ReloadResult struct {
	OK              bool   `json:"ok"`
	AppliedHash     string `json:"applied_hash,omitempty"`
	Error           string `json:"error,omitempty"`
	RestoredFromLKG bool   `json:"restored_from_lkg,omitempty"`
	LKGHash         string `json:"lkg_hash,omitempty"`
}

// credsAccessor extends with token-related operations introduced in
// v0.2.2. The Store satisfies this; tests can mock.
type credsAccessor interface {
	Verify(plain string) bool
	MustChange() bool
	UpdatedAt() time.Time
	SetPassword(newPlain string) error
	VerifyToken(plain string) (string, error)
	MintToken(user, label string) (*creds.MintResult, error)
	ListTokens(user string) []creds.TokenView
	RefreshTokenByHash(hash, requestingUser string) (*creds.TokenView, error)
	RefreshTokenSelf(plain string) (*creds.TokenView, error)
	RevokeTokenByHash(hash, requestingUser string) error
	MintWebhookKey(createdBy, label string) (*creds.WebhookKeyMintResult, error)
	ListWebhookKeys() []creds.WebhookKeyView
	RevokeWebhookKeyByHash(hash string) error
	HasAnyWebhookKey() bool
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
	testTpl, err := template.ParseFS(uiFS, "ui/test.html")
	if err != nil {
		return nil, err
	}
	tokensTpl, err := template.ParseFS(uiFS, "ui/tokens.html")
	if err != nil {
		return nil, err
	}
	replayTpl, err := template.ParseFS(uiFS, "ui/replay.html")
	if err != nil {
		return nil, err
	}
	wkTpl, err := template.ParseFS(uiFS, "ui/webhook_keys.html")
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
		tmplTest:     testTpl,
		tmplTokens:   tokensTpl,
		tmplWebhookKeys: wkTpl,
		tmplReplay:   replayTpl,
		staticFS:     http.FS(staticSub),
		store:        store,
		creds:        creds,
		ttl:          ttl,
		log:          log,
		rt:           rt,
		credsPath:    credsPath,
		logs:         logs,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (h *uiHandler) register(mux *http.ServeMux) {
	mux.Handle("/admin/ui/static/", http.StripPrefix("/admin/ui/static/", http.FileServer(h.staticFS)))
	mux.HandleFunc("/admin/ui/login", h.handleLoginPage)
	mux.HandleFunc("/admin/ui/change-password", h.requireAuth(h.handleChangePasswordPage))
	mux.HandleFunc("/admin/ui/config", h.requireAuth(h.handleConfigPage))
	mux.HandleFunc("/admin/ui/logs", h.requireAuth(h.handleLogsPage))
	mux.HandleFunc("/admin/ui/test", h.requireAuth(h.handleTestPage))
	mux.HandleFunc("/admin/ui/replay", h.requireAuth(h.handleReplayPage))
	mux.HandleFunc("/admin/ui/tokens", h.requireAuth(h.handleTokensPage))
	mux.HandleFunc("/admin/ui/", h.requireAuth(h.handleDashboard))
	mux.HandleFunc("/admin/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/ui/", http.StatusFound)
	})

	mux.HandleFunc("/admin/api/login", h.handleLoginPost)
	mux.HandleFunc("/admin/api/logout", h.handleLogout)
	mux.HandleFunc("/admin/api/change-password", h.requireAuth(h.handleChangePasswordPost))
	mux.HandleFunc("/admin/api/state", h.requireAuth(h.handleAPIState))
	mux.HandleFunc("/admin/api/deliveries", h.requireAuth(h.handleAPIDeliveries))
	mux.HandleFunc("/admin/api/config", h.requireAuth(h.handleAPIConfig))
	mux.HandleFunc("/admin/api/logs", h.requireAuth(h.handleAPILogs))

	mux.HandleFunc("/admin/api/config/validate", h.requireAuth(h.handleAPIConfigValidate))
	mux.HandleFunc("/admin/api/config/save", h.requireAuth(h.handleAPIConfigSave))
	mux.HandleFunc("/admin/api/config/reload", h.requireAuth(h.handleAPIConfigReload))

	mux.HandleFunc("/admin/api/test/send", h.requireAuth(h.handleAPITestSend))

	// Token endpoints. Every state-changing one (mint/refresh/revoke)
	// uses requireCSRFIfCookie so cookie-authed UI flows enforce CSRF
	// while bearer-authed scripts skip it.
	mux.HandleFunc("/admin/api/tokens", h.requireAuth(h.handleAPITokensList))
	mux.HandleFunc("/admin/api/tokens/mint", h.requireAuth(h.handleAPITokensMint))
	mux.HandleFunc("/admin/api/tokens/refresh", h.requireAuth(h.handleAPITokensRefresh))
	mux.HandleFunc("/admin/api/tokens/refresh-self", h.requireAuth(h.handleAPITokensRefreshSelf))
	mux.HandleFunc("/admin/api/tokens/revoke", h.requireAuth(h.handleAPITokensRevoke))

	// Webhook keys (v0.2.3): mint/list/revoke. No refresh - keys don't expire.
	mux.HandleFunc("/admin/ui/webhook-keys", h.requireAuth(h.handleWebhookKeysPage))
	mux.HandleFunc("/admin/api/webhook-keys", h.requireAuth(h.handleAPIWebhookKeysList))
	mux.HandleFunc("/admin/api/webhook-keys/mint", h.requireAuth(h.handleAPIWebhookKeysMint))
	mux.HandleFunc("/admin/api/webhook-keys/revoke", h.requireAuth(h.handleAPIWebhookKeysRevoke))
}

// requireAuth is the new gating middleware. It accepts:
//   - Session cookie (cookie auth method, CSRF required for state changes)
//   - Bearer token (bearer auth method, no CSRF needed)
//   - HTTP basic auth (basic auth method, no CSRF needed)
//
// If none match, redirects to /admin/ui/login (UI paths) or 401 JSON
// (API paths). The "must change password" redirect still applies to
// cookie-authed sessions only; bearer scripts don't get caught in
// the human-only password rotation flow.
func (h *uiHandler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1) Session cookie
		if sid := readSessionCookie(r); sid != "" {
			if user, _, ok := h.store.Get(sid); ok {
				ctx := withAuthMethod(r.Context(), authMethodCookie)
				ctx = withUser(ctx, user)
				if h.creds.MustChange() &&
					r.URL.Path != "/admin/ui/change-password" &&
					r.URL.Path != "/admin/api/change-password" &&
					r.URL.Path != "/admin/api/logout" {
					http.Redirect(w, r, "/admin/ui/change-password", http.StatusFound)
					return
				}
				r.Header.Set("X-Notrouter-User", user)
				next(w, r.WithContext(ctx))
				return
			}
		}

		// 2) Bearer token
		hdr := r.Header.Get("Authorization")
		if strings.HasPrefix(hdr, "Bearer ") {
			token := strings.TrimPrefix(hdr, "Bearer ")
			if user, err := h.creds.VerifyToken(token); err == nil {
				ctx := withAuthMethod(r.Context(), authMethodBearer)
				ctx = withUser(ctx, user)
				r.Header.Set("X-Notrouter-User", user)
				next(w, r.WithContext(ctx))
				return
			}
			// Fall through to 401 below; auth failed.
		}

		// Unauthorized.
		if strings.HasPrefix(r.URL.Path, "/admin/api/") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/admin/ui/login", http.StatusFound)
	}
}

// requireCSRFIfCookie returns nil (allow) when the request was bearer-
// authed, or runs the appropriate CSRF check when cookie-authed. We
// have two CSRF check styles (form-encoded vs header) - caller picks.
func (h *uiHandler) requireCSRFIfCookie(r *http.Request, fromHeader bool) error {
	if authMethodFrom(r) == authMethodBearer {
		return nil // Bearer-authed: CSRF not applicable
	}
	if fromHeader {
		return h.checkCSRFHeader(r)
	}
	return h.checkCSRF(r)
}

func (h *uiHandler) writeCSRFCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/admin/",
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

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
		"Links":      cfg.Links,
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

func (h *uiHandler) handleTestPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	cfg := h.currentCfg()
	h.renderTemplate(w, h.tmplTest, map[string]interface{}{
		"User":        user,
		"CSRF":        csrf,
		"Version":     version.Version,
		"Commit":      version.Commit,
		"Links":       cfg.Links,
		"Endpoints":   cfg.Receivers.Webhook.Endpoints,
		"WebhookAddr": cfg.Listen.Webhook,
	})
}

func (h *uiHandler) handleTokensPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	h.renderTemplate(w, h.tmplTokens, map[string]interface{}{
		"User":          user,
		"CSRF":          csrf,
		"Version":       version.Version,
		"Commit":        version.Commit,
		"Links":         h.currentCfg().Links,
		"TokenLifetime": creds.TokenLifetime.String(),
	})
}

// --- API: login / logout / change-password (form flows, CSRF always) ---

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

func (h *uiHandler) handleChangePasswordPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, false); err != nil {
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

// --- API: read-only state, deliveries, config (GET), logs ---

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

// --- API: editor (validate / save / reload) - smart CSRF ---

type editRequest struct {
	Body             string `json:"body"`
	ExpectedDiskHash string `json:"expected_disk_hash"`
}

func (h *uiHandler) handleAPIConfigValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
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

func (h *uiHandler) handleAPIConfigSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
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

func (h *uiHandler) handleAPIConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
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

// --- API: send test event ---

type testSendRequest struct {
	Path    string          `json:"path"`
	Payload json.RawMessage `json:"payload"`
}

func (h *uiHandler) handleAPITestSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req := &testSendRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad request body: " + err.Error()})
		return
	}
	if req.Path == "" || req.Path[0] != '/' {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "path must start with /"})
		return
	}
	if len(req.Payload) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "payload is required"})
		return
	}

	cfg := h.currentCfg()
	target := loopbackURL(cfg.Listen.Webhook) + req.Path

	h.log.Info("test event from UI",
		"user", r.Header.Get("X-Notrouter-User"),
		"target", target,
		"size", len(req.Payload))

	upstreamReq, err := http.NewRequestWithContext(r.Context(), "POST", target, bytes.NewReader(req.Payload))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("X-Notrouter-Test", "1")

	resp, err := h.httpClient.Do(upstreamReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"error":           "loopback to webhook receiver failed: " + err.Error(),
			"target":          target,
			"upstream_status": 0,
		})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":          target,
		"upstream_status": resp.StatusCode,
		"upstream_body":   string(respBody),
	})
}

// --- API: tokens (mint / list / refresh / refresh-self / revoke) ---

type mintRequest struct {
	Label string `json:"label"`
}

type tokenHashRequest struct {
	Hash string `json:"hash"`
}

// handleAPITokensList returns the user's tokens. For v0.2.2 only "admin"
// exists, so this is effectively all tokens.
func (h *uiHandler) handleAPITokensList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"GET required"}`, http.StatusMethodNotAllowed)
		return
	}
	user := r.Header.Get("X-Notrouter-User")
	// Local admin scope sees all tokens; this generalizes cleanly when
	// OIDC users land in v0.3 (they'll be scoped to user==their name).
	scope := ""
	if user != "admin" {
		scope = user
	}
	tokens := h.creds.ListTokens(scope)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tokens": tokens,
		"count":  len(tokens),
	})
}

func (h *uiHandler) handleAPITokensMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req := &mintRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad request body: " + err.Error()})
		return
	}

	user := r.Header.Get("X-Notrouter-User")
	res, err := h.creds.MintToken(user, req.Label)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, creds.ErrInvalidLabel) {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]interface{}{"error": err.Error()})
		return
	}
	h.log.Info("token minted",
		"user", user,
		"label", req.Label,
		"hash", res.View.Hash,
		"expires_at", res.View.ExpiresAt)
	// Return the plaintext token. UI shows it ONCE.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": res.Token,
		"view":  res.View,
	})
}

func (h *uiHandler) handleAPITokensRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req := &tokenHashRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	user := r.Header.Get("X-Notrouter-User")
	scope := ""
	if user != "admin" {
		scope = user
	}
	view, err := h.creds.RefreshTokenByHash(req.Hash, scope)
	if err != nil {
		status := tokenErrStatus(err)
		writeJSON(w, status, map[string]interface{}{"error": err.Error()})
		return
	}
	h.log.Info("token refreshed",
		"user", user,
		"hash", req.Hash,
		"new_expires_at", view.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]interface{}{"view": view})
}

// handleAPITokensRefreshSelf is the script path. Caller authenticates
// with the token itself; we extract it from the Bearer header (NOT the
// body, to avoid encouraging it being logged). Doesn't require CSRF
// because the token presence IS the authentication.
//
// This means a script with a soon-expiring token can refresh itself:
//
//	curl -X POST -H "Authorization: Bearer notr_..." \
//	     http://notrouter:9090/admin/api/tokens/refresh-self
func (h *uiHandler) handleAPITokensRefreshSelf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "refresh-self requires the token in the Authorization: Bearer header",
		})
		return
	}
	token := strings.TrimPrefix(hdr, "Bearer ")
	view, err := h.creds.RefreshTokenSelf(token)
	if err != nil {
		writeJSON(w, tokenErrStatus(err), map[string]interface{}{"error": err.Error()})
		return
	}
	h.log.Info("token self-refreshed",
		"hash", view.Hash,
		"user", view.User,
		"new_expires_at", view.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]interface{}{"view": view})
}

func (h *uiHandler) handleAPITokensRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req := &tokenHashRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	user := r.Header.Get("X-Notrouter-User")
	scope := ""
	if user != "admin" {
		scope = user
	}
	if err := h.creds.RevokeTokenByHash(req.Hash, scope); err != nil {
		writeJSON(w, tokenErrStatus(err), map[string]interface{}{"error": err.Error()})
		return
	}
	h.log.Warn("token revoked", "user", user, "hash", req.Hash)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// tokenErrStatus maps creds.Err* sentinels to HTTP statuses.
func tokenErrStatus(err error) int {
	switch {
	case errors.Is(err, creds.ErrTokenNotFound):
		return http.StatusNotFound
	case errors.Is(err, creds.ErrTokenExpired):
		return http.StatusGone // 410: existed but is gone
	case errors.Is(err, creds.ErrTokenForbidden):
		return http.StatusForbidden
	case errors.Is(err, creds.ErrInvalidLabel),
		errors.Is(err, creds.ErrInvalidToken):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// --- API: webhook keys ---

type webhookKeyMintRequest struct {
	Label string `json:"label"`
}

type webhookKeyHashRequest struct {
	Hash string `json:"hash"`
}

func (h *uiHandler) handleWebhookKeysPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	cfg := h.currentCfg()
	h.renderTemplate(w, h.tmplWebhookKeys, map[string]interface{}{
		"User":        user,
		"CSRF":        csrf,
		"Version":     version.Version,
		"Commit":      version.Commit,
		"Links":       cfg.Links,
		"CredsPath":   h.credsPath,
		"AuthActive":  h.creds.HasAnyWebhookKey(),
		"RequireAuth": cfg.Receivers.Webhook.RequireAuth,
	})
}

func (h *uiHandler) handleAPIWebhookKeysList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"GET required"}`, http.StatusMethodNotAllowed)
		return
	}
	keys := h.creds.ListWebhookKeys()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys":  keys,
		"count": len(keys),
	})
}

func (h *uiHandler) handleAPIWebhookKeysMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req := &webhookKeyMintRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad request body: " + err.Error()})
		return
	}
	user := r.Header.Get("X-Notrouter-User")
	res, err := h.creds.MintWebhookKey(user, req.Label)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	h.log.Info("webhook key minted",
		"user", user,
		"label", req.Label,
		"hash", res.View.Hash)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key":  res.Key,
		"view": res.View,
	})
}

func (h *uiHandler) handleAPIWebhookKeysRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := h.requireCSRFIfCookie(r, true); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "invalid csrf"})
		return
	}
	req := &webhookKeyHashRequest{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	if err := h.creds.RevokeWebhookKeyByHash(req.Hash); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "webhook key not found" {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]interface{}{"error": err.Error()})
		return
	}
	user := r.Header.Get("X-Notrouter-User")
	h.log.Warn("webhook key revoked", "user", user, "hash", req.Hash)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func loopbackURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// --- helpers ---

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

// handleReplayPage renders the replay UI - audit log browser + analyzer
// front-end. The page itself is mostly static; data is fetched via
// /admin/api/audit/recent and /admin/api/routing/analyze.
func (h *uiHandler) handleReplayPage(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-Notrouter-User")
	_, csrf, _ := h.store.Get(readSessionCookie(r))
	h.writeCSRFCookie(w, r, csrf)
	h.renderTemplate(w, h.tmplReplay, map[string]interface{}{
		"User":    user,
		"CSRF":    csrf,
		"Version": version.Version,
		"Commit":  version.Commit,
		"Links":   h.currentCfg().Links,
	})
}

