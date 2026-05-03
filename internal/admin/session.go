package admin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName = "notrouter_session"
	csrfCookieName    = "notrouter_csrf"
)

type session struct {
	user    string
	created time.Time
	expires time.Time
	csrf    string
}

// SessionStore holds active sessions in memory. Lost on restart by design -
// every operator logs in again. Simpler than persisting and avoids stale
// session bugs across binary upgrades.
type SessionStore struct {
	ttl time.Duration

	mu       sync.RWMutex
	sessions map[string]*session
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	s := &SessionStore{
		ttl:      ttl,
		sessions: make(map[string]*session),
	}
	go s.sweepLoop()
	return s
}

// Create issues a new session for the given user, returns (sessionID, csrfToken).
func (s *SessionStore) Create(user string) (string, string, error) {
	sid, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	s.mu.Lock()
	s.sessions[sid] = &session{
		user:    user,
		created: now,
		expires: now.Add(s.ttl),
		csrf:    csrf,
	}
	s.mu.Unlock()
	return sid, csrf, nil
}

// Get returns the session if it exists and hasn't expired.
func (s *SessionStore) Get(sid string) (user, csrf string, ok bool) {
	s.mu.RLock()
	sess, exists := s.sessions[sid]
	s.mu.RUnlock()
	if !exists {
		return "", "", false
	}
	if time.Now().After(sess.expires) {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		return "", "", false
	}
	return sess.user, sess.csrf, true
}

// Destroy removes a session (for logout).
func (s *SessionStore) Destroy(sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
}

func (s *SessionStore) sweepLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for sid, sess := range s.sessions {
			if now.After(sess.expires) {
				delete(s.sessions, sid)
			}
		}
		s.mu.Unlock()
	}
}

// readSessionCookie returns the session ID from the request, "" if not present.
func readSessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// writeSessionCookie sets the session cookie. Secure flag is set when the
// request appears to be over TLS (we run behind a reverse proxy in prod).
func writeSessionCookie(w http.ResponseWriter, r *http.Request, sid string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(ttl),
	})
}

// clearSessionCookie removes the session cookie from the client.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Trust X-Forwarded-Proto from reverse proxies. Fine because if the
	// proxy lies about it, the worst that happens is Secure flag wrongly
	// gets set on a plain-HTTP cookie - browsers reject it; users get a
	// login error rather than a security hole.
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ErrUnauthorized is the typed error session middleware returns when the
// caller has no valid session.
var ErrUnauthorized = errors.New("unauthorized")
