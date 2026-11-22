package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"cubus.sh/artifact/internal/store"
)

const (
	SessionTTL = 7 * 24 * time.Hour
	PreCSRFTTL = 30 * time.Minute
)

type SessionManager struct {
	store         store.Store
	secure        bool
	sessionCookie string
	csrfCookie    string
}

func NewSessionManager(st store.Store, secure bool) *SessionManager {
	sessName := "artifact_session"
	csrfName := "artifact_csrf"
	if secure {
		// __Host- prefix prevents sibling *.cubus.sh subdomain cookie tossing.
		sessName = "__Host-artifact_session"
		csrfName = "__Host-artifact_csrf"
	}
	return &SessionManager{
		store:         st,
		secure:        secure,
		sessionCookie: sessName,
		csrfCookie:    csrfName,
	}
}

func (m *SessionManager) SessionCookieName() string {
	return m.sessionCookie
}

func (m *SessionManager) Create(ctx context.Context, w http.ResponseWriter, userID string) (store.WebSession, error) {
	rawToken, err := RandomToken(32)
	if err != nil {
		return store.WebSession{}, err
	}
	csrfToken, err := RandomToken(24)
	if err != nil {
		return store.WebSession{}, err
	}
	sess := store.WebSession{
		TokenHash: SHA256Bytes(rawToken),
		UserID:    userID,
		CSRFToken: csrfToken,
		ExpiresAt: time.Now().UTC().Add(SessionTTL),
	}
	if err := m.store.CreateWebSession(ctx, sess); err != nil {
		return store.WebSession{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.sessionCookie,
		Value:    rawToken,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		MaxAge:   int(SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return sess, nil
}

func (m *SessionManager) Current(ctx context.Context, r *http.Request) (store.WebSession, store.User, bool) {
	c, err := r.Cookie(m.sessionCookie)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return store.WebSession{}, store.User{}, false
	}
	sess, u, err := m.store.GetWebSession(ctx, SHA256Bytes(c.Value))
	if err != nil || u.Status != store.UserStatusActive {
		return store.WebSession{}, store.User{}, false
	}
	return sess, u, true
}

func (m *SessionManager) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(m.sessionCookie); err == nil && c.Value != "" {
		_ = m.store.DeleteWebSession(ctx, SHA256Bytes(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// IssuePreLoginCSRF issues or reuses a pre-login double-submit CSRF token bound to a cookie.
func (m *SessionManager) IssuePreLoginCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(m.csrfCookie); err == nil && len(c.Value) >= 24 {
		return c.Value, nil
	}
	tok, err := RandomToken(24)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.csrfCookie,
		Value:    tok,
		Path:     "/",
		MaxAge:   int(PreCSRFTTL.Seconds()),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return tok, nil
}

func (m *SessionManager) VerifyPreLoginCSRF(r *http.Request, formToken string) bool {
	c, err := r.Cookie(m.csrfCookie)
	if err != nil || len(c.Value) < 24 || formToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(formToken)) == 1
}

func VerifyCSRFToken(expected, provided string) bool {
	if expected == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

// SafeNextPath strictly restricts post-login redirects to known local paths,
// blocking open redirects like //evil.com, /\evil.com, or https://evil.com.
func SafeNextPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.ContainsRune(raw, '\\') {
		return "/"
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "/"
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	if u.Path != "/" && !strings.HasPrefix(u.Path, "/v/") && u.Path != "/oauth/authorize" {
		return "/"
	}
	return u.RequestURI()
}

func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func SHA256Bytes(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
