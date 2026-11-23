package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"cubus.sh/artifact/internal/artifact"
	"cubus.sh/artifact/internal/auth"
	"cubus.sh/artifact/internal/db"
	"cubus.sh/artifact/internal/mcpserver"
	"cubus.sh/artifact/internal/store"
)

//go:embed templates/*.html static/*
var embeddedFS embed.FS

const (
	maxFormBodyBytes  = 16 << 10
	maxConcurrentPuts = 4
	healthPingTimeout = 1500 * time.Millisecond
)

type Server struct {
	store         store.Store
	sessions      *auth.SessionManager
	hasher        *auth.PasswordHasher
	oauth         *auth.OAuthServer
	mcp           *mcpserver.Server
	markdown      *artifact.MarkdownRenderer
	publicBaseURL string
	logger        *slog.Logger

	templates     *template.Template
	staticHandler http.Handler
	csrfProtect   *http.CrossOriginProtection

	loginIPLimit    *auth.Limiter
	loginUserLimit  *auth.Limiter
	signupIPLimit   *auth.Limiter
	signupUserLimit *auth.Limiter
	uploadSem       chan struct{}
}

func New(
	st store.Store,
	sessions *auth.SessionManager,
	hasher *auth.PasswordHasher,
	oauth *auth.OAuthServer,
	mcpSrv *mcpserver.Server,
	publicBaseURL string,
	logger *slog.Logger,
) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	tmpl, err := template.ParseFS(embeddedFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded templates: %w", err)
	}
	staticSub, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		return nil, fmt.Errorf("open embedded static fs: %w", err)
	}

	csrf := http.NewCrossOriginProtection()
	baseURL := strings.TrimRight(publicBaseURL, "/")
	if baseURL != "" {
		if err := csrf.AddTrustedOrigin(baseURL); err != nil {
			return nil, fmt.Errorf("trust public origin %q: %w", baseURL, err)
		}
	}

	return &Server{
		store:           st,
		sessions:        sessions,
		hasher:          hasher,
		oauth:           oauth,
		mcp:             mcpSrv,
		markdown:        artifact.NewMarkdownRenderer(),
		publicBaseURL:   baseURL,
		logger:          logger,
		templates:       tmpl,
		staticHandler:   http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))),
		csrfProtect:     csrf,
		loginIPLimit:    auth.NewLimiter(15, 15),
		loginUserLimit:  auth.NewLimiter(8, 8),
		signupIPLimit:   auth.NewLimiter(5, 5),
		signupUserLimit: auth.NewLimiter(3, 3),
		uploadSem:       make(chan struct{}, maxConcurrentPuts),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Healthcheck
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Static assets
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		s.staticHandler.ServeHTTP(w, r)
	}))

	// OAuth 2.1 Discovery + Token/DCR/Revoke (CORS enabled for browser MCP clients, never cookie-authenticated)
	prmHandler := auth.CORSMiddleware(s.oauth.ProtectedResourceMetadataHandler())
	mux.Handle("/.well-known/oauth-protected-resource", prmHandler)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", prmHandler)
	mux.Handle("/.well-known/oauth-authorization-server", auth.CORSMiddleware(http.HandlerFunc(s.oauth.HandleAuthServerMetadata)))
	mux.Handle("/oauth/register", auth.CORSMiddleware(http.HandlerFunc(s.oauth.HandleRegister)))
	mux.Handle("/oauth/token", auth.CORSMiddleware(http.HandlerFunc(s.oauth.HandleToken)))
	mux.Handle("/oauth/revoke", auth.CORSMiddleware(http.HandlerFunc(s.oauth.HandleRevoke)))

	// MCP Streamable HTTP endpoint (CORS + Bearer token auth handled inside mcpSrv)
	mux.Handle("/mcp", s.mcp.HTTPHandler())

	// Single-use out-of-band upload endpoint
	mux.HandleFunc("PUT /upload/{token}", s.handleUploadPut)

	// Cookie-authenticated Web UI & OAuth consent routes
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.Handle("POST /login", s.csrfProtect.Handler(http.HandlerFunc(s.handleLoginPost)))
	mux.Handle("POST /logout", s.csrfProtect.Handler(http.HandlerFunc(s.handleLogoutPost)))
	mux.HandleFunc("GET /signup", s.handleSignupGet)
	mux.Handle("POST /signup", s.csrfProtect.Handler(http.HandlerFunc(s.handleSignupPost)))
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorizeGet)
	mux.Handle("POST /oauth/authorize", s.csrfProtect.Handler(http.HandlerFunc(s.handleAuthorizePost)))

	// Artifact Viewer & Raw Content
	mux.HandleFunc("GET /v/{id}", s.handleViewer)
	mux.HandleFunc("GET /raw/{id}", s.handleRaw)

	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(r.Context(), healthPingTimeout)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type homeArtifactItem struct {
	ID           string
	Title        string
	Visibility   string
	ContentType  string
	Version      int
	SizeLabel    string
	UpdatedLabel string
}

type homeViewData struct {
	PageTitle   string
	User        *store.User
	CSRFToken   string
	Query       string
	Visibility  string
	Artifacts   []homeArtifactItem
	AllowSignup bool
	MCPURL      string
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	data := homeViewData{
		PageTitle: "artifact.cubus.sh",
		MCPURL:    s.publicBaseURL + "/mcp",
	}

	if sess, u, ok := s.sessions.Current(r.Context(), r); ok {
		userCopy := u
		data.User = &userCopy
		data.CSRFToken = sess.CSRFToken
		data.Query = strings.TrimSpace(r.URL.Query().Get("q"))
		vis := strings.TrimSpace(r.URL.Query().Get("visibility"))
		if vis == artifact.VisibilityPublic || vis == artifact.VisibilityPrivate {
			data.Visibility = vis
		}

		rows, err := s.store.ListArtifactsForOwner(r.Context(), u.ID, store.ListArtifactsFilter{
			Visibility: data.Visibility,
			Query:      data.Query,
			Limit:      100,
		})
		if err != nil {
			s.logger.Error("list artifacts on home failed", "err", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		items := make([]homeArtifactItem, 0, len(rows))
		for _, a := range rows {
			items = append(items, homeArtifactItem{
				ID:           a.ID,
				Title:        a.Title,
				Visibility:   a.Visibility,
				ContentType:  a.ContentType,
				Version:      a.Version,
				SizeLabel:    formatBytes(a.SizeBytes),
				UpdatedLabel: a.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			})
		}
		data.Artifacts = items
	} else {
		if settings, err := s.store.GetSettings(r.Context()); err == nil {
			data.AllowSignup = settings.AllowSignup
		}
	}

	s.renderTemplate(w, http.StatusOK, "home.html", data)
}

type loginViewData struct {
	CSRFToken   string
	Next        string
	Username    string
	Error       string
	Notice      string
	AllowSignup bool
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	nextPath := auth.SafeNextPath(r.URL.Query().Get("next"))
	if _, _, ok := s.sessions.Current(r.Context(), r); ok {
		http.Redirect(w, r, nextPath, http.StatusSeeOther)
		return
	}

	csrfTok, err := s.sessions.IssuePreLoginCSRF(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	allowSignup := false
	if settings, err := s.store.GetSettings(r.Context()); err == nil {
		allowSignup = settings.AllowSignup
	}

	s.renderTemplate(w, http.StatusOK, "login.html", loginViewData{
		CSRFToken:   csrfTok,
		Next:        nextPath,
		AllowSignup: allowSignup,
	})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}

	nextPath := auth.SafeNextPath(r.PostForm.Get("next"))
	rawUser := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	allowSignup := false
	if settings, err := s.store.GetSettings(r.Context()); err == nil {
		allowSignup = settings.AllowSignup
	}

	renderErr := func(status int, msg string) {
		csrfTok, _ := s.sessions.IssuePreLoginCSRF(w, r)
		s.renderTemplate(w, status, "login.html", loginViewData{
			CSRFToken:   csrfTok,
			Next:        nextPath,
			Username:    rawUser,
			Error:       msg,
			AllowSignup: allowSignup,
		})
	}

	if !s.sessions.VerifyPreLoginCSRF(r, r.PostForm.Get("csrf_token")) {
		renderErr(http.StatusForbidden, "Session verification expired. Please try again.")
		return
	}

	ipKey := auth.RateLimitIPKey(auth.ExtractClientIP(r))
	userKey := strings.ToLower(rawUser)
	if userKey == "" {
		userKey = "_"
	}
	if !s.loginIPLimit.Allow(ipKey) || !s.loginUserLimit.Allow(ipKey+":"+userKey) {
		w.Header().Set("Retry-After", "60")
		renderErr(http.StatusTooManyRequests, "Too many sign-in attempts. Please wait a minute and try again.")
		return
	}

	const genericAuthErr = "Invalid username or password, or account pending approval."

	normUser, err := db.NormalizeUsername(rawUser)
	if err != nil {
		if dummyErr := s.hasher.VerifyDummy(r.Context(), password); errors.Is(dummyErr, auth.ErrHasherBusy) {
			w.Header().Set("Retry-After", "2")
			renderErr(http.StatusServiceUnavailable, "Authentication service is busy. Please try again shortly.")
			return
		}
		renderErr(http.StatusUnauthorized, genericAuthErr)
		return
	}

	u, err := s.store.GetUserByUsername(r.Context(), normUser)
	if err != nil || u.Status != store.UserStatusActive {
		if dummyErr := s.hasher.VerifyDummy(r.Context(), password); errors.Is(dummyErr, auth.ErrHasherBusy) {
			w.Header().Set("Retry-After", "2")
			renderErr(http.StatusServiceUnavailable, "Authentication service is busy. Please try again shortly.")
			return
		}
		renderErr(http.StatusUnauthorized, genericAuthErr)
		return
	}

	matched, err := s.hasher.Verify(r.Context(), password, u.PasswordHash)
	if errors.Is(err, auth.ErrHasherBusy) {
		w.Header().Set("Retry-After", "2")
		renderErr(http.StatusServiceUnavailable, "Authentication service is busy. Please try again shortly.")
		return
	}
	if err != nil || !matched {
		renderErr(http.StatusUnauthorized, genericAuthErr)
		return
	}

	// Rotate any pre-existing session to prevent session fixation.
	s.sessions.Destroy(r.Context(), w, r)
	if _, err := s.sessions.Create(r.Context(), w, u.ID); err != nil {
		s.logger.Error("create session failed", "err", err)
		renderErr(http.StatusInternalServerError, "Failed to establish session.")
		return
	}
	http.Redirect(w, r, nextPath, http.StatusSeeOther)
}

func (s *Server) handleLogoutPost(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Cache-Control", "private, no-store")

	sess, _, ok := s.sessions.Current(r.Context(), r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	if !auth.VerifyCSRFToken(sess.CSRFToken, r.PostForm.Get("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	s.sessions.Destroy(r.Context(), w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type signupViewData struct {
	CSRFToken string
	Username  string
	Error     string
	Notice    string
}

func (s *Server) handleSignupGet(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !settings.AllowSignup {
		http.Error(w, "Account registration is currently disabled.", http.StatusForbidden)
		return
	}
	csrfTok, err := s.sessions.IssuePreLoginCSRF(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, http.StatusOK, "signup.html", signupViewData{CSRFToken: csrfTok})
}

func (s *Server) handleSignupPost(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !settings.AllowSignup {
		http.Error(w, "Account registration is currently disabled.", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}

	rawUser := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")

	renderPage := func(status int, errMsg, noticeMsg string) {
		csrfTok, _ := s.sessions.IssuePreLoginCSRF(w, r)
		userVal := rawUser
		if noticeMsg != "" {
			userVal = ""
		}
		s.renderTemplate(w, status, "signup.html", signupViewData{
			CSRFToken: csrfTok,
			Username:  userVal,
			Error:     errMsg,
			Notice:    noticeMsg,
		})
	}

	if !s.sessions.VerifyPreLoginCSRF(r, r.PostForm.Get("csrf_token")) {
		renderPage(http.StatusForbidden, "Session verification expired. Please try again.", "")
		return
	}

	ipKey := auth.RateLimitIPKey(auth.ExtractClientIP(r))
	userKey := strings.ToLower(rawUser)
	if userKey == "" {
		userKey = "_"
	}
	if !s.signupIPLimit.Allow(ipKey) || !s.signupUserLimit.Allow(ipKey+":"+userKey) {
		w.Header().Set("Retry-After", "60")
		renderPage(http.StatusTooManyRequests, "Too many account requests. Please wait a minute.", "")
		return
	}

	normUser, err := db.NormalizeUsername(rawUser)
	if err != nil {
		renderPage(http.StatusBadRequest, "Username must be 3-64 characters using lowercase letters, numbers, '.', '_', or '-'.", "")
		return
	}

	hash, err := s.hasher.Hash(r.Context(), password)
	if errors.Is(err, auth.ErrPasswordTooShort) || errors.Is(err, auth.ErrPasswordTooLong) {
		renderPage(http.StatusBadRequest, fmt.Sprintf("Password must be between %d and %d bytes.", auth.MinPasswordBytes, auth.MaxPasswordBytes), "")
		return
	}
	if errors.Is(err, auth.ErrHasherBusy) {
		w.Header().Set("Retry-After", "2")
		renderPage(http.StatusServiceUnavailable, "Service is busy. Please try again shortly.", "")
		return
	}
	if err != nil {
		renderPage(http.StatusInternalServerError, "Failed to process account request.", "")
		return
	}

	_, err = s.store.CreateUser(r.Context(), normUser, hash, store.RoleUser, store.UserStatusPending)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		s.logger.Error("create pending user failed", "err", err)
		renderPage(http.StatusInternalServerError, "Failed to create account request.", "")
		return
	}

	// Uniform response on success and username conflict to prevent username enumeration.
	renderPage(http.StatusOK, "", "Account request submitted. An administrator must approve your account before you can sign in.")
}

type scopeOption struct {
	Name        string
	Description string
	Required    bool
}

type consentViewData struct {
	User           store.User
	CSRFToken      string
	ClientID       string
	ClientName     string
	RedirectURI    string
	CodeChallenge  string
	State          string
	RequestedScope string
	Resource       string
	ScopeOptions   []scopeOption
	Error          string
}

func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.AuthorizeCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	authReq, err := s.oauth.ValidateAuthorizeParams(r, r.URL.Query())
	if err != nil {
		s.handleAuthorizeValidationErr(w, r, err)
		return
	}

	sess, u, ok := s.sessions.Current(r.Context(), r)
	if !ok {
		loginURL := "/login?next=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	s.renderTemplate(w, http.StatusOK, "consent.html", buildConsentViewData(u, sess.CSRFToken, authReq, ""))
}

func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.AuthorizeCSP)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	sess, u, ok := s.sessions.Current(r.Context(), r)
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	if !auth.VerifyCSRFToken(sess.CSRFToken, r.PostForm.Get("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	authReq, err := s.oauth.ValidateAuthorizeParams(r, r.PostForm)
	if err != nil {
		s.handleAuthorizeValidationErr(w, r, err)
		return
	}

	if r.PostForm.Get("decision") != "approve" {
		denyURL := auth.BuildRedirectURL(authReq.RedirectURI, map[string]string{
			"error":             "access_denied",
			"error_description": "user denied authorization",
			"state":             authReq.State,
		})
		http.Redirect(w, r, denyURL, http.StatusFound)
		return
	}

	var granted []string
	for _, sc := range r.PostForm["granted_scope"] {
		if slices.Contains(authReq.Scopes, sc) && !slices.Contains(granted, sc) {
			granted = append(granted, sc)
		}
	}
	if len(granted) == 0 {
		s.renderTemplate(w, http.StatusBadRequest, "consent.html", buildConsentViewData(u, sess.CSRFToken, authReq, "Select at least one permission to approve."))
		return
	}

	redirectURL, err := s.oauth.IssueAuthorizationCode(r, authReq, u.ID, granted)
	if err != nil {
		s.logger.Error("issue oauth authorization code failed", "err", err)
		errURL := auth.BuildRedirectURL(authReq.RedirectURI, map[string]string{
			"error":             "server_error",
			"error_description": "failed to issue authorization code",
			"state":             authReq.State,
		})
		http.Redirect(w, r, errURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleAuthorizeValidationErr(w http.ResponseWriter, r *http.Request, err error) {
	var authErr *auth.AuthorizeError
	if errors.As(err, &authErr) {
		target := auth.BuildRedirectURL(authErr.RedirectURI, map[string]string{
			"error":             authErr.Code,
			"error_description": authErr.Description,
			"state":             authErr.State,
		})
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	// Invalid client_id or redirect_uri MUST return HTTP 400 directly and NEVER redirect.
	http.Error(w, "Invalid OAuth authorization request: "+err.Error(), http.StatusBadRequest)
}

func buildConsentViewData(u store.User, csrfToken string, req auth.AuthorizeRequest, errMsg string) consentViewData {
	opts := make([]scopeOption, 0, len(req.Scopes))
	hasRead := slices.Contains(req.Scopes, auth.ScopeRead)
	for _, sc := range req.Scopes {
		switch sc {
		case auth.ScopeRead:
			opts = append(opts, scopeOption{
				Name:        sc,
				Description: "List and read your artifacts",
				Required:    true,
			})
		case auth.ScopeWrite:
			opts = append(opts, scopeOption{
				Name:        sc,
				Description: "Publish, upload, update, and delete your artifacts",
				Required:    !hasRead,
			})
		}
	}
	return consentViewData{
		User:           u,
		CSRFToken:      csrfToken,
		ClientID:       req.Client.ClientID,
		ClientName:     req.Client.ClientName,
		RedirectURI:    req.RedirectURI,
		CodeChallenge:  req.CodeChallenge,
		State:          req.State,
		RequestedScope: req.Scope,
		Resource:       req.Resource,
		ScopeOptions:   opts,
		Error:          errMsg,
	}
}

func (s *Server) handleUploadPut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	select {
	case s.uploadSem <- struct{}{}:
		defer func() { <-s.uploadSem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "upload concurrency limit reached; retry shortly"})
		return
	}

	rawToken := strings.TrimSpace(r.PathValue("token"))
	if rawToken == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid upload token"})
		return
	}
	tokenHash := auth.SHA256Bytes(rawToken)

	tok, err := s.store.PeekUploadToken(r.Context(), tokenHash)
	if errors.Is(err, store.ErrUploadTokenInvalid) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid, used, or expired upload token"})
		return
	}
	if err != nil {
		s.logger.Error("peek upload token failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate upload token"})
		return
	}

	if rawCT := strings.TrimSpace(r.Header.Get("Content-Type")); rawCT != "" {
		mt, _, parseErr := mime.ParseMediaType(rawCT)
		if parseErr != nil {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{
				"error": "malformed Content-Type header",
			})
			return
		}
		mt = strings.ToLower(mt)
		if mt != "application/octet-stream" && mt != "application/x-www-form-urlencoded" && mt != tok.ExpectedContentType {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{
				"error": fmt.Sprintf("expected Content-Type %s, got %s", tok.ExpectedContentType, mt),
			})
			return
		}
	}

	if r.ContentLength > tok.MaxBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": fmt.Sprintf("upload exceeds max size of %d bytes", tok.MaxBytes),
		})
		return
	}

	// Extend deadlines for large (up to 50 MiB) binary uploads.
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(5 * time.Minute)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)

	r.Body = http.MaxBytesReader(w, r.Body, tok.MaxBytes)
	var buf bytes.Buffer
	if r.ContentLength > 0 && r.ContentLength <= tok.MaxBytes {
		buf.Grow(int(r.ContentLength))
	}
	if _, err := io.Copy(&buf, r.Body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error": fmt.Sprintf("upload exceeds max size of %d bytes", tok.MaxBytes),
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read upload body"})
		return
	}
	data := buf.Bytes()

	if err := artifact.ValidatePayload(tok.ExpectedContentType, data); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		s.logger.Error("load settings during upload failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load server settings"})
		return
	}

	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])

	art, err := s.store.CompleteUpload(r.Context(), tokenHash, data, hexSum, int64(settings.MaxStorageMBPerUser)<<20)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrUploadTokenInvalid):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "upload token was already used or expired"})
		case errors.Is(err, store.ErrUserInactive):
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "owner account is not active"})
		case errors.Is(err, store.ErrQuotaExceeded):
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "user storage quota exceeded"})
		case errors.Is(err, store.ErrNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "target artifact no longer exists"})
		default:
			s.logger.Error("complete upload failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store uploaded artifact"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           art.ID,
		"title":        art.Title,
		"content_type": art.ContentType,
		"visibility":   art.Visibility,
		"version":      art.Version,
		"size_bytes":   art.SizeBytes,
		"sha256":       art.SHA256,
		"viewer_url":   s.publicBaseURL + "/v/" + art.ID,
		"raw_url":      s.publicBaseURL + "/raw/" + art.ID,
	})
}

type viewerData struct {
	Artifact         store.Artifact
	User             *store.User
	MediaLabel       string
	SizeLabel        string
	IsHTML           bool
	IsPDF            bool
	IsMarkdown       bool
	RenderedMarkdown template.HTML
}

type notFoundData struct {
	User *store.User
	Next string
}

func (s *Server) handleViewer(w http.ResponseWriter, r *http.Request) {
	setShellHeaders(w, artifact.ShellCSP)
	w.Header().Set("Vary", "Cookie")

	id := strings.TrimSpace(r.PathValue("id"))
	art, userPtr, ok := s.loadViewableArtifact(r, id)
	if !ok {
		w.Header().Set("Cache-Control", "private, no-store")
		nextPath := auth.SafeNextPath("/v/" + id)
		s.renderTemplate(w, http.StatusNotFound, "notfound.html", notFoundData{
			User: userPtr,
			Next: nextPath,
		})
		return
	}

	if art.Visibility == artifact.VisibilityPrivate || userPtr != nil {
		w.Header().Set("Cache-Control", "private, no-store")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	spec, _ := artifact.LookupMedia(art.ContentType)
	data := viewerData{
		Artifact:   art,
		User:       userPtr,
		MediaLabel: spec.Label,
		SizeLabel:  formatBytes(art.SizeBytes),
		IsHTML:     art.ContentType == "text/html",
		IsPDF:      art.ContentType == "application/pdf",
		IsMarkdown: art.ContentType == "text/markdown",
	}
	if data.MediaLabel == "" {
		data.MediaLabel = art.ContentType
	}

	if data.IsMarkdown {
		blob, err := s.store.GetArtifactBlob(r.Context(), art.ID)
		if err != nil {
			s.logger.Error("load markdown blob failed", "id", art.ID, "err", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		rendered, err := s.markdown.Render(blob)
		if err != nil {
			s.logger.Error("render markdown failed", "id", art.ID, "err", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.RenderedMarkdown = rendered
	}

	s.renderTemplate(w, http.StatusOK, "viewer.html", data)
}

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")

	id := strings.TrimSpace(r.PathValue("id"))
	art, _, ok := s.loadViewableArtifact(r, id)
	if !ok {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Vary", "Cookie")
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	isDownload := r.URL.Query().Get("download") == "1"

	if art.Visibility == artifact.VisibilityPrivate {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Vary", "Cookie")
	} else {
		etag := fmt.Sprintf(`"%s"`, art.SHA256)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etag)
		if !isDownload && matchETag(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	allowedCDNs := artifact.DefaultAllowedCDNOrigins
	if settings, err := s.store.GetSettings(r.Context()); err == nil {
		allowedCDNs = settings.AllowedCDNOrigins
	}
	w.Header().Set("Content-Security-Policy", artifact.BuildRawCSP(art.ContentType, allowedCDNs))

	disposition := "inline"
	if isDownload {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", artifact.SafeContentDisposition(disposition, art.Title, art.ContentType))

	ctHeader := art.ContentType
	if spec, found := artifact.LookupMedia(art.ContentType); found && spec.IsText {
		ctHeader += "; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctHeader)

	blob, err := s.store.GetArtifactBlob(r.Context(), art.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		s.logger.Error("load raw artifact blob failed", "id", art.ID, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

func (s *Server) loadViewableArtifact(r *http.Request, id string) (store.Artifact, *store.User, bool) {
	var userPtr *store.User
	if _, u, ok := s.sessions.Current(r.Context(), r); ok {
		userCopy := u
		userPtr = &userCopy
	}
	if id == "" {
		return store.Artifact{}, userPtr, false
	}
	art, err := s.store.GetArtifact(r.Context(), id)
	if err != nil || art.Status != artifact.StatusReady {
		return store.Artifact{}, userPtr, false
	}
	if art.Visibility == artifact.VisibilityPrivate {
		if userPtr == nil || userPtr.ID != art.OwnerID {
			return store.Artifact{}, userPtr, false
		}
	}
	return art, userPtr, true
}

func (s *Server) renderTemplate(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, data); err != nil {
		s.logger.Error("render template failed", "template", name, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func setShellHeaders(w http.ResponseWriter, csp string) {
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func matchETag(headerVal, etag string) bool {
	if headerVal == "" {
		return false
	}
	for _, part := range strings.Split(headerVal, ",") {
		tag := strings.TrimSpace(part)
		tag = strings.TrimPrefix(tag, "W/")
		if tag == etag || tag == "*" {
			return true
		}
	}
	return false
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
