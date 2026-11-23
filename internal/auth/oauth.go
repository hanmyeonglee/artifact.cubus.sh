package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"cubus.sh/artifact/internal/store"
)

const (
	ScopeRead  = "artifacts:read"
	ScopeWrite = "artifacts:write"

	AuthCodeTTL     = 5 * time.Minute
	AccessTokenTTL  = 1 * time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour

	maxOAuthBodyBytes = 8 << 10 // 8 KiB
)

var supportedScopes = []string{ScopeRead, ScopeWrite}

type OAuthServer struct {
	store          store.Store
	issuer         string
	resourceURL    string
	dcrIPLimiter   *Limiter
	dcrGlobalLimit *Limiter
}

func NewOAuthServer(st store.Store, publicBaseURL string) *OAuthServer {
	issuer := strings.TrimRight(publicBaseURL, "/")
	return &OAuthServer{
		store:          st,
		issuer:         issuer,
		resourceURL:    issuer + "/mcp",
		dcrIPLimiter:   NewLimiter(10, 10),
		dcrGlobalLimit: NewLimiter(60, 60),
	}
}

func (o *OAuthServer) IssuerURL() string {
	return o.issuer
}

func (o *OAuthServer) ResourceURL() string {
	return o.resourceURL
}

func (o *OAuthServer) ResourceMetadataURL() string {
	return o.issuer + "/.well-known/oauth-protected-resource/mcp"
}

// CORSMiddleware handles browser MCP discovery & token preflight requests.
// Must sit OUTSIDE RequireBearerToken and NEVER wrap cookie-authenticated routes.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, Mcp-Session-Id, Mcp-Method, Mcp-Name, Last-Event-ID")
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (o *OAuthServer) ProtectedResourceMetadataHandler() http.Handler {
	return mcpauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               o.resourceURL,
		AuthorizationServers:   []string{o.issuer},
		ScopesSupported:        slices.Clone(supportedScopes),
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "cubus.sh Artifacts MCP",
	})
}

func (o *OAuthServer) HandleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	meta := map[string]any{
		"issuer":                                o.issuer,
		"authorization_endpoint":                o.issuer + "/oauth/authorize",
		"token_endpoint":                        o.issuer + "/oauth/token",
		"registration_endpoint":                 o.issuer + "/oauth/register",
		"revocation_endpoint":                   o.issuer + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      supportedScopes,
	}
	writeOAuthJSON(w, http.StatusOK, meta)
}

type dcrRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

func (o *OAuthServer) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	ipKey := RateLimitIPKey(ExtractClientIP(r))
	if !o.dcrGlobalLimit.Allow("global") || !o.dcrIPLimiter.Allow(ipKey) {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "client registration rate limit exceeded")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_client_metadata", "request body too large")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid request body")
		return
	}

	var req dcrRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON")
		return
	}

	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must contain 1..10 URIs")
		return
	}
	cleanRedirects := make([]string, 0, len(req.RedirectURIs))
	for _, rawURI := range req.RedirectURIs {
		if err := ValidateRedirectURI(rawURI); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
		cleanRedirects = append(cleanRedirects, strings.TrimSpace(rawURI))
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, g := range grantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_type: "+g)
			return
		}
	}
	if !slices.Contains(grantTypes, "authorization_code") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "authorization_code grant_type is required")
		return
	}

	if len(req.ResponseTypes) > 0 {
		for _, rt := range req.ResponseTypes {
			if rt != "code" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response_type: "+rt)
				return
			}
		}
	}

	authMethod := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" && authMethod != "client_secret_post" && authMethod != "client_secret_basic" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}

	clientName := strings.TrimSpace(req.ClientName)
	if clientName == "" {
		clientName = "MCP Client"
	}
	if len([]rune(clientName)) > 120 {
		clientName = string([]rune(clientName)[:120])
	}

	clientID, err := RandomToken(24)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate client_id")
		return
	}

	var clientSecret string
	var secretHash []byte
	if authMethod != "none" {
		clientSecret, err = RandomToken(32)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate client_secret")
			return
		}
		secretHash = SHA256Bytes(clientSecret)
	}

	rec := store.OAuthClient{
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		ClientName:              clientName,
		RedirectURIs:            cleanRedirects,
		GrantTypes:              grantTypes,
		TokenEndpointAuthMethod: authMethod,
	}
	if err := o.store.CreateOAuthClient(r.Context(), rec); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to persist client")
		return
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"client_name":                clientName,
		"redirect_uris":              cleanRedirects,
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
		"client_id_issued_at":        time.Now().Unix(),
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret
		resp["client_secret_expires_at"] = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	writeOAuthJSON(w, http.StatusCreated, resp)
}

type AuthorizeRequest struct {
	Client        store.OAuthClient
	RedirectURI   string
	State         string
	Scope         string
	Scopes        []string
	Resource      string
	CodeChallenge string
}

// AuthorizeError indicates a redirectable OAuth error after client_id and redirect_uri are verified.
type AuthorizeError struct {
	Code        string
	Description string
	RedirectURI string
	State       string
}

func (e *AuthorizeError) Error() string {
	return e.Code + ": " + e.Description
}

// ValidateAuthorizeParams validates GET/POST /oauth/authorize query/form values.
// Returns a plain error (HTTP 400 direct, NEVER redirect) if client_id or redirect_uri is invalid,
// or *AuthorizeError when redirect_uri is verified and errors may be redirected back to the client.
func (o *OAuthServer) ValidateAuthorizeParams(r *http.Request, values url.Values) (AuthorizeRequest, error) {
	clientID := strings.TrimSpace(values.Get("client_id"))
	redirectURI := strings.TrimSpace(values.Get("redirect_uri"))
	if clientID == "" || redirectURI == "" {
		return AuthorizeRequest{}, errors.New("client_id and redirect_uri are required")
	}

	client, err := o.store.GetOAuthClient(r.Context(), clientID)
	if err != nil {
		return AuthorizeRequest{}, errors.New("unknown client_id")
	}
	if !MatchRegisteredRedirectURI(client.RedirectURIs, redirectURI) {
		return AuthorizeRequest{}, errors.New("redirect_uri does not match registered URIs")
	}

	state := values.Get("state")
	redirectErr := func(code, desc string) error {
		return &AuthorizeError{Code: code, Description: desc, RedirectURI: redirectURI, State: state}
	}

	if values.Get("response_type") != "code" {
		return AuthorizeRequest{}, redirectErr("unsupported_response_type", "only response_type=code is supported")
	}
	if values.Get("code_challenge_method") != "S256" {
		return AuthorizeRequest{}, redirectErr("invalid_request", "PKCE code_challenge_method=S256 is required")
	}
	challenge := strings.TrimSpace(values.Get("code_challenge"))
	if !isValidPKCEChallenge(challenge) {
		return AuthorizeRequest{}, redirectErr("invalid_request", "invalid code_challenge")
	}

	scopes, scopeStr, err := NormalizeScopes(values.Get("scope"))
	if err != nil {
		return AuthorizeRequest{}, redirectErr("invalid_scope", err.Error())
	}

	resource, err := o.CanonicalizeResource(values.Get("resource"))
	if err != nil {
		return AuthorizeRequest{}, redirectErr("invalid_target", err.Error())
	}

	return AuthorizeRequest{
		Client:        client,
		RedirectURI:   redirectURI,
		State:         state,
		Scope:         scopeStr,
		Scopes:        scopes,
		Resource:      resource,
		CodeChallenge: challenge,
	}, nil
}

func (o *OAuthServer) IssueAuthorizationCode(r *http.Request, req AuthorizeRequest, userID string, grantedScopes []string) (string, error) {
	if len(grantedScopes) == 0 {
		return "", errors.New("at least one scope must be granted")
	}
	for _, s := range grantedScopes {
		if !slices.Contains(req.Scopes, s) {
			return "", errors.New("granted scope exceeds requested scope")
		}
	}

	rawCode, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	code := store.OAuthAuthCode{
		CodeHash:      SHA256Bytes(rawCode),
		FamilyID:      uuid.NewString(),
		ClientID:      req.Client.ClientID,
		UserID:        userID,
		RedirectURI:   req.RedirectURI,
		Scope:         strings.Join(grantedScopes, " "),
		Resource:      req.Resource,
		CodeChallenge: req.CodeChallenge,
		ExpiresAt:     time.Now().UTC().Add(AuthCodeTTL),
	}
	if err := o.store.CreateOAuthAuthCode(r.Context(), code); err != nil {
		return "", err
	}
	_ = o.store.TouchOAuthClient(r.Context(), req.Client.ClientID)
	return BuildRedirectURL(req.RedirectURI, map[string]string{
		"code":  rawCode,
		"state": req.State,
	}), nil
}

func (o *OAuthServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form body")
		return
	}

	grantType := r.PostForm.Get("grant_type")
	switch grantType {
	case "authorization_code":
		o.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		o.handleRefreshTokenGrant(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grant_types: authorization_code, refresh_token")
	}
}

func (o *OAuthServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	client, ok := o.authenticateClient(w, r)
	if !ok {
		return
	}

	rawCode := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if rawCode == "" || redirectURI == "" || !isValidPKCEVerifier(verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri, and valid code_verifier are required")
		return
	}

	reqResource, err := o.CanonicalizeResource(r.PostForm.Get("resource"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}

	codeRec, err := o.store.ConsumeOAuthAuthCode(r.Context(), SHA256Bytes(rawCode))
	if errors.Is(err, store.ErrCodeReplayed) || errors.Is(err, store.ErrNotFound) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired, or already-used authorization code")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to consume authorization code")
		return
	}

	if codeRec.ClientID != client.ClientID || codeRec.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri mismatch")
		return
	}
	if r.PostForm.Get("resource") != "" && reqResource != codeRec.Resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
		return
	}
	if !VerifyPKCES256(verifier, codeRec.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	u, err := o.store.GetUserByID(r.Context(), codeRec.UserID)
	if err != nil || u.Status != store.UserStatusActive {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user account is not active")
		return
	}

	allowRefresh := slices.Contains(client.GrantTypes, "refresh_token")
	accessTok, refreshTok, err := o.mintTokenPair(r, codeRec.FamilyID, client.ClientID, u.ID, codeRec.Scope, codeRec.Resource, allowRefresh)
	if errors.Is(err, store.ErrCodeReplayed) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code replay detected")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}
	_ = o.store.TouchOAuthClient(r.Context(), client.ClientID)

	resp := map[string]any{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   int(AccessTokenTTL.Seconds()),
		"scope":        codeRec.Scope,
	}
	if refreshTok != "" {
		resp["refresh_token"] = refreshTok
	}
	writeOAuthJSON(w, http.StatusOK, resp)
}

func (o *OAuthServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	client, ok := o.authenticateClient(w, r)
	if !ok {
		return
	}
	if !slices.Contains(client.GrantTypes, "refresh_token") {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for refresh_token grant")
		return
	}

	rawRefresh := r.PostForm.Get("refresh_token")
	if rawRefresh == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	var reqScope string
	if rawScope := strings.TrimSpace(r.PostForm.Get("scope")); rawScope != "" {
		_, normalized, err := NormalizeScopes(rawScope)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
			return
		}
		reqScope = normalized
	}

	reqResource := ""
	if rawRes := strings.TrimSpace(r.PostForm.Get("resource")); rawRes != "" {
		canon, err := o.CanonicalizeResource(rawRes)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
			return
		}
		reqResource = canon
	}

	newAccess, err := RandomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}
	newRefresh, err := RandomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate refresh token")
		return
	}
	now := time.Now().UTC()
	refExp := now.Add(RefreshTokenTTL)
	nextTok := store.OAuthToken{
		TokenHash:        SHA256Bytes(newAccess),
		RefreshTokenHash: SHA256Bytes(newRefresh),
		Scope:            reqScope,
		Resource:         reqResource,
		AccessExpiresAt:  now.Add(AccessTokenTTL),
		RefreshExpiresAt: &refExp,
	}

	rotated, _, err := o.store.RotateRefreshToken(r.Context(), SHA256Bytes(rawRefresh), client.ClientID, nextTok)
	if errors.Is(err, store.ErrScopeEscalation) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds original grant")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
		return
	}
	if errors.Is(err, store.ErrTokenReused) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrUserInactive) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired, or revoked refresh token")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to rotate refresh token")
		return
	}
	_ = o.store.TouchOAuthClient(r.Context(), client.ClientID)

	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"access_token":  newAccess,
		"token_type":    "Bearer",
		"expires_in":    int(AccessTokenTTL.Seconds()),
		"refresh_token": newRefresh,
		"scope":         rotated.Scope,
	})
}

func (o *OAuthServer) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form body")
		return
	}
	client, ok := o.authenticateClient(w, r)
	if !ok {
		return
	}
	tok := r.PostForm.Get("token")
	if tok != "" {
		_ = o.store.RevokeOAuthToken(r.Context(), SHA256Bytes(tok), client.ClientID)
	}
	w.WriteHeader(http.StatusOK)
}

func (o *OAuthServer) TokenVerifier() mcpauth.TokenVerifier {
	return func(ctx context.Context, rawToken string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		if rawToken == "" {
			return nil, mcpauth.ErrInvalidToken
		}
		tok, u, err := o.store.GetActiveAccessToken(ctx, SHA256Bytes(rawToken))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, mcpauth.ErrInvalidToken
			}
			return nil, err
		}
		if u.Status != store.UserStatusActive {
			return nil, mcpauth.ErrInvalidToken
		}
		if tok.Resource != o.resourceURL {
			return nil, mcpauth.ErrInvalidToken
		}
		return &mcpauth.TokenInfo{
			UserID:     u.ID,
			Scopes:     strings.Fields(tok.Scope),
			Expiration: tok.AccessExpiresAt,
			Extra: map[string]any{
				"username":  u.Username,
				"client_id": tok.ClientID,
			},
		}, nil
	}
}

func (o *OAuthServer) authenticateClient(w http.ResponseWriter, r *http.Request) (store.OAuthClient, bool) {
	var clientID, clientSecret string
	usedBasic := false

	if authz := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authz), "basic ") {
		if r.PostForm.Get("client_secret") != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "multiple client authentication methods used")
			return store.OAuthClient{}, false
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authz[6:]))
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid basic authorization header")
			return store.OAuthClient{}, false
		}
		idRaw, secRaw, ok := strings.Cut(string(decoded), ":")
		if !ok {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "malformed basic credentials")
			return store.OAuthClient{}, false
		}
		// RFC 6749 §2.3.1 URL-decoding for Basic credentials.
		idDec, err1 := url.QueryUnescape(idRaw)
		secDec, err2 := url.QueryUnescape(secRaw)
		if err1 != nil || err2 != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid URL-encoding in basic credentials")
			return store.OAuthClient{}, false
		}
		clientID, clientSecret = idDec, secDec
		usedBasic = true
	} else {
		clientID = r.PostForm.Get("client_id")
		clientSecret = r.PostForm.Get("client_secret")
	}

	if clientID == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client_id is required")
		return store.OAuthClient{}, false
	}

	client, err := o.store.GetOAuthClient(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return store.OAuthClient{}, false
	}

	switch client.TokenEndpointAuthMethod {
	case "none":
		return client, true
	case "client_secret_basic":
		if !usedBasic || !verifySecretHash(clientSecret, client.ClientSecretHash) {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return store.OAuthClient{}, false
		}
		return client, true
	case "client_secret_post":
		if usedBasic || !verifySecretHash(clientSecret, client.ClientSecretHash) {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return store.OAuthClient{}, false
		}
		return client, true
	default:
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unsupported client auth method")
		return store.OAuthClient{}, false
	}
}

func (o *OAuthServer) mintTokenPair(r *http.Request, familyID, clientID, userID, scope, resource string, issueRefresh bool) (string, string, error) {
	accessTok, err := RandomToken(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	var refreshTok string
	var refreshHash []byte
	var refExp *time.Time
	if issueRefresh {
		refreshTok, err = RandomToken(32)
		if err != nil {
			return "", "", err
		}
		refreshHash = SHA256Bytes(refreshTok)
		exp := now.Add(RefreshTokenTTL)
		refExp = &exp
	}
	err = o.store.CreateOAuthToken(r.Context(), store.OAuthToken{
		FamilyID:         familyID,
		TokenHash:        SHA256Bytes(accessTok),
		RefreshTokenHash: refreshHash,
		ClientID:         clientID,
		UserID:           userID,
		Scope:            scope,
		Resource:         resource,
		AccessExpiresAt:  now.Add(AccessTokenTTL),
		RefreshExpiresAt: refExp,
	})
	return accessTok, refreshTok, err
}

// CanonicalizeResource normalizes RFC 8707 resource indicators and enforces single-resource binding.
func (o *OAuthServer) CanonicalizeResource(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// Single-resource AS fallback for legacy MCP clients that omit resource.
		return o.resourceURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.RawQuery != "" || u.User != nil {
		return "", errors.New("invalid resource URI")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = host
	} else if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	u.Scheme = scheme
	u.Path = strings.TrimRight(u.Path, "/")
	canon := u.String()
	if canon == o.resourceURL || canon == o.issuer {
		return o.resourceURL, nil
	}
	return "", fmt.Errorf("resource %q does not match %s", raw, o.resourceURL)
}

func ValidateRedirectURI(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsRune(trimmed, '\\') || strings.ContainsRune(trimmed, '#') {
		return errors.New("invalid redirect_uri")
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return errors.New("redirect_uri contains whitespace or control characters")
		}
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.User != nil {
		return errors.New("redirect_uri must be an absolute URI without fragment or userinfo")
	}
	if port := u.Port(); port != "" {
		p, perr := strconv.Atoi(port)
		if perr != nil || p < 1 || p > 65535 {
			return errors.New("redirect_uri has invalid port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("redirect_uri has empty port")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "https" {
		if host == "" {
			return errors.New("https redirect_uri requires host")
		}
		return nil
	}
	if scheme == "http" && isLoopbackRedirectHost(host) {
		return nil
	}
	return errors.New("redirect_uri must use https:// or loopback http:// (127.0.0.1, ::1, localhost)")
}

// MatchRegisteredRedirectURI implements exact match for https:// and RFC 8252 §7.3
// dynamic loopback port matching for http://(127.0.0.1|::1|localhost).
func MatchRegisteredRedirectURI(registered []string, candidate string) bool {
	if err := ValidateRedirectURI(candidate); err != nil {
		return false
	}
	candURL, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	normPath := func(p string) string {
		if p == "" {
			return "/"
		}
		return p
	}
	for _, reg := range registered {
		if reg == candidate {
			return true
		}
		regURL, err := url.Parse(reg)
		if err != nil {
			continue
		}
		if strings.ToLower(regURL.Scheme) == "http" &&
			strings.ToLower(candURL.Scheme) == "http" &&
			isLoopbackRedirectHost(strings.ToLower(regURL.Hostname())) &&
			strings.EqualFold(regURL.Hostname(), candURL.Hostname()) &&
			normPath(regURL.Path) == normPath(candURL.Path) &&
			regURL.RawQuery == candURL.RawQuery {
			return true
		}
	}
	return false
}

func isLoopbackRedirectHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func NormalizeScopes(raw string) ([]string, string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return slices.Clone(supportedScopes), strings.Join(supportedScopes, " "), nil
	}
	out := make([]string, 0, len(fields))
	for _, s := range fields {
		if !slices.Contains(supportedScopes, s) {
			return nil, "", fmt.Errorf("unsupported scope %q", s)
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, strings.Join(out, " "), nil
}

func VerifyPKCES256(verifier, expectedChallenge string) bool {
	if !isValidPKCEVerifier(verifier) || !isValidPKCEChallenge(expectedChallenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedChallenge)) == 1
}

func isValidPKCEVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

func isValidPKCEChallenge(c string) bool {
	if len(c) < 43 || len(c) > 128 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func verifySecretHash(raw string, expectedHash []byte) bool {
	if raw == "" || len(expectedHash) == 0 {
		return false
	}
	got := SHA256Bytes(raw)
	return subtle.ConstantTimeCompare(got, expectedHash) == 1
}

func BuildRedirectURL(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeOAuthJSON(w, status, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func writeOAuthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
