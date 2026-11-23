package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cubus.sh/artifact/internal/store"
)

func makePKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	v, err := RandomToken(48)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestPasswordHasherBoundsAndConcurrency(t *testing.T) {
	h := NewPasswordHasher(1)
	ctx := context.Background()

	if _, err := h.Hash(ctx, "short11byte"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
	if _, err := h.Hash(ctx, strings.Repeat("a", 129)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("expected ErrPasswordTooLong, got %v", err)
	}

	encoded, err := h.Hash(ctx, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	ok, err := h.Verify(ctx, "correct-horse-battery-staple", encoded)
	if err != nil || !ok {
		t.Fatalf("Verify valid password failed: ok=%v err=%v", ok, err)
	}
	ok, err = h.Verify(ctx, "wrong-password-12345", encoded)
	if err != nil || ok {
		t.Fatalf("Verify wrong password should be false: ok=%v err=%v", ok, err)
	}
	if err := h.VerifyDummy(ctx, "any-password"); err != nil {
		t.Fatalf("VerifyDummy failed: %v", err)
	}

	// Saturate semaphore (cap=1) and ensure canceled context returns ErrHasherBusy.
	h.sem <- struct{}{}
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = h.Verify(canceledCtx, "correct-horse-battery-staple", encoded)
	<-h.sem
	if !errors.Is(err, ErrHasherBusy) {
		t.Fatalf("expected ErrHasherBusy when semaphore saturated, got %v", err)
	}
}

func TestExtractClientIPAndRateLimitKey(t *testing.T) {
	// Trusted proxy: trusts X-Real-IP and ignores spoofed X-Forwarded-For.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "172.18.0.5:54321"
	req.Header.Set("X-Real-IP", "203.0.113.42")
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.42")
	got := ExtractClientIP(req)
	if got.String() != "203.0.113.42" {
		t.Fatalf("expected X-Real-IP 203.0.113.42, got %s", got)
	}

	// Untrusted public peer: ignores X-Real-IP spoofing.
	req2 := httptest.NewRequest(http.MethodPost, "/login", nil)
	req2.RemoteAddr = "198.51.100.9:12345"
	req2.Header.Set("X-Real-IP", "1.2.3.4")
	got2 := ExtractClientIP(req2)
	if got2.String() != "198.51.100.9" {
		t.Fatalf("expected RemoteAddr 198.51.100.9, got %s", got2)
	}

	// IPv6 addresses in the same /64 share a rate-limit bucket.
	req3 := httptest.NewRequest(http.MethodPost, "/login", nil)
	req3.RemoteAddr = "127.0.0.1:12345"
	req3.Header.Set("X-Real-IP", "2001:db8:abcd:0012::cafe")
	req4 := httptest.NewRequest(http.MethodPost, "/login", nil)
	req4.RemoteAddr = "127.0.0.1:12345"
	req4.Header.Set("X-Real-IP", "2001:db8:abcd:0012:ffff::1")
	if RateLimitIPKey(ExtractClientIP(req3)) != RateLimitIPKey(ExtractClientIP(req4)) {
		t.Fatalf("expected same /64 bucket for IPv6 peers")
	}
}

func TestSessionCookieAndSafeNextPath(t *testing.T) {
	st := store.NewMemoryStore()
	httpsMgr := NewSessionManager(st, true)
	if httpsMgr.SessionCookieName() != "__Host-artifact_session" {
		t.Fatalf("expected __Host- cookie prefix on HTTPS, got %q", httpsMgr.SessionCookieName())
	}
	httpMgr := NewSessionManager(st, false)
	if httpMgr.SessionCookieName() != "artifact_session" {
		t.Fatalf("expected unprefixed cookie on local HTTP, got %q", httpMgr.SessionCookieName())
	}

	for _, safe := range []string{"/", "/v/abc123", "/oauth/authorize?client_id=abc"} {
		if got := SafeNextPath(safe); got != safe {
			t.Fatalf("SafeNextPath(%q) = %q, want %q", safe, got, safe)
		}
	}
	for _, unsafe := range []string{"//evil.com", `/\evil.com`, "https://evil.com/v/1", "/admin/v1/users", "/v/abc\r\nSet-Cookie: x=1"} {
		if got := SafeNextPath(unsafe); got != "/" {
			t.Fatalf("SafeNextPath(%q) = %q, want /", unsafe, got)
		}
	}
}

func TestOAuth21FullLifecycleAndSecurityInvariants(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	user, err := st.CreateUser(ctx, "alice", "hash", store.RoleAdmin, store.UserStatusActive)
	if err != nil {
		t.Fatal(err)
	}

	oauth := NewOAuthServer(st, "https://artifact.cubus.sh")

	// 1. DCR rejects invalid redirect URIs.
	badDCR := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewBufferString(`{
		"client_name":"Bad Client",
		"redirect_uris":["http://127.0.0.1.evil.com/callback"]
	}`))
	badDCR.RemoteAddr = "127.0.0.1:9000"
	rec := httptest.NewRecorder()
	oauth.HandleRegister(rec, badDCR)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for spoofed loopback redirect_uri, got %d", rec.Code)
	}

	// 2. DCR succeeds with 201 Created for loopback + https callbacks.
	goodDCR := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewBufferString(`{
		"client_name":"Test MCP Client",
		"redirect_uris":["http://127.0.0.1/callback", "https://claude.ai/api/mcp/auth_callback"],
		"token_endpoint_auth_method":"none"
	}`))
	goodDCR.RemoteAddr = "127.0.0.1:9000"
	rec = httptest.NewRecorder()
	oauth.HandleRegister(rec, goodDCR)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from DCR, got %d: %s", rec.Code, rec.Body.String())
	}
	var regResp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &regResp); err != nil || regResp.ClientID == "" {
		t.Fatalf("invalid DCR response: %s", rec.Body.String())
	}

	// 3. ValidateAuthorizeParams: RFC 8252 §7.3 dynamic loopback port matches,
	//    while spoofed host returns plain error (HTTP 400, NEVER *AuthorizeError redirect).
	verifier, challenge := makePKCEPair(t)
	badParams := url.Values{
		"client_id":             {regResp.ClientID},
		"redirect_uri":          {"http://127.0.0.1.evil.com/callback"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	_, err = oauth.ValidateAuthorizeParams(httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil), badParams)
	var authErr *AuthorizeError
	if err == nil || errors.As(err, &authErr) {
		t.Fatalf("expected non-redirectable plain error for unregistered redirect_uri, got %#v", err)
	}

	// Wrong resource returns redirectable invalid_target.
	badResParams := url.Values{
		"client_id":             {regResp.ClientID},
		"redirect_uri":          {"http://127.0.0.1:54321/callback"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {"https://other.cubus.sh/mcp"},
	}
	_, err = oauth.ValidateAuthorizeParams(httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil), badResParams)
	if !errors.As(err, &authErr) || authErr.Code != "invalid_target" {
		t.Fatalf("expected redirectable invalid_target error, got %#v", err)
	}

	// Valid authorize params with RFC 8252 dynamic loopback port.
	goodParams := url.Values{
		"client_id":             {regResp.ClientID},
		"redirect_uri":          {"http://127.0.0.1:54321/callback"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"artifacts:read artifacts:write"},
		"resource":              {"https://artifact.cubus.sh/mcp"},
	}
	reqObj := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	authReq, err := oauth.ValidateAuthorizeParams(reqObj, goodParams)
	if err != nil {
		t.Fatalf("ValidateAuthorizeParams failed: %v", err)
	}

	redirectTarget, err := oauth.IssueAuthorizationCode(reqObj, authReq, user.ID, []string{ScopeRead, ScopeWrite})
	if err != nil {
		t.Fatalf("IssueAuthorizationCode failed: %v", err)
	}
	parsedRedirect, err := url.Parse(redirectTarget)
	if err != nil {
		t.Fatal(err)
	}
	code := parsedRedirect.Query().Get("code")
	if code == "" || parsedRedirect.Query().Get("state") != "xyz" {
		t.Fatalf("unexpected authorize redirect: %s", redirectTarget)
	}

	// 4. Exchange code for tokens.
	tokenCall := func(form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		oauth.HandleToken(w, r)
		return w
	}

	tokRec := tokenCall(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {regResp.ClientID},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:54321/callback"},
		"code_verifier": {verifier},
		"resource":      {"https://artifact.cubus.sh/mcp"},
	})
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token exchange failed: %d %s", tokRec.Code, tokRec.Body.String())
	}
	var tok1 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tok1); err != nil {
		t.Fatal(err)
	}

	// Verify access token via TokenVerifier.
	ti, err := oauth.TokenVerifier()(ctx, tok1.AccessToken, nil)
	if err != nil || ti.UserID != user.ID {
		t.Fatalf("TokenVerifier failed: %v %+v", err, ti)
	}

	// 5. Replaying the authorization code MUST fail AND revoke the token family!
	replayCodeRec := tokenCall(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {regResp.ClientID},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:54321/callback"},
		"code_verifier": {verifier},
	})
	if replayCodeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on auth code replay, got %d", replayCodeRec.Code)
	}
	if _, err := oauth.TokenVerifier()(ctx, tok1.AccessToken, nil); err == nil {
		t.Fatal("expected access token to be revoked after auth code replay")
	}

	// 6. Fresh auth code -> test refresh rotation, scope downscoping, non-escalation, and refresh reuse revocation.
	v2, c2 := makePKCEPair(t)
	goodParams.Set("code_challenge", c2)
	authReq2, err := oauth.ValidateAuthorizeParams(reqObj, goodParams)
	if err != nil {
		t.Fatal(err)
	}
	redir2, err := oauth.IssueAuthorizationCode(reqObj, authReq2, user.ID, []string{ScopeRead})
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := url.Parse(redir2)
	tokRec2 := tokenCall(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {regResp.ClientID},
		"code":          {u2.Query().Get("code")},
		"redirect_uri":  {"http://127.0.0.1:54321/callback"},
		"code_verifier": {v2},
	})
	if tokRec2.Code != http.StatusOK {
		t.Fatalf("second token exchange failed: %d %s", tokRec2.Code, tokRec2.Body.String())
	}
	var tok2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(tokRec2.Body.Bytes(), &tok2)

	// Attempting to escalate scope from artifacts:read to artifacts:write on refresh MUST fail with invalid_scope.
	escRec := tokenCall(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {regResp.ClientID},
		"refresh_token": {tok2.RefreshToken},
		"scope":         {"artifacts:read artifacts:write"},
	})
	if escRec.Code != http.StatusBadRequest || !strings.Contains(escRec.Body.String(), "invalid_scope") {
		t.Fatalf("expected invalid_scope on refresh escalation, got %d %s", escRec.Code, escRec.Body.String())
	}

	// Legitimate refresh rotation succeeds.
	rotRec := tokenCall(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {regResp.ClientID},
		"refresh_token": {tok2.RefreshToken},
	})
	if rotRec.Code != http.StatusOK {
		t.Fatalf("refresh rotation failed: %d %s", rotRec.Code, rotRec.Body.String())
	}
	var tok3 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rotRec.Body.Bytes(), &tok3)

	// Reusing the already-rotated tok2.RefreshToken MUST fail AND revoke the newly minted tok3.AccessToken!
	reuseRec := tokenCall(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {regResp.ClientID},
		"refresh_token": {tok2.RefreshToken},
	})
	if reuseRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on refresh token reuse, got %d", reuseRec.Code)
	}
	if _, err := oauth.TokenVerifier()(ctx, tok3.AccessToken, nil); err == nil {
		t.Fatal("expected rotated family's new access token to be revoked on refresh token reuse")
	}

	// 7. RFC 7009 revocation endpoint revokes active token.
	exp := time.Now().Add(time.Hour)
	rawActive, _ := RandomToken(32)
	_ = st.CreateOAuthToken(ctx, store.OAuthToken{
		FamilyID: "rev-fam", TokenHash: SHA256Bytes(rawActive), ClientID: regResp.ClientID, UserID: user.ID,
		Scope: ScopeRead, Resource: oauth.ResourceURL(), AccessExpiresAt: exp,
	})
	revReq := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{
		"client_id": {regResp.ClientID},
		"token":     {rawActive},
	}.Encode()))
	revReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revW := httptest.NewRecorder()
	oauth.HandleRevoke(revW, revReq)
	if revW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /oauth/revoke, got %d", revW.Code)
	}
	if _, err := oauth.TokenVerifier()(ctx, rawActive, nil); err == nil {
		t.Fatal("expected revoked token to fail verification")
	}

	// 8. Redirect URI validation rejects trailing empty '#' and invalid ports;
	//    DCR client registered without refresh_token receives no refresh_token.
	for _, badURI := range []string{"https://client.example/cb#", "http://127.0.0.1:99999/cb", "http://127.0.0.1:/cb"} {
		if err := ValidateRedirectURI(badURI); err == nil {
			t.Fatalf("expected ValidateRedirectURI to reject %q", badURI)
		}
	}
	if !MatchRegisteredRedirectURI([]string{"http://127.0.0.1"}, "http://127.0.0.1:54321/") {
		t.Fatal("expected empty path loopback redirect to match root '/'")
	}
	noRefDCR := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewBufferString(`{
		"client_name": "AuthCodeOnly",
		"redirect_uris": ["http://127.0.0.1/cb"],
		"grant_types": ["authorization_code"]
	}`))
	noRefDCR.RemoteAddr = "127.0.0.1:9001"
	noRefRec := httptest.NewRecorder()
	oauth.HandleRegister(noRefRec, noRefDCR)
	if noRefRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for auth-code-only DCR, got %d", noRefRec.Code)
	}
	var noRefReg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(noRefRec.Body.Bytes(), &noRefReg)
	v3, c3 := makePKCEPair(t)
	ar3, err := oauth.ValidateAuthorizeParams(reqObj, url.Values{
		"client_id": {noRefReg.ClientID}, "redirect_uri": {"http://127.0.0.1:45678/cb"},
		"response_type": {"code"}, "code_challenge": {c3}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r3, err := oauth.IssueAuthorizationCode(reqObj, ar3, user.ID, []string{ScopeRead})
	if err != nil {
		t.Fatal(err)
	}
	u3, _ := url.Parse(r3)
	t3Rec := tokenCall(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {noRefReg.ClientID},
		"code": {u3.Query().Get("code")}, "redirect_uri": {"http://127.0.0.1:45678/cb"}, "code_verifier": {v3},
	})
	if t3Rec.Code != http.StatusOK || strings.Contains(t3Rec.Body.String(), "refresh_token") {
		t.Fatalf("expected 200 without refresh_token for auth_code-only client, got %d %s", t3Rec.Code, t3Rec.Body.String())
	}
}
