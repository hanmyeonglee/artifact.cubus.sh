package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"cubus.sh/artifact/internal/auth"
	"cubus.sh/artifact/internal/mcpserver"
	"cubus.sh/artifact/internal/store"
)

type testEnv struct {
	ts      *httptest.Server
	store   *store.MemoryStore
	hasher  *auth.PasswordHasher
	oauth   *auth.OAuthServer
	alice   store.User
	bob     store.User
	baseURL string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st := store.NewMemoryStore()
	hasher := auth.NewPasswordHasher(4)
	ctx := context.Background()

	aliceHash, err := hasher.Hash(ctx, "alice-strong-password-123")
	if err != nil {
		t.Fatal(err)
	}
	bobHash, err := hasher.Hash(ctx, "bob-strong-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := st.CreateUser(ctx, "alice", aliceHash, store.RoleAdmin, store.UserStatusActive)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := st.CreateUser(ctx, "bob", bobHash, store.RoleUser, store.UserStatusActive)
	if err != nil {
		t.Fatal(err)
	}

	var handler http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	sessions := auth.NewSessionManager(st, false)
	oauthSrv := auth.NewOAuthServer(st, ts.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mcpSrv := mcpserver.New(st, oauthSrv, ts.URL, logger)
	webSrv, err := New(st, sessions, hasher, oauthSrv, mcpSrv, ts.URL, logger)
	if err != nil {
		t.Fatal(err)
	}
	handler = webSrv.Handler()

	return &testEnv{
		ts:      ts,
		store:   st,
		hasher:  hasher,
		oauth:   oauthSrv,
		alice:   alice,
		bob:     bob,
		baseURL: ts.URL,
	}
}

var csrfInputRe = regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`)

func extractCSRF(t *testing.T, html string) string {
	t.Helper()
	m := csrfInputRe.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("csrf_token hidden input not found in HTML: %s", html)
	}
	return m[1]
}

func (e *testEnv) newBrowserClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (e *testEnv) loginBrowser(t *testing.T, client *http.Client, username, password string) {
	t.Helper()
	resp, err := client.Get(e.baseURL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login failed: %d", resp.StatusCode)
	}
	csrf := extractCSRF(t, string(body))

	form := url.Values{
		"csrf_token": {csrf},
		"username":   {username},
		"password":   {password},
		"next":       {"/"},
	}
	req, _ := http.NewRequest(http.MethodPost, e.baseURL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.baseURL)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login failed for %s: status=%d", username, resp.StatusCode)
	}
}

func (e *testEnv) obtainOAuthAccessToken(t *testing.T, username, password string, grantedScopes []string) string {
	t.Helper()
	client := e.newBrowserClient(t)
	e.loginBrowser(t, client, username, password)

	// 1. Dynamic Client Registration
	dcrResp, err := http.Post(e.baseURL+"/oauth/register", "application/json", strings.NewReader(`{
		"client_name": "E2E MCP Client",
		"redirect_uris": ["http://127.0.0.1/cb"],
		"token_endpoint_auth_method": "none"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer dcrResp.Body.Close()
	if dcrResp.StatusCode != http.StatusCreated {
		t.Fatalf("DCR failed: %d", dcrResp.StatusCode)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(dcrResp.Body).Decode(&reg)

	// 2. GET /oauth/authorize
	verifier, _ := auth.RandomToken(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"client_id":             {reg.ClientID},
		"redirect_uri":          {"http://127.0.0.1:41234/cb"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st123"},
		"scope":                 {"artifacts:read artifacts:write"},
		"resource":              {e.baseURL + "/mcp"},
	}
	authGetResp, err := client.Get(e.baseURL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	consentHTML, _ := io.ReadAll(authGetResp.Body)
	authGetResp.Body.Close()
	if authGetResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/authorize failed: %d %s", authGetResp.StatusCode, string(consentHTML))
	}
	if authGetResp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected X-Frame-Options: DENY on consent page")
	}
	csrf := extractCSRF(t, string(consentHTML))

	// 3. POST /oauth/authorize (Approve)
	postForm := url.Values{
		"csrf_token":            {csrf},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {"http://127.0.0.1:41234/cb"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st123"},
		"scope":                 {"artifacts:read artifacts:write"},
		"resource":              {e.baseURL + "/mcp"},
		"decision":              {"approve"},
		"granted_scope":         grantedScopes,
	}
	req, _ := http.NewRequest(http.MethodPost, e.baseURL+"/oauth/authorize", strings.NewReader(postForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.baseURL)
	authPostResp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	authPostResp.Body.Close()
	if authPostResp.StatusCode != http.StatusFound {
		t.Fatalf("POST /oauth/authorize failed: %d", authPostResp.StatusCode)
	}
	loc, err := url.Parse(authPostResp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("missing auth code in redirect %q", loc.String())
	}

	// 4. POST /oauth/token
	tokResp, err := http.PostForm(e.baseURL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {reg.ClientID},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:41234/cb"},
		"code_verifier": {verifier},
		"resource":      {e.baseURL + "/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("POST /oauth/token failed: %d %s", tokResp.StatusCode, string(b))
	}
	var tokOut struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&tokOut)
	if tokOut.AccessToken == "" {
		t.Fatal("empty access_token")
	}
	return tokOut.AccessToken
}

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (b *bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(clone)
}

func (e *testEnv) connectMCP(t *testing.T, accessToken string) *mcp.ClientSession {
	t.Helper()
	cli := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1"}, nil)
	httpClient := &http.Client{
		Transport: &bearerRoundTripper{
			base:  http.DefaultTransport,
			token: accessToken,
		},
	}
	session, err := cli.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.baseURL + "/mcp",
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		t.Fatalf("MCP connect failed: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callToolJSON[T any](t *testing.T, sess *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, T) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%s) transport error: %v", name, err)
	}
	var out T
	if !res.IsError && len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			_ = json.Unmarshal([]byte(tc.Text), &out)
		}
	}
	return res, out
}

func TestCORSAndDiscoveryMetadata(t *testing.T) {
	env := newTestEnv(t)

	// OPTIONS /mcp must succeed with 204 (CORS outside RequireBearerToken).
	req, _ := http.NewRequest(http.MethodOptions, env.baseURL+"/mcp", nil)
	req.Header.Set("Origin", "https://claude.ai")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on OPTIONS /mcp, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
		t.Fatalf("missing WWW-Authenticate in Access-Control-Expose-Headers: %q", resp.Header.Get("Access-Control-Expose-Headers"))
	}

	// Unauthenticated POST /mcp returns 401 with PRM resource_metadata challenge.
	req, _ = http.NewRequest(http.MethodPost, env.baseURL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated /mcp, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("missing resource_metadata in WWW-Authenticate: %q", wwwAuth)
	}

	// PRM and AS metadata endpoints return 200 JSON with expected fields.
	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/healthz"} {
		r, err := http.Get(env.baseURL + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d", path, r.StatusCode)
		}
	}
}

func TestEndToEndMCPToolsViewerSecurityAndConcurrentUpload(t *testing.T) {
	env := newTestEnv(t)

	aliceToken := env.obtainOAuthAccessToken(t, "alice", "alice-strong-password-123", []string{auth.ScopeRead, auth.ScopeWrite})
	bobToken := env.obtainOAuthAccessToken(t, "bob", "bob-strong-password-1234", []string{auth.ScopeRead, auth.ScopeWrite})
	readOnlyToken := env.obtainOAuthAccessToken(t, "alice", "alice-strong-password-123", []string{auth.ScopeRead})

	aliceMCP := env.connectMCP(t, aliceToken)
	bobMCP := env.connectMCP(t, bobToken)
	readOnlyMCP := env.connectMCP(t, readOnlyToken)

	// 1. Read-only scope cannot publish.
	res, _ := callToolJSON[mcpserver.ArtifactView](t, readOnlyMCP, "publish_artifact", map[string]any{
		"title":        "Blocked",
		"content_type": "text/html",
		"content":      "<h1>nope</h1>",
	})
	if !res.IsError {
		t.Fatal("expected publish_artifact to fail with read-only token")
	}

	// 2. Alice publishes HTML artifact omitting visibility -> defaults to 'private'.
	res, htmlArt := callToolJSON[mcpserver.ArtifactView](t, aliceMCP, "publish_artifact", map[string]any{
		"title":        "Quarterly Dashboard",
		"content_type": "text/html",
		"content":      "<!doctype html><h1>Hello Artifact</h1>",
	})
	if res.IsError {
		t.Fatalf("publish_artifact failed: %+v", res.Content)
	}
	if htmlArt.Visibility != "private" || htmlArt.Version != 1 {
		t.Fatalf("expected private v1 artifact, got %+v", htmlArt)
	}

	// 3. Zero existence oracle: anonymous & Bob both get 404 on Alice's private artifact.
	anonResp, err := http.Get(env.baseURL + "/v/" + htmlArt.ID)
	if err != nil {
		t.Fatal(err)
	}
	anonResp.Body.Close()
	if anonResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for anonymous private /v/, got %d", anonResp.StatusCode)
	}

	bobBrowser := env.newBrowserClient(t)
	env.loginBrowser(t, bobBrowser, "bob", "bob-strong-password-1234")
	bobViewResp, err := bobBrowser.Get(env.baseURL + "/raw/" + htmlArt.ID)
	if err != nil {
		t.Fatal(err)
	}
	bobViewResp.Body.Close()
	if bobViewResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for Bob on Alice's private /raw/, got %d", bobViewResp.StatusCode)
	}

	// Bob also cannot read/delete Alice's artifact via MCP (IDOR check).
	idorRes, _ := callToolJSON[mcpserver.GetArtifactOutput](t, bobMCP, "get_artifact", map[string]any{"id": htmlArt.ID})
	if !idorRes.IsError {
		t.Fatal("expected Bob MCP get_artifact on Alice's artifact to fail")
	}

	// 4. Alice's browser CAN view her private artifact with strict security headers.
	aliceBrowser := env.newBrowserClient(t)
	env.loginBrowser(t, aliceBrowser, "alice", "alice-strong-password-123")
	vResp, err := aliceBrowser.Get(env.baseURL + "/v/" + htmlArt.ID)
	if err != nil {
		t.Fatal(err)
	}
	vBody, _ := io.ReadAll(vResp.Body)
	vResp.Body.Close()
	if vResp.StatusCode != http.StatusOK {
		t.Fatalf("Alice /v/ failed: %d", vResp.StatusCode)
	}
	if vResp.Header.Get("X-Frame-Options") != "DENY" ||
		vResp.Header.Get("Cache-Control") != "private, no-store" ||
		!strings.Contains(string(vBody), `sandbox="allow-scripts"`) {
		t.Fatalf("missing security headers/sandbox on /v/: headers=%v", vResp.Header)
	}

	rawResp, err := aliceBrowser.Get(env.baseURL + "/raw/" + htmlArt.ID)
	if err != nil {
		t.Fatal(err)
	}
	rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusOK {
		t.Fatalf("Alice /raw/ failed: %d", rawResp.StatusCode)
	}
	if rawResp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		rawResp.Header.Get("Referrer-Policy") != "no-referrer" ||
		rawResp.Header.Get("Cross-Origin-Resource-Policy") != "same-origin" ||
		rawResp.Header.Get("Cache-Control") != "private, no-store" ||
		!strings.Contains(rawResp.Header.Get("Content-Security-Policy"), "sandbox allow-scripts;") {
		t.Fatalf("missing security headers on /raw/: %v", rawResp.Header)
	}

	// 5. Alice updates artifact in place -> version 2 + public, now anonymous sees 200 + ETag 304.
	res, updated := callToolJSON[mcpserver.ArtifactView](t, aliceMCP, "update_artifact", map[string]any{
		"id":         htmlArt.ID,
		"visibility": "public",
		"content":    "<!doctype html><h1>Updated v2</h1>",
	})
	if res.IsError || updated.Version != 2 || updated.Visibility != "public" {
		t.Fatalf("update_artifact failed: res=%+v updated=%+v", res, updated)
	}

	pubRaw, err := http.Get(env.baseURL + "/raw/" + htmlArt.ID)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw.Body.Close()
	etag := pubRaw.Header.Get("ETag")
	if pubRaw.StatusCode != http.StatusOK || etag == "" {
		t.Fatalf("expected 200 with ETag for public /raw/, got %d etag=%q", pubRaw.StatusCode, etag)
	}

	condReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/raw/"+htmlArt.ID, nil)
	condReq.Header.Set("If-None-Match", etag)
	condResp, err := http.DefaultClient.Do(condReq)
	if err != nil {
		t.Fatal(err)
	}
	condResp.Body.Close()
	if condResp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified with matching ETag, got %d", condResp.StatusCode)
	}

	// Download flag sets attachment Content-Disposition.
	dlResp, err := http.Get(env.baseURL + "/raw/" + htmlArt.ID + "?download=1")
	if err != nil {
		t.Fatal(err)
	}
	dlResp.Body.Close()
	if !strings.HasPrefix(dlResp.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("expected attachment disposition, got %q", dlResp.Header.Get("Content-Disposition"))
	}

	// 6. Markdown rendering neutralizes XSS in /v/{id}.
	res, mdArt := callToolJSON[mcpserver.ArtifactView](t, aliceMCP, "publish_artifact", map[string]any{
		"title":        "Design Notes",
		"content_type": "text/markdown",
		"visibility":   "public",
		"content":      "# Notes\n\n<script>alert(1)</script>\n\n[x](javascript&colon;alert(1))",
	})
	if res.IsError {
		t.Fatalf("publish markdown failed: %+v", res.Content)
	}
	mdResp, err := http.Get(env.baseURL + "/v/" + mdArt.ID)
	if err != nil {
		t.Fatal(err)
	}
	mdHTML, _ := io.ReadAll(mdResp.Body)
	mdResp.Body.Close()
	if strings.Contains(strings.ToLower(string(mdHTML)), "<script>alert") || strings.Contains(strings.ToLower(string(mdHTML)), "javascript:") {
		t.Fatalf("unsanitized markdown rendered: %s", string(mdHTML))
	}

	// 7. create_upload + concurrent double PUT /upload/{token} under -race: strictly 1 winner!
	res, ticket := callToolJSON[mcpserver.CreateUploadOutput](t, aliceMCP, "create_upload", map[string]any{
		"title":        "Architecture Spec",
		"content_type": "application/pdf",
		"visibility":   "public",
	})
	if res.IsError || ticket.UploadURL == "" {
		t.Fatalf("create_upload failed: %+v", res.Content)
	}

	// Pending upload must return 404 on /v/{id} before upload finishes.
	pendResp, err := http.Get(ticket.ViewerURL)
	if err != nil {
		t.Fatal(err)
	}
	pendResp.Body.Close()
	if pendResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for pending_upload artifact, got %d", pendResp.StatusCode)
	}

	pdfBytes := []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n")
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	startCh := make(chan struct{})
	for i := range 2 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startCh
			req, _ := http.NewRequest(http.MethodPut, ticket.UploadURL, bytes.NewReader(pdfBytes))
			req.Header.Set("Content-Type", "application/pdf")
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("PUT %d failed: %v", idx, err)
				return
			}
			r.Body.Close()
			statuses[idx] = r.StatusCode
		}(i)
	}
	close(startCh)
	wg.Wait()

	okCount := 0
	for _, st := range statuses {
		if st == http.StatusOK {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("expected strictly 1 winner from concurrent double PUT, got statuses=%v", statuses)
	}

	// Uploaded PDF is now viewable.
	pdfResp, err := http.Get(env.baseURL + "/raw/" + ticket.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	pdfResp.Body.Close()
	if pdfResp.StatusCode != http.StatusOK || pdfResp.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("expected uploaded PDF 200, got %d ct=%q", pdfResp.StatusCode, pdfResp.Header.Get("Content-Type"))
	}

	// 8. list_artifacts, get_artifact, delete_artifact.
	res, listed := callToolJSON[mcpserver.ListArtifactsOutput](t, readOnlyMCP, "list_artifacts", map[string]any{})
	if res.IsError || listed.Count != 3 {
		t.Fatalf("expected 3 artifacts for Alice, got count=%d err=%v", listed.Count, res.IsError)
	}
	res, gotArt := callToolJSON[mcpserver.GetArtifactOutput](t, readOnlyMCP, "get_artifact", map[string]any{
		"id":              htmlArt.ID,
		"include_content": true,
	})
	if res.IsError || !strings.Contains(gotArt.Content, "Updated v2") {
		t.Fatalf("get_artifact include_content failed: %+v", gotArt)
	}
	res, delOut := callToolJSON[mcpserver.DeleteArtifactOutput](t, aliceMCP, "delete_artifact", map[string]any{"id": htmlArt.ID})
	if res.IsError || !delOut.Deleted {
		t.Fatalf("delete_artifact failed: %+v", res)
	}
}

func TestLoginCSRFAndPendingSignupGate(t *testing.T) {
	env := newTestEnv(t)

	// POST /login without pre-login CSRF cookie must fail with 403.
	req, _ := http.NewRequest(http.MethodPost, env.baseURL+"/login", strings.NewReader(url.Values{
		"username": {"alice"},
		"password": {"alice-strong-password-123"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", env.baseURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF cookie, got %d", resp.StatusCode)
	}

	// Cross-origin POST /login rejected by http.CrossOriginProtection.
	req2, _ := http.NewRequest(http.MethodPost, env.baseURL+"/login", strings.NewReader("username=alice"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", "https://evil.example")
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-site POST /login, got %d", resp2.StatusCode)
	}

	// Signup is disabled by default -> 403.
	resp3, err := http.Get(env.baseURL + "/signup")
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when allow_signup=false, got %d", resp3.StatusCode)
	}

	// Enable signup -> new user created as 'pending' and cannot sign in yet.
	allow := true
	if _, err := env.store.UpdateSettings(context.Background(), store.SettingsPatch{AllowSignup: &allow}); err != nil {
		t.Fatal(err)
	}
	browser := env.newBrowserClient(t)
	sGet, err := browser.Get(env.baseURL + "/signup")
	if err != nil {
		t.Fatal(err)
	}
	sBody, _ := io.ReadAll(sGet.Body)
	sGet.Body.Close()
	csrf := extractCSRF(t, string(sBody))

	sPostReq, _ := http.NewRequest(http.MethodPost, env.baseURL+"/signup", strings.NewReader(url.Values{
		"csrf_token": {csrf},
		"username":   {"charlie"},
		"password":   {"charlie-strong-password-123"},
	}.Encode()))
	sPostReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sPostReq.Header.Set("Origin", env.baseURL)
	sPostResp, err := browser.Do(sPostReq)
	if err != nil {
		t.Fatal(err)
	}
	sPostResp.Body.Close()
	if sPostResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on pending signup request, got %d", sPostResp.StatusCode)
	}

	u, err := env.store.GetUserByUsername(context.Background(), "charlie")
	if err != nil || u.Status != store.UserStatusPending {
		t.Fatalf("expected charlie with status=pending, got %+v err=%v", u, err)
	}

	// Pending user cannot sign in (401).
	lGet, _ := browser.Get(env.baseURL + "/login")
	lBody, _ := io.ReadAll(lGet.Body)
	lGet.Body.Close()
	lCSRF := extractCSRF(t, string(lBody))
	lPostReq, _ := http.NewRequest(http.MethodPost, env.baseURL+"/login", strings.NewReader(url.Values{
		"csrf_token": {lCSRF},
		"username":   {"charlie"},
		"password":   {"charlie-strong-password-123"},
	}.Encode()))
	lPostReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lPostReq.Header.Set("Origin", env.baseURL)
	lPostResp, err := browser.Do(lPostReq)
	if err != nil {
		t.Fatal(err)
	}
	lPostResp.Body.Close()
	if lPostResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for pending user login, got %d", lPostResp.StatusCode)
	}
}
