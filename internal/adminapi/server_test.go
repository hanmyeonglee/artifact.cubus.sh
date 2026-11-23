package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"cubus.sh/artifact/internal/store"
)

func TestAdminAPICIDRAndAuthGuard(t *testing.T) {
	st := store.NewMemoryStore()
	cidr := netip.MustParsePrefix("172.31.0.0/24")
	srv := New(st, "admin-secret-token-123456", &cidr)
	h := srv.Handler()

	// Wrong subnet -> 403 even with valid token.
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/manifest", nil)
	req.RemoteAddr = "172.30.0.5:44444"
	req.Header.Set("Authorization", "Bearer admin-secret-token-123456")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for outside CIDR, got %d", rec.Code)
	}

	// Inside subnet, missing/wrong token -> 401.
	req = httptest.NewRequest(http.MethodGet, "/admin/v1/manifest", nil)
	req.RemoteAddr = "172.31.0.10:55555"
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", rec.Code)
	}

	// Inside subnet + valid token -> 200.
	req = httptest.NewRequest(http.MethodGet, "/admin/v1/manifest", nil)
	req.RemoteAddr = "172.31.0.10:55555"
	req.Header.Set("Authorization", "Bearer admin-secret-token-123456")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorized manifest, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminAPIUsersAndSettings(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()

	admin, err := st.CreateUser(ctx, "admin", "hash", store.RoleAdmin, store.UserStatusActive)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := st.CreateUser(ctx, "bob", "hash", store.RoleUser, store.UserStatusPending)
	if err != nil {
		t.Fatal(err)
	}

	srv := New(st, "admin-secret-token-123456", nil)
	h := srv.Handler()
	do := func(method, path string, body any) *httptest.ResponseRecorder {
		var rBody *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rBody = bytes.NewReader(b)
		} else {
			rBody = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rBody)
		req.RemoteAddr = "127.0.0.1:43210"
		req.Header.Set("Authorization", "Bearer admin-secret-token-123456")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Approve pending user.
	rec := do(http.MethodPost, "/admin/v1/users/"+bob.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", rec.Code, rec.Body.String())
	}

	// Give bob a web session and OAuth token, then deny -> must revoke both immediately.
	sessHash := []byte("bob-session-hash")
	if err := st.CreateWebSession(ctx, store.WebSession{
		TokenHash: sessHash, UserID: bob.ID, CSRFToken: "c", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	tokHash := []byte("bob-oauth-token")
	if err := st.CreateOAuthToken(ctx, store.OAuthToken{
		FamilyID: "fam1", TokenHash: tokHash, ClientID: "c1", UserID: bob.ID,
		Scope: "artifacts:read", Resource: "http://127.0.0.1:8000/mcp", AccessExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	rec = do(http.MethodPost, "/admin/v1/users/"+bob.ID+"/deny", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny bob failed: %d %s", rec.Code, rec.Body.String())
	}
	if _, _, err := st.GetWebSession(ctx, sessHash); err == nil {
		t.Fatal("expected denied user's web session to be revoked")
	}
	if _, _, err := st.GetActiveAccessToken(ctx, tokHash); err == nil {
		t.Fatal("expected denied user's OAuth token to be revoked")
	}

	// Denying the last active admin must fail with 409 Conflict.
	rec = do(http.MethodPost, "/admin/v1/users/"+admin.ID+"/deny", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 when denying last admin, got %d: %s", rec.Code, rec.Body.String())
	}

	// Settings patch rejects invalid bounds and CSP injection.
	rec = do(http.MethodPatch, "/admin/v1/settings", map[string]any{"max_upload_mb": 100})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_upload_mb=100, got %d", rec.Code)
	}
	rec = do(http.MethodPatch, "/admin/v1/settings", map[string]any{"allowed_cdn_origins": []string{"https://ok.example; connect-src *"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CSP injection in allowed_cdn_origins, got %d", rec.Code)
	}

	// Valid settings patch succeeds.
	rec = do(http.MethodPatch, "/admin/v1/settings", map[string]any{
		"allow_signup":        true,
		"max_upload_mb":       30,
		"allowed_cdn_origins": []string{"https://cdn.jsdelivr.net"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid settings patch, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated store.AppSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.AllowSignup || updated.MaxUploadMB != 30 || len(updated.AllowedCDNOrigins) != 1 {
		t.Fatalf("unexpected updated settings: %+v", updated)
	}
}

func TestAdminAPIArtifactsAndStrictAllowCIDR(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()

	alice, err := st.CreateUser(ctx, "alice", "hash", store.RoleAdmin, store.UserStatusActive)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := st.CreateUser(ctx, "bob", "hash", store.RoleUser, store.UserStatusActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateArtifactWithBlob(ctx, store.Artifact{
		ID: "art-1", OwnerID: alice.ID, Title: "Alice Report", ContentType: "text/html", Visibility: "private", SHA256: "aaa",
	}, []byte("<h1>a</h1>"), 10<<20, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateArtifactWithBlob(ctx, store.Artifact{
		ID: "art-2", OwnerID: bob.ID, Title: "Bob Slide", ContentType: "application/pdf", Visibility: "public", SHA256: "bbb",
	}, []byte("%PDF-1.7\n"), 10<<20, 100); err != nil {
		t.Fatal(err)
	}

	pinnedAdmin := netip.MustParsePrefix("172.31.0.2/32")
	srv := New(st, "admin-secret-token-123456", &pinnedAdmin, "https://artifact.cubus.sh")
	h := srv.Handler()

	// Sibling container on 172.31.0.130 MUST be rejected (403) even with valid token.
	sibReq := httptest.NewRequest(http.MethodGet, "/admin/v1/artifacts", nil)
	sibReq.RemoteAddr = "172.31.0.130:54321"
	sibReq.Header.Set("Authorization", "Bearer admin-secret-token-123456")
	sibRec := httptest.NewRecorder()
	h.ServeHTTP(sibRec, sibReq)
	if sibRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for sibling IP 172.31.0.130, got %d", sibRec.Code)
	}

	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "172.31.0.2:41234"
		req.Header.Set("Authorization", "Bearer admin-secret-token-123456")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Manifest includes artifacts capability and settings_schema.
	manRec := do(http.MethodGet, "/admin/v1/manifest")
	if manRec.Code != http.StatusOK || !bytes.Contains(manRec.Body.Bytes(), []byte("settings_schema")) {
		t.Fatalf("unexpected manifest: %d %s", manRec.Code, manRec.Body.String())
	}

	// List all artifacts filtered by owner username.
	listRec := do(http.MethodGet, "/admin/v1/artifacts?owner=bob&visibility=public")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list artifacts failed: %d %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Artifacts  []map[string]any `json:"artifacts"`
		TotalCount int              `json:"total_count"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.TotalCount != 1 || len(listResp.Artifacts) != 1 || listResp.Artifacts[0]["owner_username"] != "bob" ||
		listResp.Artifacts[0]["viewer_url"] != "https://artifact.cubus.sh/v/art-2" {
		t.Fatalf("unexpected filtered artifacts: %+v", listResp)
	}

	// Invalid pagination bounds -> 400.
	if badRec := do(http.MethodGet, "/admin/v1/artifacts?limit=500"); badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for limit=500, got %d", badRec.Code)
	}

	// Delete artifact by ID -> 200, second delete -> 404.
	if delRec := do(http.MethodDelete, "/admin/v1/artifacts/art-2"); delRec.Code != http.StatusOK {
		t.Fatalf("delete artifact failed: %d %s", delRec.Code, delRec.Body.String())
	}
	if delRec2 := do(http.MethodDelete, "/admin/v1/artifacts/art-2"); delRec2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on second delete, got %d", delRec2.Code)
	}
}
