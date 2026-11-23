package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"cubus.sh/artifact/internal/artifact"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrLastAdmin          = errors.New("cannot deny the last active admin")
	ErrCodeReplayed       = errors.New("authorization code already used")
	ErrTokenReused        = errors.New("refresh token reuse detected")
	ErrUserInactive       = errors.New("user account is not active")
	ErrUploadTokenInvalid = errors.New("upload token is invalid, used, or expired")
	ErrQuotaExceeded      = errors.New("storage or artifact count quota exceeded")
	ErrScopeEscalation    = errors.New("requested scope exceeds original grant")
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"

	UserStatusPending = "pending"
	UserStatusActive  = "active"
	UserStatusDenied  = "denied"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type UserSummary struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	Role          string    `json:"role"`
	Status        string    `json:"status"`
	ArtifactCount int       `json:"artifact_count"`
	StorageBytes  int64     `json:"storage_bytes"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type AppSettings struct {
	AllowSignup         bool     `json:"allow_signup"`
	MaxUploadMB         int      `json:"max_upload_mb"`
	MaxStorageMBPerUser int      `json:"max_storage_mb_per_user"`
	AllowedCDNOrigins   []string `json:"allowed_cdn_origins"`
}

func DefaultAppSettings() AppSettings {
	origins := make([]string, len(artifact.DefaultAllowedCDNOrigins))
	copy(origins, artifact.DefaultAllowedCDNOrigins)
	return AppSettings{
		AllowSignup:         false,
		MaxUploadMB:         20,
		MaxStorageMBPerUser: 1024,
		AllowedCDNOrigins:   origins,
	}
}

type SettingsPatch struct {
	AllowSignup         *bool     `json:"allow_signup,omitempty"`
	MaxUploadMB         *int      `json:"max_upload_mb,omitempty"`
	MaxStorageMBPerUser *int      `json:"max_storage_mb_per_user,omitempty"`
	AllowedCDNOrigins   *[]string `json:"allowed_cdn_origins,omitempty"`
}

type WebSession struct {
	TokenHash []byte
	UserID    string
	CSRFToken string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type OAuthClient struct {
	ClientID                string
	ClientSecretHash        []byte
	ClientName              string
	RedirectURIs            []string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	CreatedAt               time.Time
	LastUsedAt              *time.Time
}

type OAuthAuthCode struct {
	CodeHash      []byte
	FamilyID      string
	ClientID      string
	UserID        string
	RedirectURI   string
	Scope         string
	Resource      string
	CodeChallenge string
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

type OAuthToken struct {
	ID               string
	FamilyID         string
	TokenHash        []byte
	RefreshTokenHash []byte
	ClientID         string
	UserID           string
	Scope            string
	Resource         string
	AccessExpiresAt  time.Time
	RefreshExpiresAt *time.Time
	RotatedAt        *time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
}

type Artifact struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"owner_id"`
	Title       string    `json:"title"`
	ContentType string    `json:"content_type"`
	Visibility  string    `json:"visibility"`
	Version     int       `json:"version"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ArtifactPatch struct {
	Title       *string
	Visibility  *string
	ContentType *string
	SHA256      *string
}

type ListArtifactsFilter struct {
	Visibility  string
	ContentType string
	Query       string
	Limit       int
	Offset      int
}

type AdminArtifactSummary struct {
	Artifact
	OwnerUsername string `json:"owner_username"`
}

type AdminArtifactListFilter struct {
	Owner       string
	Visibility  string
	ContentType string
	Query       string
	Limit       int
	Offset      int
}

type AdminArtifactListResult struct {
	Items      []AdminArtifactSummary `json:"artifacts"`
	TotalCount int                    `json:"total_count"`
	TotalBytes int64                  `json:"total_bytes"`
}

type UploadToken struct {
	TokenHash           []byte
	ArtifactID          string
	OwnerID             string
	ExpectedContentType string
	PendingTitle        *string
	PendingVisibility   *string
	MaxBytes            int64
	ExpiresAt           time.Time
	UsedAt              *time.Time
}

type Store interface {
	Ping(ctx context.Context) error
	ReapExpired(ctx context.Context) error

	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserByID(ctx context.Context, id string) (User, error)
	CreateUser(ctx context.Context, username, passwordHash, role, status string) (User, error)
	ListUsersWithCounts(ctx context.Context, statusFilter string) ([]UserSummary, error)
	ApproveUser(ctx context.Context, id string) (User, error)
	DenyUser(ctx context.Context, id string) (User, error)

	GetSettings(ctx context.Context) (AppSettings, error)
	UpdateSettings(ctx context.Context, patch SettingsPatch) (AppSettings, error)

	CreateWebSession(ctx context.Context, sess WebSession) error
	GetWebSession(ctx context.Context, tokenHash []byte) (WebSession, User, error)
	DeleteWebSession(ctx context.Context, tokenHash []byte) error

	CreateOAuthClient(ctx context.Context, client OAuthClient) error
	GetOAuthClient(ctx context.Context, clientID string) (OAuthClient, error)
	TouchOAuthClient(ctx context.Context, clientID string) error
	CreateOAuthAuthCode(ctx context.Context, code OAuthAuthCode) error
	ConsumeOAuthAuthCode(ctx context.Context, codeHash []byte) (OAuthAuthCode, error)
	CreateOAuthToken(ctx context.Context, tok OAuthToken) error
	GetActiveAccessToken(ctx context.Context, tokenHash []byte) (OAuthToken, User, error)
	RotateRefreshToken(ctx context.Context, refreshHash []byte, clientID string, next OAuthToken) (OAuthToken, User, error)
	RevokeOAuthToken(ctx context.Context, tokenHash []byte, clientID string) error

	CreateArtifactWithBlob(ctx context.Context, art Artifact, data []byte, maxStorageBytes int64, maxCount int) (Artifact, error)
	UpdateArtifact(ctx context.Context, ownerID, id string, patch ArtifactPatch, newData []byte, maxStorageBytes int64) (Artifact, error)
	GetArtifact(ctx context.Context, id string) (Artifact, error)
	GetArtifactForOwner(ctx context.Context, id, ownerID string) (Artifact, error)
	GetArtifactBlob(ctx context.Context, id string) ([]byte, error)
	ListArtifactsForOwner(ctx context.Context, ownerID string, filter ListArtifactsFilter) ([]Artifact, error)
	DeleteArtifactForOwner(ctx context.Context, id, ownerID string) error
	ListAllArtifactsAdmin(ctx context.Context, filter AdminArtifactListFilter) (AdminArtifactListResult, error)
	DeleteArtifactByIDAdmin(ctx context.Context, id string) error

	CreateUploadTicket(ctx context.Context, ownerID, targetID, newID, title, contentType, visibility string, tokenHash []byte, maxBytes int64, expiresAt time.Time, maxCount int) (Artifact, error)
	PeekUploadToken(ctx context.Context, tokenHash []byte) (UploadToken, error)
	CompleteUpload(ctx context.Context, tokenHash []byte, data []byte, sha256Hex string, maxStorageBytes int64) (Artifact, error)
}

type PGStore struct {
	pool  *pgxpool.Pool
	blobs *PostgresBlobStore
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{
		pool:  pool,
		blobs: NewPostgresBlobStore(pool),
	}
}

func (s *PGStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *PGStore) ReapExpired(ctx context.Context) error {
	stmts := []string{
		`DELETE FROM web_sessions WHERE expires_at < now()`,
		`DELETE FROM oauth_authorization_codes WHERE expires_at < now() - INTERVAL '1 hour'`,
		`DELETE FROM upload_tokens WHERE expires_at < now() - INTERVAL '1 hour'`,
		`DELETE FROM artifacts WHERE status = 'pending_upload' AND created_at < now() - INTERVAL '15 minutes'`,
		`DELETE FROM oauth_tokens WHERE (refresh_expires_at IS NOT NULL AND refresh_expires_at < now()) OR (refresh_expires_at IS NULL AND access_expires_at < now())`,
		`DELETE FROM oauth_clients c
		 WHERE (c.last_used_at IS NULL AND c.created_at < now() - INTERVAL '24 hours' AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.client_id))
		    OR (c.last_used_at < now() - INTERVAL '90 days' AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.client_id AND t.revoked_at IS NULL))`,
	}
	for _, stmt := range stmts {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *PGStore) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, username, password_hash, role, status, created_at, updated_at
		FROM users WHERE username = $1
	`, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func parseCanonicalUUID(raw string) (string, bool) {
	u, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	return u.String(), true
}

func (s *PGStore) GetUserByID(ctx context.Context, id string) (User, error) {
	canonID, ok := parseCanonicalUUID(id)
	if !ok {
		return User{}, ErrNotFound
	}
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, username, password_hash, role, status, created_at, updated_at
		FROM users WHERE id = $1::uuid
	`, canonID).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *PGStore) CreateUser(ctx context.Context, username, passwordHash, role, status string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role, status)
		VALUES ($1, $2, $3, $4)
		RETURNING id::text, username, password_hash, role, status, created_at, updated_at
	`, username, passwordHash, role, status).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if isUniqueViolation(err) {
		return User{}, ErrConflict
	}
	return u, err
}

func (s *PGStore) ListUsersWithCounts(ctx context.Context, statusFilter string) ([]UserSummary, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if statusFilter != "" {
		rows, err = s.pool.Query(ctx, `
			SELECT u.id::text, u.username, u.role, u.status,
			       COUNT(a.id) FILTER (WHERE a.status = 'ready')::int,
			       COALESCE(SUM(a.size_bytes) FILTER (WHERE a.status = 'ready'), 0)::bigint,
			       u.created_at, u.updated_at
			FROM users u
			LEFT JOIN artifacts a ON a.owner_id = u.id
			WHERE u.status = $1
			GROUP BY u.id
			ORDER BY u.created_at ASC
		`, statusFilter)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT u.id::text, u.username, u.role, u.status,
			       COUNT(a.id) FILTER (WHERE a.status = 'ready')::int,
			       COALESCE(SUM(a.size_bytes) FILTER (WHERE a.status = 'ready'), 0)::bigint,
			       u.created_at, u.updated_at
			FROM users u
			LEFT JOIN artifacts a ON a.owner_id = u.id
			GROUP BY u.id
			ORDER BY u.created_at ASC
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UserSummary, 0)
	for rows.Next() {
		var item UserSummary
		if err := rows.Scan(&item.ID, &item.Username, &item.Role, &item.Status, &item.ArtifactCount, &item.StorageBytes, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PGStore) ApproveUser(ctx context.Context, id string) (User, error) {
	canonID, ok := parseCanonicalUUID(id)
	if !ok {
		return User{}, ErrNotFound
	}
	var u User
	err := s.pool.QueryRow(ctx, `
		UPDATE users SET status = 'active', updated_at = now()
		WHERE id = $1::uuid
		RETURNING id::text, username, password_hash, role, status, created_at, updated_at
	`, canonID).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *PGStore) DenyUser(ctx context.Context, id string) (User, error) {
	canonID, ok := parseCanonicalUUID(id)
	if !ok {
		return User{}, ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('artifact_admin_users', 0))`); err != nil {
		return User{}, err
	}

	var u User
	err = tx.QueryRow(ctx, `
		SELECT id::text, username, password_hash, role, status, created_at, updated_at
		FROM users WHERE id = $1::uuid FOR UPDATE
	`, canonID).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}

	if u.Role == RoleAdmin && u.Status == UserStatusActive {
		var activeAdmins int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&activeAdmins); err != nil {
			return User{}, err
		}
		if activeAdmins <= 1 {
			return User{}, ErrLastAdmin
		}
	}

	err = tx.QueryRow(ctx, `
		UPDATE users SET status = 'denied', updated_at = now()
		WHERE id = $1::uuid
		RETURNING id::text, username, password_hash, role, status, created_at, updated_at
	`, canonID).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM web_sessions WHERE user_id = $1::uuid`, canonID); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_tokens SET revoked_at = now() WHERE user_id = $1::uuid AND revoked_at IS NULL`, canonID); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_authorization_codes WHERE user_id = $1::uuid AND used_at IS NULL`, canonID); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM upload_tokens WHERE owner_id = $1::uuid AND used_at IS NULL`, canonID); err != nil {
		return User{}, err
	}

	return u, tx.Commit(ctx)
}

func (s *PGStore) GetSettings(ctx context.Context) (AppSettings, error) {
	settings := DefaultAppSettings()
	rows, err := s.pool.Query(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return settings, err
	}
	defer rows.Close()

	for rows.Next() {
		var k string
		var raw []byte
		if err := rows.Scan(&k, &raw); err != nil {
			return settings, err
		}
		switch k {
		case "allow_signup":
			_ = json.Unmarshal(raw, &settings.AllowSignup)
		case "max_upload_mb":
			_ = json.Unmarshal(raw, &settings.MaxUploadMB)
		case "max_storage_mb_per_user":
			_ = json.Unmarshal(raw, &settings.MaxStorageMBPerUser)
		case "allowed_cdn_origins":
			var origins []string
			if err := json.Unmarshal(raw, &origins); err == nil {
				settings.AllowedCDNOrigins = origins
			}
		}
	}
	return settings, rows.Err()
}

func (s *PGStore) UpdateSettings(ctx context.Context, patch SettingsPatch) (AppSettings, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AppSettings{}, err
	}
	defer tx.Rollback(ctx)

	upsert := func(key string, val any) error {
		encoded, err := json.Marshal(val)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO app_settings (key, value, updated_at)
			VALUES ($1, $2::jsonb, now())
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
		`, key, string(encoded))
		return err
	}

	if patch.AllowSignup != nil {
		if err := upsert("allow_signup", *patch.AllowSignup); err != nil {
			return AppSettings{}, err
		}
	}
	if patch.MaxUploadMB != nil {
		if err := upsert("max_upload_mb", *patch.MaxUploadMB); err != nil {
			return AppSettings{}, err
		}
	}
	if patch.MaxStorageMBPerUser != nil {
		if err := upsert("max_storage_mb_per_user", *patch.MaxStorageMBPerUser); err != nil {
			return AppSettings{}, err
		}
	}
	if patch.AllowedCDNOrigins != nil {
		if err := upsert("allowed_cdn_origins", *patch.AllowedCDNOrigins); err != nil {
			return AppSettings{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return AppSettings{}, err
	}
	return s.GetSettings(ctx)
}

func (s *PGStore) CreateWebSession(ctx context.Context, sess WebSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO web_sessions (token_hash, user_id, csrf_token, expires_at)
		VALUES ($1, $2::uuid, $3, $4)
	`, sess.TokenHash, sess.UserID, sess.CSRFToken, sess.ExpiresAt)
	return err
}

func (s *PGStore) GetWebSession(ctx context.Context, tokenHash []byte) (WebSession, User, error) {
	var sess WebSession
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT ws.token_hash, ws.user_id::text, ws.csrf_token, ws.expires_at, ws.created_at,
		       u.id::text, u.username, u.password_hash, u.role, u.status, u.created_at, u.updated_at
		FROM web_sessions ws
		JOIN users u ON u.id = ws.user_id
		WHERE ws.token_hash = $1 AND ws.expires_at > now()
	`, tokenHash).Scan(
		&sess.TokenHash, &sess.UserID, &sess.CSRFToken, &sess.ExpiresAt, &sess.CreatedAt,
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebSession{}, User{}, ErrNotFound
	}
	return sess, u, err
}

func (s *PGStore) DeleteWebSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM web_sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *PGStore) CreateOAuthClient(ctx context.Context, c OAuthClient) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, token_endpoint_auth_method)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, c.ClientID, c.ClientSecretHash, c.ClientName, c.RedirectURIs, c.GrantTypes, c.TokenEndpointAuthMethod)
	return err
}

func (s *PGStore) GetOAuthClient(ctx context.Context, clientID string) (OAuthClient, error) {
	var c OAuthClient
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret_hash, client_name, redirect_uris, grant_types, token_endpoint_auth_method, created_at, last_used_at
		FROM oauth_clients WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &c.RedirectURIs, &c.GrantTypes, &c.TokenEndpointAuthMethod, &c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthClient{}, ErrNotFound
	}
	return c, err
}

func (s *PGStore) TouchOAuthClient(ctx context.Context, clientID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE oauth_clients SET last_used_at = now() WHERE client_id = $1`, clientID)
	return err
}

func (s *PGStore) CreateOAuthAuthCode(ctx context.Context, code OAuthAuthCode) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_authorization_codes (code_hash, family_id, client_id, user_id, redirect_uri, scope, resource, code_challenge, expires_at)
		VALUES ($1, $2::uuid, $3, $4::uuid, $5, $6, $7, $8, $9)
	`, code.CodeHash, code.FamilyID, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.Resource, code.CodeChallenge, code.ExpiresAt)
	return err
}

func (s *PGStore) ConsumeOAuthAuthCode(ctx context.Context, codeHash []byte) (OAuthAuthCode, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OAuthAuthCode{}, err
	}
	defer tx.Rollback(ctx)

	var code OAuthAuthCode
	err = tx.QueryRow(ctx, `
		UPDATE oauth_authorization_codes
		SET used_at = now()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING code_hash, family_id::text, client_id, user_id::text, redirect_uri, scope, resource, code_challenge, expires_at, used_at
	`, codeHash).Scan(
		&code.CodeHash, &code.FamilyID, &code.ClientID, &code.UserID, &code.RedirectURI,
		&code.Scope, &code.Resource, &code.CodeChallenge, &code.ExpiresAt, &code.UsedAt,
	)
	if err == nil {
		return code, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return OAuthAuthCode{}, err
	}

	// Check if already used -> mark family compromised persistently and revoke tokens (RFC 6749 §4.1.2).
	var familyID string
	err2 := tx.QueryRow(ctx, `
		UPDATE oauth_authorization_codes
		SET replayed_at = COALESCE(replayed_at, now())
		WHERE code_hash = $1 AND used_at IS NOT NULL
		RETURNING family_id::text
	`, codeHash).Scan(&familyID)
	if err2 == nil {
		if _, rerr := tx.Exec(ctx, `UPDATE oauth_tokens SET revoked_at = now() WHERE family_id = $1::uuid AND revoked_at IS NULL`, familyID); rerr != nil {
			return OAuthAuthCode{}, rerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return OAuthAuthCode{}, cerr
		}
		return OAuthAuthCode{}, ErrCodeReplayed
	}
	return OAuthAuthCode{}, ErrNotFound
}

func (s *PGStore) CreateOAuthToken(ctx context.Context, tok OAuthToken) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Lock any matching auth code row in the same order as replay detection (oauth_authorization_codes -> oauth_tokens)
	// so a concurrent code replay cannot miss revoking this newly minted token.
	var replayedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT replayed_at
		FROM oauth_authorization_codes
		WHERE family_id = $1::uuid
		FOR UPDATE
	`, tok.FamilyID).Scan(&replayedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if replayedAt != nil {
		return ErrCodeReplayed
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO oauth_tokens (family_id, token_hash, refresh_token_hash, client_id, user_id, scope, resource, access_expires_at, refresh_expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9)
	`, tok.FamilyID, tok.TokenHash, tok.RefreshTokenHash, tok.ClientID, tok.UserID, tok.Scope, tok.Resource, tok.AccessExpiresAt, tok.RefreshExpiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PGStore) GetActiveAccessToken(ctx context.Context, tokenHash []byte) (OAuthToken, User, error) {
	var tok OAuthToken
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT t.id::text, t.family_id::text, t.token_hash, t.refresh_token_hash, t.client_id, t.user_id::text,
		       t.scope, t.resource, t.access_expires_at, t.refresh_expires_at, t.rotated_at, t.revoked_at, t.created_at,
		       u.id::text, u.username, u.password_hash, u.role, u.status, u.created_at, u.updated_at
		FROM oauth_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.access_expires_at > now()
	`, tokenHash).Scan(
		&tok.ID, &tok.FamilyID, &tok.TokenHash, &tok.RefreshTokenHash, &tok.ClientID, &tok.UserID,
		&tok.Scope, &tok.Resource, &tok.AccessExpiresAt, &tok.RefreshExpiresAt, &tok.RotatedAt, &tok.RevokedAt, &tok.CreatedAt,
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthToken{}, User{}, ErrNotFound
	}
	return tok, u, err
}

func (s *PGStore) RotateRefreshToken(ctx context.Context, refreshHash []byte, clientID string, next OAuthToken) (OAuthToken, User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OAuthToken{}, User{}, err
	}
	defer tx.Rollback(ctx)

	var old OAuthToken
	err = tx.QueryRow(ctx, `
		UPDATE oauth_tokens
		SET rotated_at = now(), revoked_at = now()
		WHERE refresh_token_hash = $1 AND client_id = $2 AND revoked_at IS NULL AND refresh_expires_at IS NOT NULL AND refresh_expires_at > now()
		RETURNING id::text, family_id::text, client_id, user_id::text, scope, resource
	`, refreshHash, clientID).Scan(&old.ID, &old.FamilyID, &old.ClientID, &old.UserID, &old.Scope, &old.Resource)
	if errors.Is(err, pgx.ErrNoRows) {
		// Detect reuse of an already-rotated refresh token -> revoke entire token family (OAuth 2.1).
		var familyID string
		var rotatedAt *time.Time
		if qerr := tx.QueryRow(ctx, `SELECT family_id::text, rotated_at FROM oauth_tokens WHERE refresh_token_hash = $1`, refreshHash).Scan(&familyID, &rotatedAt); qerr == nil && rotatedAt != nil {
			if _, rerr := tx.Exec(ctx, `UPDATE oauth_tokens SET revoked_at = now() WHERE family_id = $1::uuid AND revoked_at IS NULL`, familyID); rerr != nil {
				return OAuthToken{}, User{}, rerr
			}
			if cerr := tx.Commit(ctx); cerr != nil {
				return OAuthToken{}, User{}, cerr
			}
			return OAuthToken{}, User{}, ErrTokenReused
		}
		return OAuthToken{}, User{}, ErrNotFound
	}
	if err != nil {
		return OAuthToken{}, User{}, err
	}

	var u User
	err = tx.QueryRow(ctx, `
		SELECT id::text, username, password_hash, role, status, created_at, updated_at
		FROM users WHERE id = $1::uuid
	`, old.UserID).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return OAuthToken{}, User{}, err
	}
	if u.Status != UserStatusActive {
		return OAuthToken{}, User{}, ErrUserInactive
	}

	next.FamilyID = old.FamilyID
	next.ClientID = old.ClientID
	next.UserID = old.UserID
	if next.Scope == "" {
		next.Scope = old.Scope
	} else if !isScopeSubset(next.Scope, old.Scope) {
		return OAuthToken{}, User{}, ErrScopeEscalation
	}
	if next.Resource == "" {
		next.Resource = old.Resource
	} else if next.Resource != old.Resource {
		return OAuthToken{}, User{}, ErrConflict
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO oauth_tokens (family_id, token_hash, refresh_token_hash, client_id, user_id, scope, resource, access_expires_at, refresh_expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9)
		RETURNING id::text, created_at
	`, next.FamilyID, next.TokenHash, next.RefreshTokenHash, next.ClientID, next.UserID, next.Scope, next.Resource, next.AccessExpiresAt, next.RefreshExpiresAt).Scan(&next.ID, &next.CreatedAt)
	if err != nil {
		return OAuthToken{}, User{}, err
	}

	return next, u, tx.Commit(ctx)
}

func (s *PGStore) RevokeOAuthToken(ctx context.Context, tokenHash []byte, clientID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE oauth_tokens
		SET revoked_at = now()
		WHERE client_id = $1 AND revoked_at IS NULL AND (token_hash = $2 OR refresh_token_hash = $2)
	`, clientID, tokenHash)
	return err
}

func (s *PGStore) CreateArtifactWithBlob(ctx context.Context, art Artifact, data []byte, maxStorageBytes int64, maxCount int) (Artifact, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Artifact{}, err
	}
	defer tx.Rollback(ctx)

	if err := checkOwnerQuotaPG(ctx, tx, art.OwnerID, int64(len(data)), 1, maxStorageBytes, maxCount); err != nil {
		return Artifact{}, err
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO artifacts (id, owner_id, title, content_type, visibility, version, size_bytes, sha256, status)
		VALUES ($1, $2::uuid, $3, $4, $5, 1, $6, $7, 'ready')
		RETURNING id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
	`, art.ID, art.OwnerID, art.Title, art.ContentType, art.Visibility, int64(len(data)), art.SHA256).Scan(
		&art.ID, &art.OwnerID, &art.Title, &art.ContentType, &art.Visibility,
		&art.Version, &art.SizeBytes, &art.SHA256, &art.Status, &art.CreatedAt, &art.UpdatedAt,
	)
	if err != nil {
		return Artifact{}, err
	}
	if err := putBlobPG(ctx, tx, art.ID, data); err != nil {
		return Artifact{}, err
	}
	return art, tx.Commit(ctx)
}

func (s *PGStore) UpdateArtifact(ctx context.Context, ownerID, id string, patch ArtifactPatch, newData []byte, maxStorageBytes int64) (Artifact, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Artifact{}, err
	}
	defer tx.Rollback(ctx)

	var cur Artifact
	err = tx.QueryRow(ctx, `
		SELECT id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
		FROM artifacts WHERE id = $1 AND owner_id = $2::uuid FOR UPDATE
	`, id, ownerID).Scan(
		&cur.ID, &cur.OwnerID, &cur.Title, &cur.ContentType, &cur.Visibility,
		&cur.Version, &cur.SizeBytes, &cur.SHA256, &cur.Status, &cur.CreatedAt, &cur.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, err
	}

	if patch.Title != nil {
		cur.Title = *patch.Title
	}
	if patch.Visibility != nil {
		cur.Visibility = *patch.Visibility
	}
	if patch.ContentType != nil {
		cur.ContentType = *patch.ContentType
	}
	if newData != nil {
		delta := int64(len(newData)) - cur.SizeBytes
		if err := checkOwnerQuotaPG(ctx, tx, ownerID, delta, 0, maxStorageBytes, artifact.MaxArtifactsPerUser+1); err != nil {
			return Artifact{}, err
		}
		cur.SizeBytes = int64(len(newData))
		if patch.SHA256 != nil {
			cur.SHA256 = *patch.SHA256
		}
		cur.Status = artifact.StatusReady
		if err := putBlobPG(ctx, tx, cur.ID, newData); err != nil {
			return Artifact{}, err
		}
	}

	err = tx.QueryRow(ctx, `
		UPDATE artifacts
		SET title = $1, content_type = $2, visibility = $3, version = version + 1,
		    size_bytes = $4, sha256 = $5, status = $6, updated_at = now()
		WHERE id = $7 AND owner_id = $8::uuid
		RETURNING id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
	`, cur.Title, cur.ContentType, cur.Visibility, cur.SizeBytes, cur.SHA256, cur.Status, cur.ID, ownerID).Scan(
		&cur.ID, &cur.OwnerID, &cur.Title, &cur.ContentType, &cur.Visibility,
		&cur.Version, &cur.SizeBytes, &cur.SHA256, &cur.Status, &cur.CreatedAt, &cur.UpdatedAt,
	)
	if err != nil {
		return Artifact{}, err
	}
	return cur, tx.Commit(ctx)
}

func (s *PGStore) GetArtifact(ctx context.Context, id string) (Artifact, error) {
	var a Artifact
	err := s.pool.QueryRow(ctx, `
		SELECT id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
		FROM artifacts WHERE id = $1
	`, id).Scan(
		&a.ID, &a.OwnerID, &a.Title, &a.ContentType, &a.Visibility,
		&a.Version, &a.SizeBytes, &a.SHA256, &a.Status, &a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return a, err
}

func (s *PGStore) GetArtifactForOwner(ctx context.Context, id, ownerID string) (Artifact, error) {
	var a Artifact
	err := s.pool.QueryRow(ctx, `
		SELECT id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
		FROM artifacts WHERE id = $1 AND owner_id = $2::uuid
	`, id, ownerID).Scan(
		&a.ID, &a.OwnerID, &a.Title, &a.ContentType, &a.Visibility,
		&a.Version, &a.SizeBytes, &a.SHA256, &a.Status, &a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return a, err
}

func (s *PGStore) GetArtifactBlob(ctx context.Context, id string) ([]byte, error) {
	return s.blobs.Get(ctx, id)
}

func (s *PGStore) ListArtifactsForOwner(ctx context.Context, ownerID string, f ListArtifactsFilter) ([]Artifact, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := max(f.Offset, 0)

	args := []any{ownerID}
	conds := []string{"owner_id = $1::uuid", "status = 'ready'"}
	if f.Visibility != "" {
		args = append(args, f.Visibility)
		conds = append(conds, fmt.Sprintf("visibility = $%d", len(args)))
	}
	if f.ContentType != "" {
		args = append(args, f.ContentType)
		conds = append(conds, fmt.Sprintf("content_type = $%d", len(args)))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+escapeILIKE(q)+"%")
		conds = append(conds, fmt.Sprintf("title ILIKE $%d ESCAPE '\\'", len(args)))
	}
	args = append(args, limit, offset)

	query := fmt.Sprintf(`
		SELECT id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
		FROM artifacts
		WHERE %s
		ORDER BY updated_at DESC
		LIMIT $%d OFFSET $%d
	`, strings.Join(conds, " AND "), len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Artifact, 0)
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(
			&a.ID, &a.OwnerID, &a.Title, &a.ContentType, &a.Visibility,
			&a.Version, &a.SizeBytes, &a.SHA256, &a.Status, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PGStore) DeleteArtifactForOwner(ctx context.Context, id, ownerID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM artifacts WHERE id = $1 AND owner_id = $2::uuid`, id, ownerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) ListAllArtifactsAdmin(ctx context.Context, f AdminArtifactListFilter) (AdminArtifactListResult, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	offset := max(f.Offset, 0)

	args := make([]any, 0, 6)
	conds := []string{"a.status = 'ready'"}
	if owner := strings.TrimSpace(f.Owner); owner != "" {
		if canonID, ok := parseCanonicalUUID(owner); ok {
			args = append(args, canonID)
			conds = append(conds, fmt.Sprintf("a.owner_id = $%d::uuid", len(args)))
		} else {
			args = append(args, strings.ToLower(owner))
			conds = append(conds, fmt.Sprintf("u.username = $%d", len(args)))
		}
	}
	if f.Visibility != "" {
		args = append(args, f.Visibility)
		conds = append(conds, fmt.Sprintf("a.visibility = $%d", len(args)))
	}
	if f.ContentType != "" {
		args = append(args, f.ContentType)
		conds = append(conds, fmt.Sprintf("a.content_type = $%d", len(args)))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+escapeILIKE(q)+"%")
		conds = append(conds, fmt.Sprintf("a.title ILIKE $%d ESCAPE '\\'", len(args)))
	}

	whereClause := strings.Join(conds, " AND ")
	var res AdminArtifactListResult
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)::int, COALESCE(SUM(a.size_bytes), 0)::bigint
		FROM artifacts a
		JOIN users u ON u.id = a.owner_id
		WHERE %s
	`, whereClause)
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&res.TotalCount, &res.TotalBytes); err != nil {
		return AdminArtifactListResult{}, err
	}

	argsWithPage := append(append([]any(nil), args...), limit, offset)
	listQuery := fmt.Sprintf(`
		SELECT a.id, a.owner_id::text, u.username, a.title, a.content_type, a.visibility,
		       a.version, a.size_bytes, a.sha256, a.status, a.created_at, a.updated_at
		FROM artifacts a
		JOIN users u ON u.id = a.owner_id
		WHERE %s
		ORDER BY a.updated_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, len(argsWithPage)-1, len(argsWithPage))

	rows, err := s.pool.Query(ctx, listQuery, argsWithPage...)
	if err != nil {
		return AdminArtifactListResult{}, err
	}
	defer rows.Close()

	items := make([]AdminArtifactSummary, 0)
	for rows.Next() {
		var item AdminArtifactSummary
		if err := rows.Scan(
			&item.ID, &item.OwnerID, &item.OwnerUsername, &item.Title, &item.ContentType, &item.Visibility,
			&item.Version, &item.SizeBytes, &item.SHA256, &item.Status, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return AdminArtifactListResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return AdminArtifactListResult{}, err
	}
	res.Items = items
	return res, nil
}

func (s *PGStore) DeleteArtifactByIDAdmin(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM artifacts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func escapeILIKE(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func (s *PGStore) CreateUploadTicket(ctx context.Context, ownerID, targetID, newID, title, contentType, visibility string, tokenHash []byte, maxBytes int64, expiresAt time.Time, maxCount int) (Artifact, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Artifact{}, err
	}
	defer tx.Rollback(ctx)

	var art Artifact
	var pendingTitle *string
	var pendingVisibility *string
	if targetID == "" {
		if err := checkOwnerQuotaPG(ctx, tx, ownerID, 0, 1, 1<<62, maxCount); err != nil {
			return Artifact{}, err
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO artifacts (id, owner_id, title, content_type, visibility, version, size_bytes, sha256, status)
			VALUES ($1, $2::uuid, $3, $4, $5, 1, 0, '', 'pending_upload')
			RETURNING id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
		`, newID, ownerID, title, contentType, visibility).Scan(
			&art.ID, &art.OwnerID, &art.Title, &art.ContentType, &art.Visibility,
			&art.Version, &art.SizeBytes, &art.SHA256, &art.Status, &art.CreatedAt, &art.UpdatedAt,
		)
		if err != nil {
			return Artifact{}, err
		}
	} else {
		// Updating an existing owned artifact keeps BOTH its live payload AND live title/visibility
		// completely untouched until PUT /upload/{token} succeeds atomically in CompleteUpload.
		err = tx.QueryRow(ctx, `
			SELECT id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
			FROM artifacts WHERE id = $1 AND owner_id = $2::uuid FOR UPDATE
		`, targetID, ownerID).Scan(
			&art.ID, &art.OwnerID, &art.Title, &art.ContentType, &art.Visibility,
			&art.Version, &art.SizeBytes, &art.SHA256, &art.Status, &art.CreatedAt, &art.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return Artifact{}, ErrNotFound
		}
		if err != nil {
			return Artifact{}, err
		}
		if title != "" {
			t := title
			pendingTitle = &t
		}
		if visibility != "" {
			v := visibility
			pendingVisibility = &v
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO upload_tokens (token_hash, artifact_id, owner_id, expected_content_type, pending_title, pending_visibility, max_bytes, expires_at)
		VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8)
	`, tokenHash, art.ID, ownerID, contentType, pendingTitle, pendingVisibility, maxBytes, expiresAt); err != nil {
		return Artifact{}, err
	}

	return art, tx.Commit(ctx)
}

func (s *PGStore) PeekUploadToken(ctx context.Context, tokenHash []byte) (UploadToken, error) {
	var tok UploadToken
	err := s.pool.QueryRow(ctx, `
		SELECT ut.token_hash, ut.artifact_id, ut.owner_id::text, ut.expected_content_type, ut.pending_title, ut.pending_visibility, ut.max_bytes, ut.expires_at, ut.used_at
		FROM upload_tokens ut
		JOIN users u ON u.id = ut.owner_id
		WHERE ut.token_hash = $1 AND ut.used_at IS NULL AND ut.expires_at > now() AND u.status = 'active'
	`, tokenHash).Scan(&tok.TokenHash, &tok.ArtifactID, &tok.OwnerID, &tok.ExpectedContentType, &tok.PendingTitle, &tok.PendingVisibility, &tok.MaxBytes, &tok.ExpiresAt, &tok.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UploadToken{}, ErrUploadTokenInvalid
	}
	return tok, err
}

func (s *PGStore) CompleteUpload(ctx context.Context, tokenHash []byte, data []byte, sha256Hex string, maxStorageBytes int64) (Artifact, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Artifact{}, err
	}
	defer tx.Rollback(ctx)

	// 1. Plain SELECT (no row lock) to discover artifact_id + owner_id.
	//    Locking artifacts BEFORE upload_tokens matches DELETE FROM artifacts (ON DELETE CASCADE)
	//    and prevents PostgreSQL 40P01 deadlocks.
	var artifactID, ownerID string
	err = tx.QueryRow(ctx, `
		SELECT artifact_id, owner_id::text
		FROM upload_tokens
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
	`, tokenHash).Scan(&artifactID, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrUploadTokenInvalid
	}
	if err != nil {
		return Artifact{}, err
	}

	// 2. Lock parent artifact row first.
	var cur Artifact
	err = tx.QueryRow(ctx, `
		SELECT id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
		FROM artifacts WHERE id = $1 AND owner_id = $2::uuid FOR UPDATE
	`, artifactID, ownerID).Scan(
		&cur.ID, &cur.OwnerID, &cur.Title, &cur.ContentType, &cur.Visibility,
		&cur.Version, &cur.SizeBytes, &cur.SHA256, &cur.Status, &cur.CreatedAt, &cur.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, err
	}

	// 3. Atomically claim the single-use upload token second.
	var tok UploadToken
	err = tx.QueryRow(ctx, `
		UPDATE upload_tokens
		SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING token_hash, artifact_id, owner_id::text, expected_content_type, pending_title, pending_visibility, max_bytes, expires_at, used_at
	`, tokenHash).Scan(&tok.TokenHash, &tok.ArtifactID, &tok.OwnerID, &tok.ExpectedContentType, &tok.PendingTitle, &tok.PendingVisibility, &tok.MaxBytes, &tok.ExpiresAt, &tok.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrUploadTokenInvalid
	}
	if err != nil {
		return Artifact{}, err
	}

	var userStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1::uuid`, tok.OwnerID).Scan(&userStatus); err != nil {
		return Artifact{}, err
	}
	if userStatus != UserStatusActive {
		return Artifact{}, ErrUserInactive
	}

	delta := int64(len(data)) - cur.SizeBytes
	if err := checkOwnerQuotaPG(ctx, tx, tok.OwnerID, delta, 0, maxStorageBytes, artifact.MaxArtifactsPerUser+1); err != nil {
		return Artifact{}, err
	}

	if err := putBlobPG(ctx, tx, cur.ID, data); err != nil {
		return Artifact{}, err
	}

	err = tx.QueryRow(ctx, `
		UPDATE artifacts
		SET title = COALESCE($1, title),
		    visibility = COALESCE($2, visibility),
		    content_type = $3,
		    size_bytes = $4,
		    sha256 = $5,
		    version = CASE WHEN status = 'ready' THEN version + 1 ELSE version END,
		    status = 'ready',
		    updated_at = now()
		WHERE id = $6
		RETURNING id, owner_id::text, title, content_type, visibility, version, size_bytes, sha256, status, created_at, updated_at
	`, tok.PendingTitle, tok.PendingVisibility, tok.ExpectedContentType, int64(len(data)), sha256Hex, cur.ID).Scan(
		&cur.ID, &cur.OwnerID, &cur.Title, &cur.ContentType, &cur.Visibility,
		&cur.Version, &cur.SizeBytes, &cur.SHA256, &cur.Status, &cur.CreatedAt, &cur.UpdatedAt,
	)
	if err != nil {
		return Artifact{}, err
	}
	return cur, tx.Commit(ctx)
}

func checkOwnerQuotaPG(ctx context.Context, tx pgx.Tx, ownerID string, deltaBytes int64, deltaCount int, maxStorageBytes int64, maxCount int) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "quota:"+ownerID); err != nil {
		return err
	}
	var count int
	var totalBytes int64
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*)::int, COALESCE(SUM(size_bytes), 0)::bigint
		FROM artifacts WHERE owner_id = $1::uuid
	`, ownerID).Scan(&count, &totalBytes); err != nil {
		return err
	}
	if deltaCount > 0 && count+deltaCount > maxCount {
		return ErrQuotaExceeded
	}
	if deltaBytes > 0 && totalBytes+deltaBytes > maxStorageBytes {
		return ErrQuotaExceeded
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isScopeSubset(requested, granted string) bool {
	grantedSet := make(map[string]struct{})
	for _, s := range strings.Fields(granted) {
		grantedSet[s] = struct{}{}
	}
	for _, s := range strings.Fields(requested) {
		if _, ok := grantedSet[s]; !ok {
			return false
		}
	}
	return true
}
