package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"cubus.sh/artifact/internal/artifact"
)

// MemoryStore is a concurrency-safe in-memory Store implementation mirroring
// PGStore's atomic transaction semantics for comprehensive -race unit tests.
type MemoryStore struct {
	mu           sync.Mutex
	users        map[string]User
	settings     AppSettings
	sessions     map[string]WebSession
	clients      map[string]OAuthClient
	authCodes    map[string]OAuthAuthCode
	tokens       map[string]OAuthToken
	artifacts    map[string]Artifact
	blobs        map[string][]byte
	uploadTokens map[string]UploadToken
	pingErr      error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:        make(map[string]User),
		settings:     DefaultAppSettings(),
		sessions:     make(map[string]WebSession),
		clients:      make(map[string]OAuthClient),
		authCodes:    make(map[string]OAuthAuthCode),
		tokens:       make(map[string]OAuthToken),
		artifacts:    make(map[string]Artifact),
		blobs:        make(map[string][]byte),
		uploadTokens: make(map[string]UploadToken),
	}
}

func (m *MemoryStore) SetPingError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingErr = err
}

func (m *MemoryStore) Ping(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pingErr
}

func (m *MemoryStore) ReapExpired(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, s := range m.sessions {
		if s.ExpiresAt.Before(now) {
			delete(m.sessions, k)
		}
	}
	for k, c := range m.authCodes {
		if c.ExpiresAt.Before(now.Add(-time.Hour)) {
			delete(m.authCodes, k)
		}
	}
	for k, u := range m.uploadTokens {
		if u.ExpiresAt.Before(now.Add(-time.Hour)) {
			delete(m.uploadTokens, k)
		}
	}
	for k, a := range m.artifacts {
		if a.Status == artifact.StatusPendingUpload && a.CreatedAt.Before(now.Add(-15*time.Minute)) {
			delete(m.artifacts, k)
			delete(m.blobs, k)
		}
	}
	for k, t := range m.tokens {
		if (t.RefreshExpiresAt != nil && t.RefreshExpiresAt.Before(now)) || (t.RefreshExpiresAt == nil && t.AccessExpiresAt.Before(now)) {
			delete(m.tokens, k)
		}
	}
	return nil
}

func (m *MemoryStore) GetUserByUsername(_ context.Context, username string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (m *MemoryStore) GetUserByID(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *MemoryStore) CreateUser(_ context.Context, username, passwordHash, role, status string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Username == username {
			return User{}, ErrConflict
		}
	}
	now := time.Now().UTC()
	u := User{
		ID:           uuid.NewString(),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		Status:       status,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	m.users[u.ID] = u
	return u, nil
}

func (m *MemoryStore) ListUsersWithCounts(_ context.Context, statusFilter string) ([]UserSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]UserSummary, 0, len(m.users))
	for _, u := range m.users {
		if statusFilter != "" && u.Status != statusFilter {
			continue
		}
		var cnt int
		var bytesTotal int64
		for _, a := range m.artifacts {
			if a.OwnerID == u.ID && a.Status == artifact.StatusReady {
				cnt++
				bytesTotal += a.SizeBytes
			}
		}
		out = append(out, UserSummary{
			ID:            u.ID,
			Username:      u.Username,
			Role:          u.Role,
			Status:        u.Status,
			ArtifactCount: cnt,
			StorageBytes:  bytesTotal,
			CreatedAt:     u.CreatedAt,
			UpdatedAt:     u.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) ApproveUser(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Status = UserStatusActive
	u.UpdatedAt = time.Now().UTC()
	m.users[id] = u
	return u, nil
}

func (m *MemoryStore) DenyUser(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	if u.Role == RoleAdmin && u.Status == UserStatusActive {
		activeAdmins := 0
		for _, other := range m.users {
			if other.Role == RoleAdmin && other.Status == UserStatusActive {
				activeAdmins++
			}
		}
		if activeAdmins <= 1 {
			return User{}, ErrLastAdmin
		}
	}
	now := time.Now().UTC()
	u.Status = UserStatusDenied
	u.UpdatedAt = now
	m.users[id] = u
	for k, s := range m.sessions {
		if s.UserID == id {
			delete(m.sessions, k)
		}
	}
	for k, t := range m.tokens {
		if t.UserID == id && t.RevokedAt == nil {
			t.RevokedAt = &now
			m.tokens[k] = t
		}
	}
	for k, ut := range m.uploadTokens {
		if ut.OwnerID == id && ut.UsedAt == nil {
			delete(m.uploadTokens, k)
		}
	}
	return u, nil
}

func (m *MemoryStore) GetSettings(context.Context) (AppSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := m.settings
	cp.AllowedCDNOrigins = slices.Clone(m.settings.AllowedCDNOrigins)
	return cp, nil
}

func (m *MemoryStore) UpdateSettings(_ context.Context, patch SettingsPatch) (AppSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if patch.AllowSignup != nil {
		m.settings.AllowSignup = *patch.AllowSignup
	}
	if patch.MaxUploadMB != nil {
		m.settings.MaxUploadMB = *patch.MaxUploadMB
	}
	if patch.MaxStorageMBPerUser != nil {
		m.settings.MaxStorageMBPerUser = *patch.MaxStorageMBPerUser
	}
	if patch.AllowedCDNOrigins != nil {
		m.settings.AllowedCDNOrigins = slices.Clone(*patch.AllowedCDNOrigins)
	}
	cp := m.settings
	cp.AllowedCDNOrigins = slices.Clone(m.settings.AllowedCDNOrigins)
	return cp, nil
}

func (m *MemoryStore) CreateWebSession(_ context.Context, sess WebSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess.CreatedAt = time.Now().UTC()
	m.sessions[hex.EncodeToString(sess.TokenHash)] = sess
	return nil
}

func (m *MemoryStore) GetWebSession(_ context.Context, tokenHash []byte) (WebSession, User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[hex.EncodeToString(tokenHash)]
	if !ok || !sess.ExpiresAt.After(time.Now()) {
		return WebSession{}, User{}, ErrNotFound
	}
	u, ok := m.users[sess.UserID]
	if !ok {
		return WebSession{}, User{}, ErrNotFound
	}
	return sess, u, nil
}

func (m *MemoryStore) DeleteWebSession(_ context.Context, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hex.EncodeToString(tokenHash))
	return nil
}

func (m *MemoryStore) CreateOAuthClient(_ context.Context, c OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.CreatedAt = time.Now().UTC()
	m.clients[c.ClientID] = c
	return nil
}

func (m *MemoryStore) GetOAuthClient(_ context.Context, clientID string) (OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[clientID]
	if !ok {
		return OAuthClient{}, ErrNotFound
	}
	return c, nil
}

func (m *MemoryStore) TouchOAuthClient(_ context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[clientID]; ok {
		now := time.Now().UTC()
		c.LastUsedAt = &now
		m.clients[clientID] = c
	}
	return nil
}

func (m *MemoryStore) CreateOAuthAuthCode(_ context.Context, code OAuthAuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCodes[hex.EncodeToString(code.CodeHash)] = code
	return nil
}

func (m *MemoryStore) ConsumeOAuthAuthCode(_ context.Context, codeHash []byte) (OAuthAuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hex.EncodeToString(codeHash)
	code, ok := m.authCodes[key]
	if !ok {
		return OAuthAuthCode{}, ErrNotFound
	}
	now := time.Now().UTC()
	if code.UsedAt != nil {
		for tk, t := range m.tokens {
			if t.FamilyID == code.FamilyID && t.RevokedAt == nil {
				t.RevokedAt = &now
				m.tokens[tk] = t
			}
		}
		return OAuthAuthCode{}, ErrCodeReplayed
	}
	if !code.ExpiresAt.After(now) {
		return OAuthAuthCode{}, ErrNotFound
	}
	code.UsedAt = &now
	m.authCodes[key] = code
	return code, nil
}

func (m *MemoryStore) CreateOAuthToken(_ context.Context, tok OAuthToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok.ID = uuid.NewString()
	tok.CreatedAt = time.Now().UTC()
	m.tokens[tok.ID] = tok
	return nil
}

func (m *MemoryStore) GetActiveAccessToken(_ context.Context, tokenHash []byte) (OAuthToken, User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, t := range m.tokens {
		if bytes.Equal(t.TokenHash, tokenHash) && t.RevokedAt == nil && t.AccessExpiresAt.After(now) {
			u, ok := m.users[t.UserID]
			if !ok {
				return OAuthToken{}, User{}, ErrNotFound
			}
			return t, u, nil
		}
	}
	return OAuthToken{}, User{}, ErrNotFound
}

func (m *MemoryStore) RotateRefreshToken(_ context.Context, refreshHash []byte, clientID string, next OAuthToken) (OAuthToken, User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var found *OAuthToken
	var foundKey string
	for k, t := range m.tokens {
		if bytes.Equal(t.RefreshTokenHash, refreshHash) {
			cp := t
			found = &cp
			foundKey = k
			break
		}
	}
	if found == nil {
		return OAuthToken{}, User{}, ErrNotFound
	}
	if found.RotatedAt != nil {
		for k, t := range m.tokens {
			if t.FamilyID == found.FamilyID && t.RevokedAt == nil {
				t.RevokedAt = &now
				m.tokens[k] = t
			}
		}
		return OAuthToken{}, User{}, ErrTokenReused
	}
	if found.ClientID != clientID || found.RevokedAt != nil || found.RefreshExpiresAt == nil || !found.RefreshExpiresAt.After(now) {
		return OAuthToken{}, User{}, ErrNotFound
	}
	u, ok := m.users[found.UserID]
	if !ok {
		return OAuthToken{}, User{}, ErrNotFound
	}
	if u.Status != UserStatusActive {
		return OAuthToken{}, User{}, ErrUserInactive
	}
	if next.Scope != "" && !isScopeSubset(next.Scope, found.Scope) {
		return OAuthToken{}, User{}, ErrScopeEscalation
	}
	if next.Resource != "" && next.Resource != found.Resource {
		return OAuthToken{}, User{}, ErrConflict
	}
	found.RotatedAt = &now
	found.RevokedAt = &now
	m.tokens[foundKey] = *found

	next.ID = uuid.NewString()
	next.FamilyID = found.FamilyID
	next.ClientID = found.ClientID
	next.UserID = found.UserID
	if next.Scope == "" {
		next.Scope = found.Scope
	}
	if next.Resource == "" {
		next.Resource = found.Resource
	}
	next.CreatedAt = now
	m.tokens[next.ID] = next
	return next, u, nil
}

func (m *MemoryStore) RevokeOAuthToken(_ context.Context, tokenHash []byte, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for k, t := range m.tokens {
		if t.ClientID == clientID && t.RevokedAt == nil && (bytes.Equal(t.TokenHash, tokenHash) || bytes.Equal(t.RefreshTokenHash, tokenHash)) {
			t.RevokedAt = &now
			m.tokens[k] = t
		}
	}
	return nil
}

func (m *MemoryStore) ownerQuotaLocked(ownerID string, deltaBytes int64, deltaCount int, maxStorageBytes int64, maxCount int) error {
	var cnt int
	var total int64
	for _, a := range m.artifacts {
		if a.OwnerID == ownerID {
			cnt++
			total += a.SizeBytes
		}
	}
	if deltaCount > 0 && cnt+deltaCount > maxCount {
		return ErrQuotaExceeded
	}
	if deltaBytes > 0 && total+deltaBytes > maxStorageBytes {
		return ErrQuotaExceeded
	}
	return nil
}

func (m *MemoryStore) CreateArtifactWithBlob(_ context.Context, art Artifact, data []byte, maxStorageBytes int64, maxCount int) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ownerQuotaLocked(art.OwnerID, int64(len(data)), 1, maxStorageBytes, maxCount); err != nil {
		return Artifact{}, err
	}
	now := time.Now().UTC()
	art.Version = 1
	art.SizeBytes = int64(len(data))
	art.Status = artifact.StatusReady
	art.CreatedAt = now
	art.UpdatedAt = now
	m.artifacts[art.ID] = art
	m.blobs[art.ID] = slices.Clone(data)
	return art, nil
}

func (m *MemoryStore) UpdateArtifact(_ context.Context, ownerID, id string, patch ArtifactPatch, newData []byte, maxStorageBytes int64) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.artifacts[id]
	if !ok || cur.OwnerID != ownerID {
		return Artifact{}, ErrNotFound
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
		if err := m.ownerQuotaLocked(ownerID, delta, 0, maxStorageBytes, artifact.MaxArtifactsPerUser+1); err != nil {
			return Artifact{}, err
		}
		cur.SizeBytes = int64(len(newData))
		if patch.SHA256 != nil {
			cur.SHA256 = *patch.SHA256
		}
		cur.Status = artifact.StatusReady
		m.blobs[cur.ID] = slices.Clone(newData)
	}
	cur.Version++
	cur.UpdatedAt = time.Now().UTC()
	m.artifacts[cur.ID] = cur
	return cur, nil
}

func (m *MemoryStore) GetArtifact(_ context.Context, id string) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.artifacts[id]
	if !ok {
		return Artifact{}, ErrNotFound
	}
	return a, nil
}

func (m *MemoryStore) GetArtifactForOwner(_ context.Context, id, ownerID string) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.artifacts[id]
	if !ok || a.OwnerID != ownerID {
		return Artifact{}, ErrNotFound
	}
	return a, nil
}

func (m *MemoryStore) GetArtifactBlob(_ context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return slices.Clone(b), nil
}

func (m *MemoryStore) ListArtifactsForOwner(_ context.Context, ownerID string, f ListArtifactsFilter) ([]Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Artifact, 0)
	q := strings.ToLower(strings.TrimSpace(f.Query))
	for _, a := range m.artifacts {
		if a.OwnerID != ownerID || a.Status != artifact.StatusReady {
			continue
		}
		if f.Visibility != "" && a.Visibility != f.Visibility {
			continue
		}
		if f.ContentType != "" && a.ContentType != f.ContentType {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(a.Title), q) {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	offset := max(f.Offset, 0)
	if offset >= len(out) {
		return []Artifact{}, nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	end := min(offset+limit, len(out))
	return out[offset:end], nil
}

func (m *MemoryStore) DeleteArtifactForOwner(_ context.Context, id, ownerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.artifacts[id]
	if !ok || a.OwnerID != ownerID {
		return ErrNotFound
	}
	delete(m.artifacts, id)
	delete(m.blobs, id)
	for k, ut := range m.uploadTokens {
		if ut.ArtifactID == id {
			delete(m.uploadTokens, k)
		}
	}
	return nil
}

func (m *MemoryStore) CreateUploadTicket(_ context.Context, ownerID, targetID, newID, title, contentType, visibility string, tokenHash []byte, maxBytes int64, expiresAt time.Time, maxCount int) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var art Artifact
	if targetID == "" {
		if err := m.ownerQuotaLocked(ownerID, 0, 1, 1<<62, maxCount); err != nil {
			return Artifact{}, err
		}
		art = Artifact{
			ID:          newID,
			OwnerID:     ownerID,
			Title:       title,
			ContentType: contentType,
			Visibility:  visibility,
			Version:     1,
			Status:      artifact.StatusPendingUpload,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		m.artifacts[art.ID] = art
	} else {
		cur, ok := m.artifacts[targetID]
		if !ok || cur.OwnerID != ownerID {
			return Artifact{}, ErrNotFound
		}
		if title != "" {
			cur.Title = title
		}
		if visibility != "" {
			cur.Visibility = visibility
		}
		cur.UpdatedAt = now
		m.artifacts[cur.ID] = cur
		art = cur
	}
	m.uploadTokens[hex.EncodeToString(tokenHash)] = UploadToken{
		TokenHash:           slices.Clone(tokenHash),
		ArtifactID:          art.ID,
		OwnerID:             ownerID,
		ExpectedContentType: contentType,
		MaxBytes:            maxBytes,
		ExpiresAt:           expiresAt,
	}
	return art, nil
}

func (m *MemoryStore) PeekUploadToken(_ context.Context, tokenHash []byte) (UploadToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.uploadTokens[hex.EncodeToString(tokenHash)]
	if !ok || tok.UsedAt != nil || !tok.ExpiresAt.After(time.Now()) {
		return UploadToken{}, ErrUploadTokenInvalid
	}
	u, ok := m.users[tok.OwnerID]
	if !ok || u.Status != UserStatusActive {
		return UploadToken{}, ErrUploadTokenInvalid
	}
	return tok, nil
}

func (m *MemoryStore) CompleteUpload(_ context.Context, tokenHash []byte, data []byte, sha256Hex string, maxStorageBytes int64) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hex.EncodeToString(tokenHash)
	tok, ok := m.uploadTokens[key]
	now := time.Now().UTC()
	if !ok || tok.UsedAt != nil || !tok.ExpiresAt.After(now) {
		return Artifact{}, ErrUploadTokenInvalid
	}
	u, ok := m.users[tok.OwnerID]
	if !ok || u.Status != UserStatusActive {
		return Artifact{}, ErrUserInactive
	}
	cur, ok := m.artifacts[tok.ArtifactID]
	if !ok || cur.OwnerID != tok.OwnerID {
		return Artifact{}, ErrNotFound
	}
	delta := int64(len(data)) - cur.SizeBytes
	if err := m.ownerQuotaLocked(tok.OwnerID, delta, 0, maxStorageBytes, artifact.MaxArtifactsPerUser+1); err != nil {
		return Artifact{}, err
	}

	tok.UsedAt = &now
	m.uploadTokens[key] = tok
	m.blobs[cur.ID] = slices.Clone(data)

	if cur.Status == artifact.StatusReady {
		cur.Version++
	}
	cur.ContentType = tok.ExpectedContentType
	cur.SizeBytes = int64(len(data))
	cur.SHA256 = sha256Hex
	cur.Status = artifact.StatusReady
	cur.UpdatedAt = now
	m.artifacts[cur.ID] = cur
	return cur, nil
}
