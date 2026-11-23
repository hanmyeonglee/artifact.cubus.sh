package adminapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"cubus.sh/artifact/internal/artifact"
	"cubus.sh/artifact/internal/store"
)

const (
	maxAdminBodyBytes = 16 << 10
	minUploadMB       = 1
	maxUploadMB       = 50 // Aligned with nginx client_max_body_size 55m
	minStorageMB      = 10
	maxStorageMB      = 102400
)

type Server struct {
	store         store.Store
	token         string
	allowCIDR     *netip.Prefix
	publicBaseURL string
}

func New(st store.Store, token string, allowCIDR *netip.Prefix, publicBaseURL ...string) *Server {
	base := ""
	if len(publicBaseURL) > 0 {
		base = strings.TrimRight(strings.TrimSpace(publicBaseURL[0]), "/")
	}
	return &Server{
		store:         st,
		token:         token,
		allowCIDR:     allowCIDR,
		publicBaseURL: base,
	}
}

// ResolveBindAddr resolves the exact listen address for the internal Admin API.
// Never binds 0.0.0.0: binds strictly to the container's interface IP inside
// allowCIDR (admin network) when configured, or 127.0.0.1 for local dev.
func ResolveBindAddr(allowCIDR *netip.Prefix, port int) (string, error) {
	if allowCIDR == nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("list interface addresses: %w", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if allowCIDR.Contains(addr) {
			return net.JoinHostPort(addr.String(), strconv.Itoa(port)), nil
		}
	}
	return "", fmt.Errorf("no local interface IP found inside ADMIN_BIND_CIDR %s", allowCIDR.String())
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/manifest", s.handleManifest)
	mux.HandleFunc("GET /admin/v1/users", s.handleListUsers)
	mux.HandleFunc("POST /admin/v1/users/{id}/approve", s.handleApproveUser)
	mux.HandleFunc("POST /admin/v1/users/{id}/deny", s.handleDenyUser)
	mux.HandleFunc("GET /admin/v1/settings", s.handleGetSettings)
	mux.HandleFunc("PATCH /admin/v1/settings", s.handlePatchSettings)
	mux.HandleFunc("GET /admin/v1/artifacts", s.handleListArtifacts)
	mux.HandleFunc("DELETE /admin/v1/artifacts/{id}", s.handleDeleteArtifact)
	return s.guardMiddleware(mux)
}

func (s *Server) guardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peerHost = r.RemoteAddr
		}
		peerIP, err := netip.ParseAddr(strings.TrimSpace(peerHost))
		if err != nil {
			writeAdminError(w, http.StatusForbidden, "invalid peer address")
			return
		}
		peerIP = peerIP.Unmap()
		if s.allowCIDR != nil {
			if !s.allowCIDR.Contains(peerIP) {
				writeAdminError(w, http.StatusForbidden, "peer outside allowed admin subnet")
				return
			}
		} else if !peerIP.IsLoopback() {
			writeAdminError(w, http.StatusForbidden, "admin API restricted to loopback")
			return
		}

		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") ||
			subtle.ConstantTimeCompare([]byte(fields[1]), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="artifact-admin"`)
			writeAdminError(w, http.StatusUnauthorized, "missing or invalid admin bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"service":      "artifact",
		"version":      "0.2.0",
		"capabilities": []string{"users", "settings", "artifacts"},
		"endpoints": map[string]string{
			"users_list":      "GET /admin/v1/users",
			"user_approve":    "POST /admin/v1/users/{id}/approve",
			"user_deny":       "POST /admin/v1/users/{id}/deny",
			"settings_get":    "GET /admin/v1/settings",
			"settings_update": "PATCH /admin/v1/settings",
			"artifacts_list":  "GET /admin/v1/artifacts",
			"artifact_delete": "DELETE /admin/v1/artifacts/{id}",
		},
		"settings_schema": []map[string]any{
			{
				"key":   "allow_signup",
				"label": "Allow new account requests",
				"type":  "bool",
				"help":  "When enabled, visitors can submit pending account requests at /signup.",
			},
			{
				"key":   "max_upload_mb",
				"label": "Max upload size (MiB)",
				"type":  "int",
				"min":   minUploadMB,
				"max":   maxUploadMB,
				"help":  "Maximum single artifact size accepted via PUT /upload/{token}.",
			},
			{
				"key":   "max_storage_mb_per_user",
				"label": "Max storage per user (MiB)",
				"type":  "int",
				"min":   minStorageMB,
				"max":   maxStorageMB,
				"help":  "Total artifact byte quota enforced per user.",
			},
			{
				"key":   "allowed_cdn_origins",
				"label": "Allowed HTML CDN origins",
				"type":  "string_list",
				"help":  "Strict https:// origins allowed inside sandboxed HTML artifact CSP (one per line).",
			},
		},
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	if statusFilter != "" && statusFilter != store.UserStatusPending && statusFilter != store.UserStatusActive && statusFilter != store.UserStatusDenied {
		writeAdminError(w, http.StatusBadRequest, "invalid status filter (expected pending, active, or denied)")
		return
	}
	users, err := s.store.ListUsersWithCounts(r.Context(), statusFilter)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleApproveUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	u, err := s.store.ApproveUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeAdminError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to approve user")
		return
	}
	writeAdminJSON(w, http.StatusOK, u)
}

func (s *Server) handleDenyUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	u, err := s.store.DenyUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeAdminError(w, http.StatusNotFound, "user not found")
		return
	}
	if errors.Is(err, store.ErrLastAdmin) {
		writeAdminError(w, http.StatusConflict, "cannot deny the last active admin")
		return
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to deny user")
		return
	}
	writeAdminJSON(w, http.StatusOK, u)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	writeAdminJSON(w, http.StatusOK, settings)
}

func (s *Server) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeAdminError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeAdminError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var patch store.SettingsPatch
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&patch); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid settings patch JSON")
		return
	}

	if patch.MaxUploadMB != nil && (*patch.MaxUploadMB < minUploadMB || *patch.MaxUploadMB > maxUploadMB) {
		writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("max_upload_mb must be between %d and %d", minUploadMB, maxUploadMB))
		return
	}
	if patch.MaxStorageMBPerUser != nil && (*patch.MaxStorageMBPerUser < minStorageMB || *patch.MaxStorageMBPerUser > maxStorageMB) {
		writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("max_storage_mb_per_user must be between %d and %d", minStorageMB, maxStorageMB))
		return
	}
	if patch.AllowedCDNOrigins != nil {
		normalized, err := artifact.NormalizeCDNOrigins(*patch.AllowedCDNOrigins)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}
		patch.AllowedCDNOrigins = &normalized
	}

	updated, err := s.store.UpdateSettings(r.Context(), patch)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to update settings")
		return
	}
	writeAdminJSON(w, http.StatusOK, updated)
}

type adminArtifactItem struct {
	store.AdminArtifactSummary
	ViewerURL string `json:"viewer_url,omitempty"`
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	visibility := strings.TrimSpace(q.Get("visibility"))
	if visibility != "" && visibility != artifact.VisibilityPublic && visibility != artifact.VisibilityPrivate {
		writeAdminError(w, http.StatusBadRequest, "invalid visibility filter (expected public or private)")
		return
	}

	contentType := strings.TrimSpace(q.Get("content_type"))
	if contentType != "" {
		spec, ok := artifact.LookupMedia(contentType)
		if !ok {
			writeAdminError(w, http.StatusBadRequest, "unsupported content_type filter")
			return
		}
		contentType = spec.ContentType
	}

	limit := 50
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 || n > 100 {
			writeAdminError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = n
	}

	offset := 0
	if rawOffset := strings.TrimSpace(q.Get("offset")); rawOffset != "" {
		n, err := strconv.Atoi(rawOffset)
		if err != nil || n < 0 {
			writeAdminError(w, http.StatusBadRequest, "offset must be >= 0")
			return
		}
		offset = n
	}

	res, err := s.store.ListAllArtifactsAdmin(r.Context(), store.AdminArtifactListFilter{
		Owner:       strings.TrimSpace(q.Get("owner")),
		Visibility:  visibility,
		ContentType: contentType,
		Query:       strings.TrimSpace(q.Get("q")),
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list artifacts")
		return
	}

	items := make([]adminArtifactItem, 0, len(res.Items))
	for _, item := range res.Items {
		viewerURL := "/v/" + item.ID
		if s.publicBaseURL != "" {
			viewerURL = s.publicBaseURL + "/v/" + item.ID
		}
		items = append(items, adminArtifactItem{
			AdminArtifactSummary: item,
			ViewerURL:            viewerURL,
		})
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"artifacts":   items,
		"total_count": res.TotalCount,
		"total_bytes": res.TotalBytes,
		"limit":       limit,
		"offset":      offset,
	})
}

func (s *Server) handleDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeAdminError(w, http.StatusBadRequest, "artifact id is required")
		return
	}
	if err := s.store.DeleteArtifactByIDAdmin(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "artifact not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to delete artifact")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	writeAdminJSON(w, status, map[string]string{"error": msg})
}

func writeAdminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
