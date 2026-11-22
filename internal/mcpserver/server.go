package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"cubus.sh/artifact/internal/artifact"
	"cubus.sh/artifact/internal/auth"
	"cubus.sh/artifact/internal/store"
)

const (
	UploadTokenTTL      = 5 * time.Minute
	maxMCPRequestBytes  = 8 << 20 // 8 MiB (accommodates 4 MiB JSON-escaped HTML + overhead)
	artifactIDRandomLen = 16      // 128-bit entropy -> 22-char base64url
)

type Server struct {
	store         store.Store
	oauth         *auth.OAuthServer
	publicBaseURL string
	logger        *slog.Logger
	mcpServer     *mcp.Server
}

func New(st store.Store, oauth *auth.OAuthServer, publicBaseURL string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		store:         st,
		oauth:         oauth,
		publicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		logger:        logger,
	}
	ms := mcp.NewServer(&mcp.Implementation{
		Name:    "artifact.cubus.sh",
		Version: "0.1.0",
	}, &mcp.ServerOptions{
		Instructions: "Publish and manage web-viewable HTML, PDF, Markdown, SVG, and image artifacts on artifact.cubus.sh. Use publish_artifact for inline HTML/Markdown/SVG text (<=4 MiB) or small base64 binaries (<=1 MiB). Use create_upload for larger PDFs/images to obtain a single-use HTTP PUT upload URL.",
	})
	s.registerTools(ms)
	s.mcpServer = ms
	return s
}

func (s *Server) HTTPHandler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return s.mcpServer
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		Logger:                       s.logger,
		MaxRequestBodyBytes:          maxMCPRequestBytes,
		PropagateRequestCancellation: true,
		DisableLocalhostProtection:   true, // Behind nginx-proxy/Cloudflare; protected by OAuth Bearer tokens.
	})

	// Deliberately omit a narrowed Scopes list on RequireBearerTokenOptions so 401
	// discovery points clients at PRM scopes_supported (artifacts:read + artifacts:write),
	// preventing clients from getting stuck with read-only scope. Scopes are enforced per-tool below.
	protected := mcpauth.RequireBearerToken(s.oauth.TokenVerifier(), &mcpauth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.oauth.ResourceMetadataURL(),
		ClockSkew:           5 * time.Second,
	})(streamable)

	// CORS sits OUTSIDE RequireBearerToken so OPTIONS preflight succeeds with 204.
	return auth.CORSMiddleware(protected)
}

func (s *Server) registerTools(ms *mcp.Server) {
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "publish_artifact",
		Description: "Create and publish a new artifact from inline UTF-8 text (HTML, Markdown, SVG up to 4 MiB) or small base64 binary (PDF/images up to 1 MiB). For larger PDFs or images, call create_upload instead. Visibility defaults to 'private'.",
	}, s.handlePublishArtifact)

	mcp.AddTool(ms, &mcp.Tool{
		Name:        "create_upload",
		Description: "Mint a 5-minute single-use HTTP PUT upload URL for uploading binary artifacts (PDF, PNG, JPEG, WebP) or large text files up to max_upload_mb without sending base64 in tool arguments. Optionally pass artifact_id to replace an existing owned artifact in place.",
	}, s.handleCreateUpload)

	mcp.AddTool(ms, &mcp.Tool{
		Name:        "update_artifact",
		Description: "Update an existing artifact owned by the caller in place (same viewer URL, increments version). Can update title, visibility ('public'|'private'), and/or replace inline content.",
	}, s.handleUpdateArtifact)

	mcp.AddTool(ms, &mcp.Tool{
		Name:        "list_artifacts",
		Description: "List ready artifacts owned by the authenticated caller with optional visibility, content_type, title search, limit (1..100), and offset.",
	}, s.handleListArtifacts)

	mcp.AddTool(ms, &mcp.Tool{
		Name:        "get_artifact",
		Description: "Get metadata for an artifact owned by the caller, and optionally return its UTF-8 text content (for text types up to 512 KiB).",
	}, s.handleGetArtifact)

	mcp.AddTool(ms, &mcp.Tool{
		Name:        "delete_artifact",
		Description: "Permanently delete an artifact owned by the caller.",
	}, s.handleDeleteArtifact)
}

type ArtifactView struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	ContentType string `json:"content_type"`
	Visibility  string `json:"visibility"`
	Version     int    `json:"version"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	ViewerURL   string `json:"viewer_url"`
	RawURL      string `json:"raw_url"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (s *Server) toView(a store.Artifact) ArtifactView {
	return ArtifactView{
		ID:          a.ID,
		Title:       a.Title,
		ContentType: a.ContentType,
		Visibility:  a.Visibility,
		Version:     a.Version,
		SizeBytes:   a.SizeBytes,
		SHA256:      a.SHA256,
		ViewerURL:   s.publicBaseURL + "/v/" + a.ID,
		RawURL:      s.publicBaseURL + "/raw/" + a.ID,
		CreatedAt:   a.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   a.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

type PublishArtifactInput struct {
	Title       string `json:"title" jsonschema:"Short human-readable title (1..200 characters)."`
	ContentType string `json:"content_type" jsonschema:"MIME type: text/html, text/markdown, image/svg+xml, application/pdf, image/png, image/jpeg, or image/webp."`
	Visibility  string `json:"visibility,omitempty" jsonschema:"Access level: 'private' (default, owner-only) or 'public' (anyone with link)."`
	Content     string `json:"content" jsonschema:"Artifact content as UTF-8 text (default) or base64 when encoding='base64'."`
	Encoding    string `json:"encoding,omitempty" jsonschema:"Content encoding: 'utf8' (default) or 'base64'."`
}

func (s *Server) handlePublishArtifact(ctx context.Context, _ *mcp.CallToolRequest, in PublishArtifactInput) (*mcp.CallToolResult, ArtifactView, error) {
	userID, err := requireScope(ctx, auth.ScopeWrite)
	if err != nil {
		return nil, ArtifactView{}, err
	}

	title, err := artifact.SanitizeTitle(in.Title)
	if err != nil {
		return nil, ArtifactView{}, err
	}
	spec, ok := artifact.LookupMedia(in.ContentType)
	if !ok {
		return nil, ArtifactView{}, fmt.Errorf("unsupported content_type %q (allowed: %s)", in.ContentType, strings.Join(artifact.SupportedContentTypes(), ", "))
	}
	visibility, err := artifact.NormalizeVisibility(in.Visibility)
	if err != nil {
		return nil, ArtifactView{}, err
	}

	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		return nil, ArtifactView{}, errors.New("failed to load server settings")
	}

	payload, err := decodeInlineContent(spec, in.Content, in.Encoding, settings.MaxUploadMB)
	if err != nil {
		return nil, ArtifactView{}, err
	}
	if err := artifact.ValidatePayload(spec.ContentType, payload); err != nil {
		return nil, ArtifactView{}, err
	}

	id, err := auth.RandomToken(artifactIDRandomLen)
	if err != nil {
		return nil, ArtifactView{}, errors.New("failed to generate artifact id")
	}
	sum := sha256.Sum256(payload)
	created, err := s.store.CreateArtifactWithBlob(ctx, store.Artifact{
		ID:          id,
		OwnerID:     userID,
		Title:       title,
		ContentType: spec.ContentType,
		Visibility:  visibility,
		SHA256:      hex.EncodeToString(sum[:]),
	}, payload, int64(settings.MaxStorageMBPerUser)<<20, artifact.MaxArtifactsPerUser)
	if err != nil {
		if errors.Is(err, store.ErrQuotaExceeded) {
			return nil, ArtifactView{}, errors.New("storage or artifact count quota exceeded")
		}
		return nil, ArtifactView{}, errors.New("failed to store artifact")
	}
	return nil, s.toView(created), nil
}

type CreateUploadInput struct {
	Title       string `json:"title,omitempty" jsonschema:"Artifact title (required when creating a new artifact; optional when updating artifact_id)."`
	ContentType string `json:"content_type" jsonschema:"MIME type of the file to upload: application/pdf, text/html, text/markdown, image/svg+xml, image/png, image/jpeg, or image/webp."`
	Visibility  string `json:"visibility,omitempty" jsonschema:"Access level: 'private' (default) or 'public'."`
	ArtifactID  string `json:"artifact_id,omitempty" jsonschema:"Optional existing owned artifact ID to replace in place upon upload completion."`
}

type CreateUploadOutput struct {
	ArtifactID  string `json:"artifact_id"`
	UploadURL   string `json:"upload_url"`
	Method      string `json:"method"`
	ContentType string `json:"content_type"`
	MaxBytes    int64  `json:"max_bytes"`
	ExpiresAt   string `json:"expires_at"`
	ViewerURL   string `json:"viewer_url"`
	CurlCommand string `json:"curl_command"`
}

func (s *Server) handleCreateUpload(ctx context.Context, _ *mcp.CallToolRequest, in CreateUploadInput) (*mcp.CallToolResult, CreateUploadOutput, error) {
	userID, err := requireScope(ctx, auth.ScopeWrite)
	if err != nil {
		return nil, CreateUploadOutput{}, err
	}

	spec, ok := artifact.LookupMedia(in.ContentType)
	if !ok {
		return nil, CreateUploadOutput{}, fmt.Errorf("unsupported content_type %q", in.ContentType)
	}

	targetID := strings.TrimSpace(in.ArtifactID)
	var title string
	if targetID == "" || strings.TrimSpace(in.Title) != "" {
		title, err = artifact.SanitizeTitle(in.Title)
		if err != nil {
			return nil, CreateUploadOutput{}, err
		}
	}

	var visibility string
	if targetID == "" || strings.TrimSpace(in.Visibility) != "" {
		visibility, err = artifact.NormalizeVisibility(in.Visibility)
		if err != nil {
			return nil, CreateUploadOutput{}, err
		}
	}

	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		return nil, CreateUploadOutput{}, errors.New("failed to load server settings")
	}
	maxBytes := int64(settings.MaxUploadMB) << 20

	newID, err := auth.RandomToken(artifactIDRandomLen)
	if err != nil {
		return nil, CreateUploadOutput{}, errors.New("failed to generate artifact id")
	}
	rawToken, err := auth.RandomToken(32)
	if err != nil {
		return nil, CreateUploadOutput{}, errors.New("failed to generate upload token")
	}
	expiresAt := time.Now().UTC().Add(UploadTokenTTL)

	art, err := s.store.CreateUploadTicket(
		ctx,
		userID,
		targetID,
		newID,
		title,
		spec.ContentType,
		visibility,
		auth.SHA256Bytes(rawToken),
		maxBytes,
		expiresAt,
		artifact.MaxArtifactsPerUser,
	)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, CreateUploadOutput{}, errors.New("artifact not found")
		}
		if errors.Is(err, store.ErrQuotaExceeded) {
			return nil, CreateUploadOutput{}, errors.New("artifact count quota exceeded")
		}
		return nil, CreateUploadOutput{}, errors.New("failed to create upload ticket")
	}

	uploadURL := s.publicBaseURL + "/upload/" + rawToken
	return nil, CreateUploadOutput{
		ArtifactID:  art.ID,
		UploadURL:   uploadURL,
		Method:      http.MethodPut,
		ContentType: spec.ContentType,
		MaxBytes:    maxBytes,
		ExpiresAt:   expiresAt.Format(time.RFC3339),
		ViewerURL:   s.publicBaseURL + "/v/" + art.ID,
		CurlCommand: fmt.Sprintf("curl --fail-with-body -X PUT -H 'Content-Type: %s' --data-binary @<file> '%s'", spec.ContentType, uploadURL),
	}, nil
}

type UpdateArtifactInput struct {
	ID          string  `json:"id" jsonschema:"Artifact ID to update."`
	Title       *string `json:"title,omitempty" jsonschema:"Optional new title."`
	Visibility  *string `json:"visibility,omitempty" jsonschema:"Optional new visibility: 'public' or 'private'."`
	Content     *string `json:"content,omitempty" jsonschema:"Optional replacement content."`
	ContentType *string `json:"content_type,omitempty" jsonschema:"Optional new MIME type when replacing content."`
	Encoding    string  `json:"encoding,omitempty" jsonschema:"Content encoding when replacing content: 'utf8' (default) or 'base64'."`
}

func (s *Server) handleUpdateArtifact(ctx context.Context, _ *mcp.CallToolRequest, in UpdateArtifactInput) (*mcp.CallToolResult, ArtifactView, error) {
	userID, err := requireScope(ctx, auth.ScopeWrite)
	if err != nil {
		return nil, ArtifactView{}, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, ArtifactView{}, errors.New("id is required")
	}

	existing, err := s.store.GetArtifactForOwner(ctx, id, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ArtifactView{}, errors.New("artifact not found")
		}
		return nil, ArtifactView{}, errors.New("failed to load artifact")
	}

	var patch store.ArtifactPatch
	if in.Title != nil {
		clean, err := artifact.SanitizeTitle(*in.Title)
		if err != nil {
			return nil, ArtifactView{}, err
		}
		patch.Title = &clean
	}
	if in.Visibility != nil {
		vis, err := artifact.NormalizeVisibility(*in.Visibility)
		if err != nil {
			return nil, ArtifactView{}, err
		}
		patch.Visibility = &vis
	}

	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		return nil, ArtifactView{}, errors.New("failed to load server settings")
	}

	var newData []byte
	if in.Content != nil {
		ct := existing.ContentType
		if in.ContentType != nil && strings.TrimSpace(*in.ContentType) != "" {
			ct = *in.ContentType
		}
		spec, ok := artifact.LookupMedia(ct)
		if !ok {
			return nil, ArtifactView{}, fmt.Errorf("unsupported content_type %q", ct)
		}
		patch.ContentType = &spec.ContentType

		newData, err = decodeInlineContent(spec, *in.Content, in.Encoding, settings.MaxUploadMB)
		if err != nil {
			return nil, ArtifactView{}, err
		}
		if err := artifact.ValidatePayload(spec.ContentType, newData); err != nil {
			return nil, ArtifactView{}, err
		}
		sum := sha256.Sum256(newData)
		hexSum := hex.EncodeToString(sum[:])
		patch.SHA256 = &hexSum
	} else if in.ContentType != nil {
		return nil, ArtifactView{}, errors.New("content_type cannot be changed without providing content (or use create_upload)")
	}

	if patch.Title == nil && patch.Visibility == nil && newData == nil {
		return nil, ArtifactView{}, errors.New("provide at least one field to update: title, visibility, or content")
	}

	updated, err := s.store.UpdateArtifact(ctx, userID, id, patch, newData, int64(settings.MaxStorageMBPerUser)<<20)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ArtifactView{}, errors.New("artifact not found")
		}
		if errors.Is(err, store.ErrQuotaExceeded) {
			return nil, ArtifactView{}, errors.New("storage quota exceeded")
		}
		return nil, ArtifactView{}, errors.New("failed to update artifact")
	}
	return nil, s.toView(updated), nil
}

type ListArtifactsInput struct {
	Visibility  string `json:"visibility,omitempty" jsonschema:"Filter by 'public' or 'private'."`
	ContentType string `json:"content_type,omitempty" jsonschema:"Filter by MIME type."`
	Query       string `json:"query,omitempty" jsonschema:"Case-insensitive substring search against artifact title."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Page size (default 20, max 100)."`
	Offset      int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)."`
}

type ListArtifactsOutput struct {
	Items []ArtifactView `json:"items"`
	Count int            `json:"count"`
}

func (s *Server) handleListArtifacts(ctx context.Context, _ *mcp.CallToolRequest, in ListArtifactsInput) (*mcp.CallToolResult, ListArtifactsOutput, error) {
	userID, err := requireScope(ctx, auth.ScopeRead)
	if err != nil {
		return nil, ListArtifactsOutput{}, err
	}

	var vis string
	if strings.TrimSpace(in.Visibility) != "" {
		vis, err = artifact.NormalizeVisibility(in.Visibility)
		if err != nil {
			return nil, ListArtifactsOutput{}, err
		}
	}
	var ct string
	if strings.TrimSpace(in.ContentType) != "" {
		spec, ok := artifact.LookupMedia(in.ContentType)
		if !ok {
			return nil, ListArtifactsOutput{}, fmt.Errorf("unsupported content_type %q", in.ContentType)
		}
		ct = spec.ContentType
	}

	rows, err := s.store.ListArtifactsForOwner(ctx, userID, store.ListArtifactsFilter{
		Visibility:  vis,
		ContentType: ct,
		Query:       in.Query,
		Limit:       in.Limit,
		Offset:      in.Offset,
	})
	if err != nil {
		return nil, ListArtifactsOutput{}, errors.New("failed to list artifacts")
	}

	items := make([]ArtifactView, 0, len(rows))
	for _, a := range rows {
		items = append(items, s.toView(a))
	}
	return nil, ListArtifactsOutput{Items: items, Count: len(items)}, nil
}

type GetArtifactInput struct {
	ID             string `json:"id" jsonschema:"Artifact ID to retrieve."`
	IncludeContent bool   `json:"include_content,omitempty" jsonschema:"If true, include UTF-8 text content for text artifacts up to 512 KiB."`
}

type GetArtifactOutput struct {
	ArtifactView
	Content          string `json:"content,omitempty"`
	ContentTruncated bool   `json:"content_truncated,omitempty"`
	ContentNote      string `json:"content_note,omitempty"`
}

func (s *Server) handleGetArtifact(ctx context.Context, _ *mcp.CallToolRequest, in GetArtifactInput) (*mcp.CallToolResult, GetArtifactOutput, error) {
	userID, err := requireScope(ctx, auth.ScopeRead)
	if err != nil {
		return nil, GetArtifactOutput{}, err
	}
	art, err := s.store.GetArtifactForOwner(ctx, strings.TrimSpace(in.ID), userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, GetArtifactOutput{}, errors.New("artifact not found")
		}
		return nil, GetArtifactOutput{}, errors.New("failed to load artifact")
	}

	out := GetArtifactOutput{ArtifactView: s.toView(art)}
	if in.IncludeContent && art.Status == artifact.StatusReady {
		spec, ok := artifact.LookupMedia(art.ContentType)
		if !ok || !spec.IsText {
			out.ContentNote = "binary content omitted; download via raw_url"
		} else if art.SizeBytes > artifact.MaxGetContentBytes {
			out.ContentTruncated = true
			out.ContentNote = fmt.Sprintf("text content exceeds %d KiB inline limit; download via raw_url", artifact.MaxGetContentBytes>>10)
		} else {
			blob, err := s.store.GetArtifactBlob(ctx, art.ID)
			if err != nil {
				return nil, GetArtifactOutput{}, errors.New("failed to read artifact content")
			}
			out.Content = string(blob)
		}
	}
	return nil, out, nil
}

type DeleteArtifactInput struct {
	ID string `json:"id" jsonschema:"Artifact ID to delete."`
}

type DeleteArtifactOutput struct {
	Deleted bool   `json:"deleted"`
	ID      string `json:"id"`
}

func (s *Server) handleDeleteArtifact(ctx context.Context, _ *mcp.CallToolRequest, in DeleteArtifactInput) (*mcp.CallToolResult, DeleteArtifactOutput, error) {
	userID, err := requireScope(ctx, auth.ScopeWrite)
	if err != nil {
		return nil, DeleteArtifactOutput{}, err
	}
	id := strings.TrimSpace(in.ID)
	if err := s.store.DeleteArtifactForOwner(ctx, id, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, DeleteArtifactOutput{}, errors.New("artifact not found")
		}
		return nil, DeleteArtifactOutput{}, errors.New("failed to delete artifact")
	}
	return nil, DeleteArtifactOutput{Deleted: true, ID: id}, nil
}

func requireScope(ctx context.Context, needed string) (string, error) {
	ti := mcpauth.TokenInfoFromContext(ctx)
	if ti == nil || ti.UserID == "" {
		return "", errors.New("unauthenticated request")
	}
	if !slices.Contains(ti.Scopes, needed) {
		return "", fmt.Errorf("insufficient scope: %s is required", needed)
	}
	return ti.UserID, nil
}

func decodeInlineContent(spec artifact.MediaSpec, content, encoding string, maxUploadMB int) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" {
		if spec.IsText {
			enc = "utf8"
		} else {
			enc = "base64"
		}
	}
	maxSettingBytes := int64(maxUploadMB) << 20

	switch enc {
	case "utf8":
		if !spec.IsText {
			return nil, fmt.Errorf("%s requires encoding='base64' (<=1 MiB) or create_upload for larger files", spec.ContentType)
		}
		limit := min(int64(artifact.MaxInlineTextBytes), maxSettingBytes)
		if int64(len(content)) > limit {
			return nil, fmt.Errorf("inline text content exceeds %d bytes; use create_upload instead", limit)
		}
		return []byte(content), nil
	case "base64":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 content: %w", err)
		}
		limit := min(int64(artifact.MaxInlineBase64Bytes), maxSettingBytes)
		if int64(len(raw)) > limit {
			return nil, fmt.Errorf("inline base64 content exceeds %d bytes; use create_upload instead", limit)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unsupported encoding %q: use 'utf8' or 'base64'", encoding)
	}
}
