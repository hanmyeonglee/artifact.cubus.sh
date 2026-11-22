package artifact

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxTitleRunes         = 200
	MaxInlineTextBytes    = 4 << 20   // 4 MiB for MCP inline text publish/update
	MaxInlineBase64Bytes  = 1 << 20   // 1 MiB for MCP inline base64 binary
	MaxGetContentBytes    = 512 << 10 // 512 KiB returned by MCP get_artifact
	MaxArtifactsPerUser   = 1000
	VisibilityPublic      = "public"
	VisibilityPrivate     = "private"
	StatusPendingUpload   = "pending_upload"
	StatusReady           = "ready"
)

type MediaSpec struct {
	ContentType string
	Extension   string
	IsText      bool
	Label       string
}

var supportedMedia = map[string]MediaSpec{
	"text/html":       {ContentType: "text/html", Extension: ".html", IsText: true, Label: "HTML"},
	"application/pdf": {ContentType: "application/pdf", Extension: ".pdf", IsText: false, Label: "PDF"},
	"text/markdown":   {ContentType: "text/markdown", Extension: ".md", IsText: true, Label: "Markdown"},
	"image/svg+xml":   {ContentType: "image/svg+xml", Extension: ".svg", IsText: true, Label: "SVG"},
	"image/png":       {ContentType: "image/png", Extension: ".png", IsText: false, Label: "PNG"},
	"image/jpeg":      {ContentType: "image/jpeg", Extension: ".jpg", IsText: false, Label: "JPEG"},
	"image/webp":      {ContentType: "image/webp", Extension: ".webp", IsText: false, Label: "WebP"},
}

func LookupMedia(raw string) (MediaSpec, bool) {
	mt, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		return MediaSpec{}, false
	}
	spec, ok := supportedMedia[strings.ToLower(mt)]
	return spec, ok
}

func SupportedContentTypes() []string {
	return []string{
		"text/html",
		"application/pdf",
		"text/markdown",
		"image/svg+xml",
		"image/png",
		"image/jpeg",
		"image/webp",
	}
}

func NormalizeVisibility(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return VisibilityPrivate, nil
	}
	if v != VisibilityPublic && v != VisibilityPrivate {
		return "", fmt.Errorf("invalid visibility %q: must be 'public' or 'private'", raw)
	}
	return v, nil
}

func SanitizeTitle(raw string) (string, error) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	clean := strings.TrimSpace(b.String())
	if clean == "" {
		return "", errors.New("title must not be empty")
	}
	if utf8.RuneCountInString(clean) > MaxTitleRunes {
		return "", fmt.Errorf("title exceeds maximum length of %d characters", MaxTitleRunes)
	}
	return clean, nil
}

// ValidatePayload enforces exact format signatures per declared content_type.
func ValidatePayload(contentType string, data []byte) error {
	spec, ok := LookupMedia(contentType)
	if !ok {
		return fmt.Errorf("unsupported content_type %q", contentType)
	}
	if len(data) == 0 {
		return errors.New("artifact payload must not be empty")
	}

	switch spec.ContentType {
	case "application/pdf":
		if !bytes.HasPrefix(data, []byte("%PDF-")) {
			return errors.New("invalid PDF payload: missing %PDF- signature")
		}
		return nil

	case "image/png":
		pngSig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
		if !bytes.HasPrefix(data, pngSig) {
			return errors.New("invalid PNG payload: bad signature")
		}
		return nil

	case "image/jpeg":
		if len(data) < 3 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
			return errors.New("invalid JPEG payload: bad signature")
		}
		return nil

	case "image/webp":
		if len(data) < 12 || !bytes.Equal(data[:4], []byte("RIFF")) || !bytes.Equal(data[8:12], []byte("WEBP")) {
			return errors.New("invalid WebP payload: bad signature")
		}
		return nil

	case "text/html", "text/markdown":
		if !utf8.Valid(data) {
			return fmt.Errorf("invalid %s payload: must be valid UTF-8", spec.Label)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return fmt.Errorf("invalid %s payload: NUL byte not allowed", spec.Label)
		}
		return nil

	case "image/svg+xml":
		if !utf8.Valid(data) {
			return errors.New("invalid SVG payload: must be valid UTF-8")
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return errors.New("invalid SVG payload: NUL byte not allowed")
		}
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("<!doctype")) || bytes.Contains(lower, []byte("<!entity")) {
			return errors.New("invalid SVG payload: DOCTYPE and ENTITY declarations are forbidden")
		}
		if err := validateSVGRoot(data); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("unsupported content_type %q", contentType)
}

func validateSVGRoot(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Entity = map[string]string{}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return errors.New("invalid SVG payload: missing <svg> root element")
		}
		if err != nil {
			return fmt.Errorf("invalid SVG XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.ToLower(t.Name.Local) != "svg" {
				return fmt.Errorf("invalid SVG payload: root element is <%s>, expected <svg>", t.Name.Local)
			}
			return nil
		case xml.Directive:
			return errors.New("invalid SVG payload: XML directives are forbidden")
		}
	}
}

// SafeContentDisposition builds a header-injection-safe Content-Disposition value.
func SafeContentDisposition(disposition, title, contentType string) string {
	ext := ".bin"
	if spec, ok := LookupMedia(contentType); ok {
		ext = spec.Extension
	}

	var b strings.Builder
	for _, r := range title {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ' ' {
			b.WriteRune(r)
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	base := strings.Trim(strings.TrimSpace(b.String()), "._ ")
	if base == "" {
		base = "artifact"
	}
	runes := []rune(base)
	if len(runes) > 80 {
		base = string(runes[:80])
	}
	if !strings.HasSuffix(strings.ToLower(base), ext) {
		base += ext
	}
	formatted := mime.FormatMediaType(disposition, map[string]string{"filename": base})
	if formatted == "" {
		return disposition + `; filename="artifact` + ext + `"`
	}
	return formatted
}
