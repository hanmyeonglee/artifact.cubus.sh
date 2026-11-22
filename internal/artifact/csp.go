package artifact

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

const (
	// ShellCSP protects /v/{id}, /, /login, and /signup (zero inline scripts).
	ShellCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

	// AuthorizeCSP protects /oauth/authorize consent screens.
	// Deliberately omits form-action because Chromium enforces form-action across
	// HTTP 302/303 OAuth callback redirect chains (e.g. https://claude.ai or
	// http://127.0.0.1:<port>); default-src does not fall back to form-action.
	AuthorizeCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

var DefaultAllowedCDNOrigins = []string{
	"https://cdn.jsdelivr.net",
	"https://cdnjs.cloudflare.com",
	"https://unpkg.com",
	"https://esm.sh",
	"https://cdn.tailwindcss.com",
	"https://fonts.googleapis.com",
	"https://fonts.gstatic.com",
}

// NormalizeCDNOrigins validates each entry as a strict https:// origin
// (preventing CSP directive/header injection) and returns deduplicated canonical origins.
func NormalizeCDNOrigins(raw []string) ([]string, error) {
	if len(raw) > 50 {
		return nil, fmt.Errorf("too many CDN origins (%d > 50)", len(raw))
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		origin, err := validateCDNOrigin(entry)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, origin) {
			out = append(out, origin)
		}
	}
	return out, nil
}

func validateCDNOrigin(entry string) (string, error) {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return "", fmt.Errorf("empty CDN origin")
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == ';' || r == ',' || r == '*' || r == '\'' || r == '"' || r == '\\' {
			return "", fmt.Errorf("invalid character in CDN origin %q", entry)
		}
	}
	u, err := url.Parse(trimmed)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("CDN origin %q must be a valid https:// origin", entry)
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("CDN origin %q must not include userinfo, path, query, or fragment", entry)
	}
	host := strings.ToLower(u.Host)
	return "https://" + host, nil
}

// BuildRawCSP returns the strict per-content-type Content-Security-Policy for /raw/{id}.
func BuildRawCSP(contentType string, cdnOrigins []string) string {
	spec, ok := LookupMedia(contentType)
	if !ok {
		return "default-src 'none'; sandbox; frame-ancestors 'none'"
	}

	switch spec.ContentType {
	case "text/html":
		safeCDNs, err := NormalizeCDNOrigins(cdnOrigins)
		if err != nil {
			safeCDNs = DefaultAllowedCDNOrigins
		}
		cdnList := ""
		if len(safeCDNs) > 0 {
			cdnList = " " + strings.Join(safeCDNs, " ")
		}
		return fmt.Sprintf(
			"sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'%s; style-src 'unsafe-inline'%s; img-src data: blob:%s; font-src data:%s; connect-src 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; frame-ancestors 'self'",
			cdnList, cdnList, cdnList, cdnList,
		)

	case "application/pdf":
		return "default-src 'none'; object-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'"

	case "image/svg+xml":
		return "default-src 'none'; sandbox; style-src 'unsafe-inline'; frame-ancestors 'self'"

	default:
		return "default-src 'none'; sandbox; frame-ancestors 'self'"
	}
}
