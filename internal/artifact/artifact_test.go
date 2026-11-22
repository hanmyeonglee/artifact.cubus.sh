package artifact

import (
	"strings"
	"testing"
)

func TestValidatePayloadSignatures(t *testing.T) {
	validCases := []struct {
		ct   string
		data []byte
	}{
		{"text/html", []byte("<!doctype html><h1>Hello</h1>")},
		{"text/markdown", []byte("# Heading\n\nParagraph")},
		{"image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>`)},
		{"application/pdf", []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n")},
		{"image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}},
		{"image/jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00}},
		{"image/webp", []byte("RIFF\x10\x00\x00\x00WEBP")},
	}
	for _, tc := range validCases {
		if err := ValidatePayload(tc.ct, tc.data); err != nil {
			t.Fatalf("expected valid %s, got %v", tc.ct, err)
		}
	}

	invalidCases := []struct {
		name string
		ct   string
		data []byte
	}{
		{"empty", "text/html", nil},
		{"html nul", "text/html", []byte("<h1>\x00</h1>")},
		{"html bad utf8", "text/html", []byte{0xff, 0xfe}},
		{"fake pdf", "application/pdf", []byte("<html>not a pdf</html>")},
		{"fake png", "image/png", []byte("not-a-png")},
		{"fake jpeg", "image/jpeg", []byte{0x00, 0x01, 0x02}},
		{"fake webp", "image/webp", []byte("RIFF\x10\x00\x00\x00WAVE")},
		{"svg doctype", "image/svg+xml", []byte(`<!DOCTYPE svg SYSTEM "http://evil"><svg/>`)},
		{"svg entity", "image/svg+xml", []byte(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`)},
		{"svg non-svg root", "image/svg+xml", []byte(`<html><body>hi</body></html>`)},
		{"unsupported type", "application/octet-stream", []byte("abc")},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(tc.ct, tc.data); err == nil {
				t.Fatalf("expected error for %s (%s)", tc.name, tc.ct)
			}
		})
	}
}

func TestMarkdownSanitizationNeutralizesXSS(t *testing.T) {
	r := NewMarkdownRenderer()
	// Covers raw <script>, javascript: links, and entity-encoded CVE-2026-5160 bypasses.
	src := []byte("# Title\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1))\n\n[y](javascript&colon;alert(2))\n\n[ok](https://example.com)")
	out, err := r.Render(src)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	s := string(out)
	if strings.Contains(strings.ToLower(s), "<script") || strings.Contains(strings.ToLower(s), "javascript:") {
		t.Fatalf("unsafe output leaked through markdown sanitizer: %s", s)
	}
	if !strings.Contains(s, `href="https://example.com"`) {
		t.Fatalf("expected safe link preserved, got: %s", s)
	}
	if !strings.Contains(s, "noreferrer") {
		t.Fatalf("expected noreferrer on external links, got: %s", s)
	}
}

func TestNormalizeCDNOriginsBlocksCSPInjection(t *testing.T) {
	ok, err := NormalizeCDNOrigins([]string{"https://CDN.JSDELIVR.NET", "https://unpkg.com", "https://unpkg.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ok) != 2 || ok[0] != "https://cdn.jsdelivr.net" || ok[1] != "https://unpkg.com" {
		t.Fatalf("unexpected normalized origins: %#v", ok)
	}

	badEntries := []string{
		"http://insecure.example.com",
		"https://cdn.example.com; connect-src *",
		"https://cdn.example.com/path",
		"https://*.example.com",
		"https://cdn.example.com 'unsafe-inline'",
		"https://user:pass@cdn.example.com",
		"",
	}
	for _, entry := range badEntries {
		if _, err := NormalizeCDNOrigins([]string{entry}); err == nil {
			t.Fatalf("expected CSP origin rejection for %q", entry)
		}
	}
}

func TestBuildRawCSP(t *testing.T) {
	htmlCSP := BuildRawCSP("text/html", []string{"https://cdn.jsdelivr.net"})
	for _, want := range []string{
		"sandbox allow-scripts;",
		"connect-src 'none'",
		"form-action 'none'",
		"img-src data: blob: https://cdn.jsdelivr.net;",
		"frame-ancestors 'self'",
	} {
		if !strings.Contains(htmlCSP, want) {
			t.Fatalf("HTML CSP missing %q: %s", want, htmlCSP)
		}
	}
	if strings.Contains(htmlCSP, "https:;") || strings.Contains(htmlCSP, "https: ") {
		t.Fatalf("HTML CSP must not allow wildcard https: img-src exfiltration: %s", htmlCSP)
	}

	pdfCSP := BuildRawCSP("application/pdf", nil)
	if !strings.Contains(pdfCSP, "object-src 'self'") || strings.Contains(pdfCSP, "sandbox") {
		t.Fatalf("unexpected PDF CSP: %s", pdfCSP)
	}

	svgCSP := BuildRawCSP("image/svg+xml", nil)
	if !strings.Contains(svgCSP, "sandbox;") || strings.Contains(svgCSP, "allow-scripts") {
		t.Fatalf("SVG CSP must sandbox without scripts: %s", svgCSP)
	}
}

func TestSafeContentDisposition(t *testing.T) {
	cd := SafeContentDisposition("attachment", "Q1 Report\r\nX-Injected: evil; \"bad\"/path", "application/pdf")
	if strings.ContainsAny(cd, "\r\n") {
		t.Fatalf("CRLF leaked into Content-Disposition: %q", cd)
	}
	if !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, ".pdf") {
		t.Fatalf("unexpected Content-Disposition: %q", cd)
	}
}
