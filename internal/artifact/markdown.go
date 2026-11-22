package artifact

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

type MarkdownRenderer struct {
	md     goldmark.Markdown
	policy *bluemonday.Policy
}

func NewMarkdownRenderer() *MarkdownRenderer {
	policy := bluemonday.UGCPolicy()
	policy.RequireNoReferrerOnLinks(true)
	policy.AddTargetBlankToFullyQualifiedLinks(true)
	return &MarkdownRenderer{
		md: goldmark.New(
			goldmark.WithExtensions(extension.GFM),
		),
		policy: policy,
	}
}

// Render converts Markdown into sanitized HTML safe for embedding inside /v/{id}.
// Raw HTML in Markdown is omitted by goldmark, and output is additionally scrubbed
// with bluemonday.UGCPolicy to neutralize URL/entity bypasses (e.g., CVE-2026-5160).
func (r *MarkdownRenderer) Render(src []byte) (template.HTML, error) {
	var raw bytes.Buffer
	if err := r.md.Convert(src, &raw); err != nil {
		return "", fmt.Errorf("render markdown: %w", err)
	}
	sanitized := r.policy.SanitizeBytes(raw.Bytes())
	return template.HTML(sanitized), nil
}
