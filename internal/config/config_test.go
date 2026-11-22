package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadValidProductionConfig(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{
		"PUBLIC_BASE_URL":          "https://ARTIFACT.CUBUS.SH:443/",
		"DB_BROKER_URL":            "http://db-broker:8080/v1/database",
		"ADMIN_BIND_CIDR":          "172.31.0.0/24",
		"ADMIN_API_TOKEN":          "super-secret-admin-token-1234",
		"BOOTSTRAP_ADMIN_USERNAME": "admin",
		"BOOTSTRAP_ADMIN_PASSWORD": "correct-horse-battery-staple",
	}))
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if cfg.PublicBaseURL != "https://artifact.cubus.sh" || !cfg.PublicIsHTTPS {
		t.Fatalf("unexpected PublicBaseURL=%q PublicIsHTTPS=%v", cfg.PublicBaseURL, cfg.PublicIsHTTPS)
	}
	if cfg.AdminBindCIDR == nil || cfg.AdminBindCIDR.String() != "172.31.0.0/24" {
		t.Fatalf("unexpected AdminBindCIDR=%v", cfg.AdminBindCIDR)
	}

	// Verify secret redaction in structured logs and String().
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "cfg", cfg)
	logged := buf.String() + cfg.String()
	for _, secret := range []string{"super-secret-admin-token-1234", "correct-horse-battery-staple"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("secret %q leaked into logs/String(): %s", secret, logged)
		}
	}
}

func TestLoadRejectsNonLoopbackHTTP(t *testing.T) {
	_, err := Load(envMap(map[string]string{
		"PUBLIC_BASE_URL": "http://artifact.cubus.sh",
		"DATABASE_URL":    "postgres://user:pass@localhost:5432/db",
	}))
	if err == nil {
		t.Fatal("expected error for non-loopback http PUBLIC_BASE_URL")
	}

	// Loopback http must succeed.
	for _, okBase := range []string{"http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"} {
		cfg, err := Load(envMap(map[string]string{
			"PUBLIC_BASE_URL": okBase,
			"DATABASE_URL":    "postgres://user:pass@localhost:5432/db",
		}))
		if err != nil {
			t.Fatalf("expected loopback %q to succeed, got %v", okBase, err)
		}
		if cfg.PublicIsHTTPS {
			t.Fatalf("expected PublicIsHTTPS=false for %q", okBase)
		}
	}
}

func TestLoadRejectsPlaceholdersAndMissingDB(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "missing db url",
			env:  map[string]string{"PUBLIC_BASE_URL": "https://artifact.cubus.sh"},
		},
		{
			name: "placeholder admin token",
			env: map[string]string{
				"PUBLIC_BASE_URL": "https://artifact.cubus.sh",
				"DATABASE_URL":    "postgres://u:p@localhost/db",
				"ADMIN_API_TOKEN": "replace-with-a-random-admin-api-token",
			},
		},
		{
			name: "short admin token",
			env: map[string]string{
				"PUBLIC_BASE_URL": "https://artifact.cubus.sh",
				"DATABASE_URL":    "postgres://u:p@localhost/db",
				"ADMIN_API_TOKEN": "short",
			},
		},
		{
			name: "placeholder bootstrap password",
			env: map[string]string{
				"PUBLIC_BASE_URL":          "https://artifact.cubus.sh",
				"DATABASE_URL":             "postgres://u:p@localhost/db",
				"BOOTSTRAP_ADMIN_PASSWORD": "replace-with-a-strong-admin-password",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(envMap(tc.env)); err == nil {
				t.Fatalf("expected Load error for %s", tc.name)
			}
		})
	}
}

func TestHealthcheckURL(t *testing.T) {
	got, err := HealthcheckURL("")
	if err != nil || got != "http://127.0.0.1:8000/healthz" {
		t.Fatalf("got (%q, %v), want http://127.0.0.1:8000/healthz", got, err)
	}
	got, err = HealthcheckURL("0.0.0.0:9123")
	if err != nil || got != "http://127.0.0.1:9123/healthz" {
		t.Fatalf("got (%q, %v), want http://127.0.0.1:9123/healthz", got, err)
	}
	if _, err := HealthcheckURL("bad-addr"); err == nil {
		t.Fatal("expected error for invalid LISTEN_ADDR")
	}
}
