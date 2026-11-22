package db

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"cubus.sh/artifact/internal/config"
)

func TestResolveDatabaseURLPrecedence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"database":"svc_artifact","url":"postgres://svc_artifact:secret@postgres:5432/svc_artifact?sslmode=disable"}`))
	}))
	defer srv.Close()

	// DB_BROKER_URL takes precedence over DATABASE_URL.
	got, err := ResolveDatabaseURL(context.Background(), config.Config{
		DBBrokerURL: srv.URL,
		DatabaseURL: "postgres://local:local@127.0.0.1:5432/local",
	}, srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "postgres://svc_artifact:secret@postgres:5432/svc_artifact?sslmode=disable" {
		t.Fatalf("unexpected broker DSN: %q", got)
	}

	// Standalone fallback when DB_BROKER_URL is unset.
	got, err = ResolveDatabaseURL(context.Background(), config.Config{
		DatabaseURL: "postgres://local:local@127.0.0.1:5432/local",
	}, nil)
	if err != nil || got != "postgres://local:local@127.0.0.1:5432/local" {
		t.Fatalf("unexpected standalone DSN (%q, %v)", got, err)
	}
}

func TestFetchFromBrokerRetries503AndFailsFastOn403(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"url":"postgres://svc_artifact:pw@postgres:5432/svc_artifact?sslmode=disable"}`))
	}))
	defer srv.Close()

	var sleeps int
	got, err := fetchFromBroker(context.Background(), srv.URL, srv.Client(), func(time.Duration) {
		sleeps++
	})
	if err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if got == "" || attempts.Load() != 3 || sleeps != 2 {
		t.Fatalf("expected 3 attempts and 2 sleeps, got attempts=%d sleeps=%d", attempts.Load(), sleeps)
	}

	// Non-retryable 403 must fail fast on attempt 1.
	var forbiddenCalls atomic.Int32
	srv403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forbiddenCalls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv403.Close()

	if _, err := fetchFromBroker(context.Background(), srv403.URL, srv403.Client(), func(time.Duration) {
		t.Fatal("must not sleep/retry on 403")
	}); err == nil {
		t.Fatal("expected error on 403")
	}
	if forbiddenCalls.Load() != 1 {
		t.Fatalf("expected 1 attempt on 403, got %d", forbiddenCalls.Load())
	}
}

func TestNormalizeUsername(t *testing.T) {
	if got, err := NormalizeUsername("  Alice_01-dev.io "); err != nil || got != "alice_01-dev.io" {
		t.Fatalf("got (%q, %v)", got, err)
	}
	for _, bad := range []string{"ab", "bad user", "admin@example.com", "../root"} {
		if _, err := NormalizeUsername(bad); err == nil {
			t.Fatalf("expected error for invalid username %q", bad)
		}
	}
}
