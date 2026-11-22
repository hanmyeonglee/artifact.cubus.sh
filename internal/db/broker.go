package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"cubus.sh/artifact/internal/config"
)

const (
	poolMaxConns       = 10 // Headroom below db-broker's ROLE_CONNECTION_LIMIT=15
	poolMinConns       = 1
	poolMaxIdleTime    = 5 * time.Minute
	brokerHTTPTimeout  = 10 * time.Second
	brokerMaxRespBytes = 64 << 10
	brokerMaxAttempts  = 5
)

type brokerResponse struct {
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	URL      string `json:"url"`
}

// ResolveDatabaseURL follows the cubus.sh db-broker client contract:
// DB_BROKER_URL takes precedence when set; DATABASE_URL is used for standalone dev.
func ResolveDatabaseURL(ctx context.Context, cfg config.Config, client *http.Client) (string, error) {
	if cfg.DBBrokerURL == "" {
		if cfg.DatabaseURL == "" {
			return "", errors.New("set DB_BROKER_URL or DATABASE_URL")
		}
		return cfg.DatabaseURL, nil
	}
	return fetchFromBroker(ctx, cfg.DBBrokerURL, client, time.Sleep)
}

func fetchFromBroker(ctx context.Context, brokerURL string, client *http.Client, sleepFn func(time.Duration)) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: brokerHTTPTimeout}
	}
	if sleepFn == nil {
		sleepFn = time.Sleep
	}

	var lastErr error
	for attempt := range brokerMaxAttempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerURL, strings.NewReader("{}"))
		if err != nil {
			return "", fmt.Errorf("build db-broker request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("db-broker request failed: %w", err)
			if ctx.Err() != nil || attempt == brokerMaxAttempts-1 {
				break
			}
			sleepWithJitter(ctx, sleepFn, backoffDuration(attempt, 0))
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, brokerMaxRespBytes))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && readErr == nil {
			var parsed brokerResponse
			if err := json.Unmarshal(body, &parsed); err != nil {
				return "", fmt.Errorf("decode db-broker response: %w", err)
			}
			if parsed.URL == "" {
				return "", errors.New("db-broker response missing url")
			}
			return parsed.URL, nil
		}

		// Fail fast on non-retryable client/policy errors.
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusRequestEntityTooLarge:
			return "", fmt.Errorf("db-broker rejected request with status %d", resp.StatusCode)
		}

		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		lastErr = fmt.Errorf("db-broker returned status %d", resp.StatusCode)
		if ctx.Err() != nil || attempt == brokerMaxAttempts-1 {
			break
		}
		sleepWithJitter(ctx, sleepFn, backoffDuration(attempt, retryAfter))
	}
	return "", lastErr
}

func parseRetryAfter(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > 10 {
		secs = 10
	}
	return time.Duration(secs) * time.Second
}

func backoffDuration(attempt int, retryAfter time.Duration) time.Duration {
	base := time.Duration(500<<attempt) * time.Millisecond
	if retryAfter > base {
		base = retryAfter
	}
	jitter := time.Duration(rand.IntN(250)) * time.Millisecond
	return base + jitter
}

func sleepWithJitter(ctx context.Context, sleepFn func(time.Duration), d time.Duration) {
	if ctx.Err() != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		sleepFn(d)
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func OpenPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("failed to parse postgres DSN")
	}
	poolCfg.MaxConns = poolMaxConns
	poolCfg.MinConns = poolMinConns
	poolCfg.MaxConnIdleTime = poolMaxIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, errors.New("failed to create postgres connection pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}
