package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"cubus.sh/artifact/internal/config"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var usernamePattern = regexp.MustCompile(`^[a-z0-9._-]{3,64}$`)

type migration struct {
	version int
	file    string
}

var allMigrations = []migration{
	{version: 1, file: "migrations/001_init.sql"},
	{version: 2, file: "migrations/002_hardening.sql"},
}

// Migrate applies embedded SQL migrations inside transaction-scoped advisory
// locks so concurrent restarts cannot race and no session lock can leak.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('artifact_migrations', 0))`); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range allMigrations {
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}
		if applied {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile(m.file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m.file, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", m.version, m.file, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

// BootstrapAdmin ensures at least one admin account exists on first boot.
// If any admin already exists, it skips cleanly even when BOOTSTRAP_ADMIN_* are unset.
func BootstrapAdmin(ctx context.Context, pool *pgxpool.Pool, username, password string, hashPassword func(context.Context, string) (string, error)) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin bootstrap tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('artifact_bootstrap_admin', 0))`); err != nil {
		return false, fmt.Errorf("acquire bootstrap lock: %w", err)
	}

	var hasAdmin bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`).Scan(&hasAdmin); err != nil {
		return false, fmt.Errorf("check existing admin: %w", err)
	}
	if hasAdmin {
		return false, tx.Commit(ctx)
	}

	normUser, err := NormalizeUsername(username)
	if err != nil {
		return false, fmt.Errorf("no admin exists yet; valid BOOTSTRAP_ADMIN_USERNAME is required: %w", err)
	}
	if len(password) < 12 || len(password) > 128 || config.IsPlaceholder(password) {
		return false, errors.New("no admin exists yet; BOOTSTRAP_ADMIN_PASSWORD must be 12..128 bytes and not a placeholder")
	}

	hash, err := hashPassword(ctx, password)
	if err != nil {
		return false, fmt.Errorf("hash bootstrap admin password: %w", err)
	}

	if _, err := tx.Exec(
		ctx,
		`INSERT INTO users (username, password_hash, role, status) VALUES ($1, $2, 'admin', 'active')`,
		normUser,
		hash,
	); err != nil {
		return false, fmt.Errorf("insert bootstrap admin: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit bootstrap admin: %w", err)
	}
	return true, nil
}

func NormalizeUsername(raw string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(raw))
	if !usernamePattern.MatchString(u) {
		return "", fmt.Errorf("invalid username %q (must match ^[a-z0-9._-]{3,64}$)", raw)
	}
	return u, nil
}
