package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BlobStore abstracts binary payload storage so the backend can later swap
// from PostgreSQL BYTEA/TOAST to S3/R2 without touching callers.
type BlobStore interface {
	Put(ctx context.Context, artifactID string, data []byte) error
	Get(ctx context.Context, artifactID string) ([]byte, error)
	Delete(ctx context.Context, artifactID string) error
}

type pgExecQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type PostgresBlobStore struct {
	pool *pgxpool.Pool
}

func NewPostgresBlobStore(pool *pgxpool.Pool) *PostgresBlobStore {
	return &PostgresBlobStore{pool: pool}
}

func (b *PostgresBlobStore) Put(ctx context.Context, artifactID string, data []byte) error {
	return putBlobPG(ctx, b.pool, artifactID, data)
}

func (b *PostgresBlobStore) Get(ctx context.Context, artifactID string) ([]byte, error) {
	var data []byte
	err := b.pool.QueryRow(ctx, `SELECT data FROM artifact_blobs WHERE artifact_id = $1`, artifactID).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return data, err
}

func (b *PostgresBlobStore) Delete(ctx context.Context, artifactID string) error {
	_, err := b.pool.Exec(ctx, `DELETE FROM artifact_blobs WHERE artifact_id = $1`, artifactID)
	return err
}

func putBlobPG(ctx context.Context, q pgExecQuerier, artifactID string, data []byte) error {
	_, err := q.Exec(ctx, `
		INSERT INTO artifact_blobs (artifact_id, data)
		VALUES ($1, $2)
		ON CONFLICT (artifact_id) DO UPDATE SET data = EXCLUDED.data
	`, artifactID, data)
	return err
}
