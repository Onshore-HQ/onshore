// Package store opens the database and applies embedded migrations.
package store

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/migrations"
)

// Open connects and pings a pool.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Pending lists migrations not yet applied. A fresh database has all of them.
func Pending(ctx context.Context, url string) ([]string, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, name := range entries {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.schema_migrations WHERE name=$1)`, name).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			pending = append(pending, name)
		}
	}
	return pending, nil
}

var safePassword = regexp.MustCompile(`^[A-Za-z0-9_-]{16,}$`)

// Migrate applies pending migrations, then sets runtime role passwords.
func Migrate(ctx context.Context, url, vaultPassword, controlPassword string) ([]string, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(727001)`); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	var applied []string
	for _, name := range entries {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.schema_migrations WHERE name=$1)`, name).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			tx.Rollback(ctx)
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.schema_migrations(name) VALUES ($1)`, name); err != nil {
			tx.Rollback(ctx)
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		applied = append(applied, name)
	}
	for role, pw := range map[string]string{"rv_vault": vaultPassword, "rv_control": controlPassword} {
		if pw == "" {
			continue
		}
		if !safePassword.MatchString(pw) {
			return nil, fmt.Errorf("password for %s must match %s", role, safePassword)
		}
		if _, err := conn.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s PASSWORD '%s'`, role, pw)); err != nil {
			return nil, err
		}
	}
	return applied, nil
}
