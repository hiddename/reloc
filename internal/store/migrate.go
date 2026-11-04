package store

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrateLockID int64 = 0x72656c6f63

const createTableSchemaMigrationsSQL = `
create table if not exists schema_migrations (
	version int8 primary key,
	applied_at timestamptz not null default now()
)
`

type migration struct {
	version int64
	name    string
	sql     string
}

func Migrate(ctx context.Context, db *pgxpool.Pool, fsys fs.FS) error {
	if err := migrate(ctx, db, fsys); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

func migrate(ctx context.Context, db *pgxpool.Pool, fsys fs.FS) error {
	ms, err := parseFiles(fsys)
	if err != nil {
		return err
	}

	conn, err := db.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	return withAdvisoryLock(ctx, conn, func() error {
		if _, err := conn.Exec(ctx, createTableSchemaMigrationsSQL); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		appliedVs, err := appliedVersions(ctx, conn)
		if err != nil {
			return err
		}
		pendingMs, err := pendingMigrations(ms, appliedVs)
		if err != nil {
			return err
		}
		for _, m := range pendingMs {
			if err := applyMigration(ctx, conn, m); err != nil {
				return fmt.Errorf("%s: %w", m.name, err)
			}
		}
		return nil
	})
}

func parseFiles(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	ms := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		m, err := parseFile(fsys, e)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	slices.SortFunc(ms, func(a, b migration) int {
		return cmp.Compare(a.version, b.version)
	})
	for i, m := range ms {
		if m.version != int64(i+1) {
			return nil, fmt.Errorf("%s: non-continuous version", m.name)
		}
	}
	return ms, nil
}

func parseFile(fsys fs.FS, f fs.DirEntry) (migration, error) {
	version, err := parseVersion(f.Name())
	if err != nil {
		return migration{}, err
	}
	sql, err := fs.ReadFile(fsys, f.Name())
	if err != nil {
		return migration{}, err
	}
	return migration{
		version: version,
		name:    f.Name(),
		sql:     string(sql),
	}, nil
}

func parseVersion(filename string) (int64, error) {
	versionStr, _, ok := strings.Cut(filename, "_")
	if !ok || strings.ContainsFunc(versionStr, func(r rune) bool { return r < '0' || r > '9' }) {
		return 0, fmt.Errorf("%s: bad version", filename)
	}
	version, err := strconv.ParseInt(versionStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", filename, err)
	}
	return version, nil
}

func withAdvisoryLock(ctx context.Context, conn *pgxpool.Conn, fn func() error) error {
	_, err := conn.Exec(ctx, "select pg_advisory_lock($1)", migrateLockID)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, unlockErr := conn.Exec(unlockCtx, "select pg_advisory_unlock($1)", migrateLockID)
		if unlockErr != nil {
			// unlock failed: closing the conn drops the session lock on the server
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	return fn()
}

func appliedVersions(ctx context.Context, conn *pgxpool.Conn) ([]int64, error) {
	rows, err := conn.Query(ctx, "select version from schema_migrations order by version")
	if err != nil {
		return nil, fmt.Errorf("applied versions: %w", err)
	}
	res, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, fmt.Errorf("applied versions: %w", err)
	}
	return res, nil
}

func pendingMigrations(ms []migration, applied []int64) ([]migration, error) {
	for i, v := range applied {
		if v != int64(i+1) {
			return nil, fmt.Errorf("pending migrations: applied versions have a gap at %d", i+1)
		}
	}
	if len(applied) > len(ms) {
		return nil, fmt.Errorf(
			"pending migrations: database ahead of files: %d applied vs %d files",
			len(applied), len(ms),
		)
	}
	return ms[len(applied):], nil
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, m migration) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "insert into schema_migrations (version) values ($1)", m.version)
		return err
	})
}
