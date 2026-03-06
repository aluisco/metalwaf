package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrate creates the schema_migrations tracking table and applies any pending
// SQL migration files found in the embedded migrations directory.
func migrate(ctx context.Context, db *sql.DB) error {
	// Ensure the tracking table exists.
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER  PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	// Read which versions have already been applied.
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("querying applied migrations: %w", err)
	}
	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("scanning migration version: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Discover available migration files.
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations dir: %w", err)
	}

	type migration struct {
		version int
		name    string
		content string
	}
	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var version int
		if _, err := fmt.Sscanf(e.Name(), "%d", &version); err != nil {
			continue // skip files that don't start with a number
		}
		data, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("reading migration file %q: %w", e.Name(), err)
		}
		migrations = append(migrations, migration{
			version: version,
			name:    e.Name(),
			content: string(data),
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	// Apply pending migrations inside individual transactions.
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("beginning transaction for migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, m.content); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("applying migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version) VALUES (?)`, m.version,
		); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("recording migration %q: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %q: %w", m.name, err)
		}
	}

	return nil
}
