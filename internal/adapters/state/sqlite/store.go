// Package sqlite is a candidate durable metadata adapter. It is not selected by
// a production composition root. It never stores financial payloads or secrets.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	_ "modernc.org/sqlite"
)

var (
	ErrUnavailable        = errors.New("metadata store unavailable")
	ErrCorrupt            = errors.New("metadata store is inconsistent")
	ErrUninitialized      = errors.New("owner metadata has not been initialized")
	ErrAlreadyInitialized = errors.New("owner metadata already initialized")
	ErrInvalidPath        = errors.New("metadata store requires a private regular file")
	ErrSchema             = errors.New("unsupported metadata schema")
	ErrReadOnly           = errors.New("metadata store is read-only")
)

const (
	applicationID     = 0x594e4142 // YNAB; distinguishes this metadata file from unrelated databases.
	schemaVersion     = 1
	maxMetadataBytes  = 65536
	maxAllowedBudgets = 1024
)

type Store struct {
	db       *sql.DB
	readOnly bool
}

var _ ports.AccessGrantRepository = (*Store)(nil)

// Open opens or creates a metadata database, and transactionally applies the
// known schema to an empty file. It never creates an owner or usable quota.
// path is a filesystem path, never an SQLite URI. Its directory must be trusted.
func Open(path string) (*Store, error) { return open(path, false) }

// OpenReadOnly opens an existing database for inspection without migration or
// configuration writes. All write repository methods return ErrReadOnly.
func OpenReadOnly(path string) (*Store, error) { return open(path, true) }

func open(path string, readOnly bool) (*Store, error) {
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrInvalidPath
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalidPath
	}
	if !readOnly {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err == nil {
			if err = f.Close(); err != nil {
				return nil, ErrUnavailable
			}
		} else if !errors.Is(err, os.ErrExist) {
			return nil, ErrUnavailable
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalidPath
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "synchronous(FULL)", "trusted_schema(OFF)"}, "_txlock": {"immediate"}}
	if readOnly {
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Set("mode", "rw")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, readOnly: readOnly}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.prepare(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error                                  { return dbError(context.Background(), s.db.Close()) }
func (s *Store) Connections() ports.ScopedConnectionRepository { return connectionRepository{s} }
func (s *Store) Quotas() ports.QuotaRepository                 { return quotaRepository{s} }

func dbError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Never return SQL, paths, identifiers, metadata JSON or driver messages.
	return ErrUnavailable
}

func (s *Store) write(ctx context.Context, f func(*sql.Tx) error) error {
	if s.readOnly {
		return ErrReadOnly
	}
	tx, err := s.db.BeginTx(ctx, nil) // DSN uses BEGIN IMMEDIATE; serialize before loading state.
	if err != nil {
		return dbError(ctx, err)
	}
	defer tx.Rollback()
	if err = f(tx); err != nil {
		return err
	}
	return dbError(ctx, tx.Commit())
}

func (s *Store) prepare(ctx context.Context) error {
	var app, version int
	if err := s.db.QueryRowContext(ctx, "SELECT application_id,user_version FROM pragma_application_id,pragma_user_version").Scan(&app, &version); err != nil {
		return dbError(ctx, err)
	}
	if app == 0 && version == 0 && !s.readOnly {
		if err := s.write(ctx, func(tx *sql.Tx) error {
			// Recheck under the writer lock: a concurrent opener may have migrated.
			if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
				return dbError(ctx, err)
			}
			if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
				return dbError(ctx, err)
			}
			if app == applicationID && version == schemaVersion {
				return nil
			}
			if app != 0 || version != 0 {
				return ErrSchema
			}
			var tables int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
				return dbError(ctx, err)
			}
			if tables != 0 {
				return ErrSchema
			}
			if _, err := tx.ExecContext(ctx, schema); err != nil {
				return dbError(ctx, err)
			}
			return nil
		}); err != nil {
			return err
		}
	} else if app != applicationID || version != schemaVersion {
		return ErrSchema
	}
	var check string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return ErrCorrupt
	}
	rows, err := s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return dbError(ctx, err)
	}
	defer rows.Close()
	if rows.Next() {
		return ErrCorrupt
	}
	return dbError(ctx, rows.Err())
}

const schema = `
CREATE TABLE owners (
 singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1),
 owner_id TEXT NOT NULL UNIQUE CHECK(length(owner_id) BETWEEN 1 AND 200),
 issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 2048),
 subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 512),
 tenant_key TEXT NOT NULL CHECK(length(tenant_key) BETWEEN 2 AND 514),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 policy_version INTEGER NOT NULL CHECK(policy_version > 0),
 UNIQUE(issuer,subject,tenant_key)
) STRICT;
CREATE TABLE connections (
 connection_id TEXT PRIMARY KEY CHECK(length(connection_id) BETWEEN 1 AND 200),
 owner_id TEXT NOT NULL UNIQUE REFERENCES owners(owner_id),
 state_version INTEGER NOT NULL CHECK(state_version > 0),
 metadata TEXT NOT NULL CHECK(length(metadata) BETWEEN 2 AND 65536),
 UNIQUE(owner_id,connection_id)
) STRICT;
CREATE TABLE access_grants (
 owner_id TEXT PRIMARY KEY REFERENCES owners(owner_id),
 connection_id TEXT NOT NULL,
 notes_permitted INTEGER NOT NULL CHECK(notes_permitted IN (0,1)),
 FOREIGN KEY(owner_id,connection_id) REFERENCES connections(owner_id,connection_id)
) STRICT;
CREATE TABLE allowed_budgets (
 owner_id TEXT NOT NULL REFERENCES access_grants(owner_id),
 budget_id TEXT NOT NULL CHECK(length(budget_id) BETWEEN 1 AND 200),
 PRIMARY KEY(owner_id,budget_id)
) STRICT;
CREATE TABLE quota_windows (
 quota_key TEXT PRIMARY KEY REFERENCES connections(connection_id),
 version INTEGER NOT NULL CHECK(version > 0),
 metadata TEXT NOT NULL CHECK(length(metadata) BETWEEN 2 AND 65536)
) STRICT;
PRAGMA application_id=1498300738;
PRAGMA user_version=1;
`
