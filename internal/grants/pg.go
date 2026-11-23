package grants

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"idp-mcp-bridge/migrations"
)

// DefaultTimeout bounds one statement or transaction that does not wait for a third party; a slow database refuses the call
// instead of holding it. A refresh holds its row lock while the authorization server answers (RefreshTimeout of the caller).
const DefaultTimeout = 5 * time.Second

// PG is the PostgreSQL store. Every replica has its own pool; the rows are shared.
type PG struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

// Open connects and checks that the schema is at the version this binary needs.
func Open(ctx context.Context, url string) (*PG, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("the database URL is not valid")
	}
	guardDial(&cfg.ConnConfig.Config)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &PG{pool: pool, timeout: DefaultTimeout}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The service is the least-privilege role and nothing more (ADR-0001 D25): it is the one component whose process holds every
	// member's third-party tokens, and it must not be able to create, alter or drop a table. Refused: a superuser, a role that
	// bypasses row security, one that may create objects in the schema, one that owns a table of the schema.
	var super, bypass, create, owns bool
	if err := pool.QueryRow(c, `SELECT r.rolsuper, r.rolbypassrls, has_schema_privilege(current_user, current_schema(), 'CREATE'),
EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() AND tableowner = current_user)
FROM pg_roles r WHERE r.rolname = current_user`).Scan(&super, &bypass, &create, &owns); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unreachable or role unknown: %w", err)
	}
	if super || bypass || create || owns {
		pool.Close()
		return nil, errors.New("refusing to run as a role that can change the schema (superuser, BYPASSRLS, CREATE on the schema, or an owner of tables): connect as a member of idp_bridge_app, made by `idp-mcp-bridge ensure-login`")
	}
	var version int
	if err := pool.QueryRow(c, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		pool.Close()
		return nil, fmt.Errorf("schema not migrated (run idp-mcp-bridge migrate as the schema owner): %w", err)
	}
	if want := latest(); version != want {
		pool.Close()
		return nil, fmt.Errorf("schema at version %d, binary needs %d (run idp-mcp-bridge migrate as the schema owner first; the server never migrates)", version, want)
	}
	return s, nil
}

// Close releases the pool.
func (s *PG) Close() { s.pool.Close() }

// Ping is what /readyz asks.
func (s *PG) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.pool.Ping(ctx)
}

type migration struct {
	version int
	name    string
	sql     string
}

func load() []migration {
	var out []migration
	entries, _ := fs.ReadDir(migrations.FS, ".")
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(n, "_", 2)[0])
		if err != nil {
			continue
		}
		b, _ := fs.ReadFile(migrations.FS, n)
		out = append(out, migration{v, n, string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

func latest() int {
	m := load()
	if len(m) == 0 {
		return 0
	}
	return m[len(m)-1].version
}

// Migrate applies the pending migrations, one transaction each, serialized by an advisory lock so that replicas that start
// together cannot interleave (the procedure of idp-web, idp-mcp and idp-host). The role needs the right to create tables.
func Migrate(ctx context.Context, url string) (applied []string, err error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, errors.New("the database is not reachable with this URL")
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(72590)`); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(72590)`)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idp_bridge_app') THEN GRANT SELECT ON schema_migrations TO idp_bridge_app; END IF; END $$`); err != nil {
		return nil, err
	}
	var current int
	if err := conn.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return nil, err
	}
	for _, m := range load() {
		if m.version <= current {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("%s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if _, err := tx.Exec(ctx, `GRANT SELECT ON schema_migrations TO idp_bridge_app`); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, err
		}
		applied = append(applied, m.name)
	}
	return applied, nil
}

func (s *PG) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}

const grantCols = `tenant, member, connection, sealed_access, sealed_refresh, access_expires, issuer, scope, needed_scope, reauth_reason, created_at, refreshed_at, reviewer, authorized_by, authorizer_left`

type scanner interface{ Scan(...any) error }

func scanGrant(r scanner) (Grant, error) {
	var g Grant
	var exp *time.Time
	err := r.Scan(&g.Tenant, &g.Member, &g.Connection, &g.SealedAccess, &g.SealedRefresh, &exp, &g.Issuer, &g.Scope, &g.NeededScope, &g.ReauthReason, &g.CreatedAt, &g.RefreshedAt, &g.Reviewer, &g.AuthorizedBy, &g.AuthorizerLeft)
	if exp != nil {
		g.AccessExpires = *exp
	}
	return g, err
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nullBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (s *PG) Get(ctx context.Context, k Key) (Grant, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	g, err := scanGrant(s.pool.QueryRow(ctx, `SELECT `+grantCols+` FROM grants WHERE tenant=$1 AND member=$2 AND connection=$3 AND reviewer=$4`, k.Tenant, k.Member, k.Connection, k.Reviewer))
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	return g, err
}

const upsert = `INSERT INTO grants (` + grantCols + `) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (tenant, member, connection, reviewer) DO UPDATE SET sealed_access=EXCLUDED.sealed_access, sealed_refresh=EXCLUDED.sealed_refresh,
 access_expires=EXCLUDED.access_expires, issuer=EXCLUDED.issuer, scope=EXCLUDED.scope, needed_scope=EXCLUDED.needed_scope, reauth_reason=EXCLUDED.reauth_reason,
 created_at=EXCLUDED.created_at, refreshed_at=EXCLUDED.refreshed_at, authorized_by=EXCLUDED.authorized_by, authorizer_left=EXCLUDED.authorizer_left`

func putArgs(g Grant) []any {
	return []any{g.Tenant, g.Member, g.Connection, g.SealedAccess, nullBytes(g.SealedRefresh), nullTime(g.AccessExpires), g.Issuer, g.Scope, g.NeededScope, g.ReauthReason, g.CreatedAt, g.RefreshedAt, g.Reviewer, g.AuthorizedBy, g.AuthorizerLeft}
}

func (s *PG) Put(ctx context.Context, g Grant) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.pool.Exec(ctx, upsert, putArgs(g)...)
	return err
}

func (s *PG) Delete(ctx context.Context, k Key) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.pool.Exec(ctx, `DELETE FROM grants WHERE tenant=$1 AND member=$2 AND connection=$3 AND reviewer=$4`, k.Tenant, k.Member, k.Connection, k.Reviewer)
	return err
}

func (s *PG) DeleteMember(ctx context.Context, tenant, member string) (int, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	t, err := s.pool.Exec(ctx, `DELETE FROM grants WHERE tenant=$1 AND member=$2 AND NOT reviewer`, tenant, member)
	return int(t.RowsAffected()), err
}

func (s *PG) DeleteConnection(ctx context.Context, connection string) (int, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	t, err := s.pool.Exec(ctx, `DELETE FROM grants WHERE connection=$1`, connection)
	return int(t.RowsAffected()), err
}

func (s *PG) ForMember(ctx context.Context, tenant, member string) ([]Grant, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+grantCols+` FROM grants WHERE tenant=$1 AND member=$2 AND NOT reviewer ORDER BY connection`, tenant, member)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Locked takes the row with SELECT ... FOR UPDATE in a transaction of its own and holds it while fn runs: a second caller, on
// this replica or another, waits at the SELECT and then reads what the first left. The transaction is not bounded by the
// store's timeout, since fn may wait for an authorization server; the caller's context bounds it.
func (s *PG) Locked(ctx context.Context, k Key, fn func(Grant) (Grant, Action, error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	g, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantCols+` FROM grants WHERE tenant=$1 AND member=$2 AND connection=$3 AND reviewer=$4 FOR UPDATE`, k.Tenant, k.Member, k.Connection, k.Reviewer))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	ng, act, err := fn(g)
	if err != nil {
		return err
	}
	switch act {
	case Update:
		ng.Key = k
		if _, err := tx.Exec(ctx, upsert, putArgs(ng)...); err != nil {
			return err
		}
	case Delete:
		if _, err := tx.Exec(ctx, `DELETE FROM grants WHERE tenant=$1 AND member=$2 AND connection=$3 AND reviewer=$4`, k.Tenant, k.Member, k.Connection, k.Reviewer); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PG) Reseal(ctx context.Context, fn func(Grant) (Grant, bool, error)) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT tenant, member, connection, reviewer FROM grants ORDER BY tenant, member, connection, reviewer`)
	if err != nil {
		return 0, err
	}
	var keys []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.Tenant, &k.Member, &k.Connection, &k.Reviewer); err != nil {
			rows.Close()
			return 0, err
		}
		keys = append(keys, k)
	}
	rows.Close()
	n := 0
	for _, k := range keys {
		err := s.Locked(ctx, k, func(g Grant) (Grant, Action, error) {
			ng, changed, err := fn(g)
			if err != nil || !changed {
				return g, Keep, err
			}
			n++
			return ng, Update, nil
		})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return n, err
		}
	}
	return n, nil
}

func (s *PG) PutState(ctx context.Context, st State) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.pool.Exec(ctx, `INSERT INTO pending_states (state_hash, tenant, member, connection, sealed_verifier, issuer, redirect_uri, scope, client_id, resource, expires_at, reviewer)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, st.Hash, st.Tenant, st.Member, st.Connection, st.SealedVerifier, st.Issuer, st.RedirectURI, st.Scope, st.ClientID, st.Resource, st.Expires, st.Reviewer)
	return err
}

func (s *PG) TakeState(ctx context.Context, hash []byte, tenant, member string) (State, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	var st State
	err := s.pool.QueryRow(ctx, `DELETE FROM pending_states WHERE state_hash=$1 AND tenant=$2 AND member=$3
RETURNING state_hash, tenant, member, connection, sealed_verifier, issuer, redirect_uri, scope, client_id, resource, expires_at, reviewer`, hash, tenant, member).
		Scan(&st.Hash, &st.Tenant, &st.Member, &st.Connection, &st.SealedVerifier, &st.Issuer, &st.RedirectURI, &st.Scope, &st.ClientID, &st.Resource, &st.Expires, &st.Reviewer)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrNotFound
	}
	return st, err
}

func (s *PG) SweepStates(ctx context.Context, cutoff time.Time) (int, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	t, err := s.pool.Exec(ctx, `DELETE FROM pending_states WHERE expires_at < $1`, cutoff)
	return int(t.RowsAffected()), err
}

func (s *PG) GetRegistration(ctx context.Context, connection, issuer, redirectURI string) (Registration, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	r := Registration{Connection: connection, Issuer: issuer, RedirectURI: redirectURI}
	err := s.pool.QueryRow(ctx, `SELECT client_id, sealed_secret, auth_method FROM client_registrations WHERE connection=$1 AND issuer=$2 AND redirect_uri=$3`,
		connection, issuer, redirectURI).Scan(&r.ClientID, &r.SealedSecret, &r.AuthMethod)
	if errors.Is(err, pgx.ErrNoRows) {
		return Registration{}, ErrNotFound
	}
	return r, err
}

func (s *PG) PutRegistration(ctx context.Context, r Registration) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.pool.Exec(ctx, `INSERT INTO client_registrations (connection, issuer, redirect_uri, client_id, sealed_secret, auth_method) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (connection, issuer, redirect_uri) DO UPDATE SET client_id=EXCLUDED.client_id, sealed_secret=EXCLUDED.sealed_secret, auth_method=EXCLUDED.auth_method`,
		r.Connection, r.Issuer, r.RedirectURI, r.ClientID, nullBytes(r.SealedSecret), r.AuthMethod)
	return err
}

func (s *PG) Registrations(ctx context.Context) ([]Registration, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT connection, issuer, redirect_uri, client_id, sealed_secret, auth_method FROM client_registrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Registration
	for rows.Next() {
		var r Registration
		if err := rows.Scan(&r.Connection, &r.Issuer, &r.RedirectURI, &r.ClientID, &r.SealedSecret, &r.AuthMethod); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var _ Store = (*PG)(nil)

// EnsureLogin creates or updates a login role that is a member of idp_bridge_app (owner connection): the role the service runs
// as. Run once by the operator (`idp-mcp-bridge ensure-login USER`), after migrate has made idp_bridge_app.
func EnsureLogin(ctx context.Context, ownerURL, user, password string) error {
	if !validIdent(user) {
		return errors.New("invalid role name: lower case letters, digits and _, at most 63")
	}
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return errors.New("the database is not reachable with this URL")
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, user).Scan(&exists); err != nil {
		return err
	}
	verb := "CREATE"
	if exists {
		verb = "ALTER"
	}
	// role names and passwords cannot be bind parameters; the name is restricted to [a-z0-9_] and the password is a quoted literal
	if _, err := conn.Exec(ctx, fmt.Sprintf(`%s ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %s`, verb, user, "'"+strings.ReplaceAll(password, "'", "''")+"'")); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, fmt.Sprintf(`GRANT idp_bridge_app TO %s`, user))
	return err
}

func validIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

func (s *PG) DeleteMemberStates(ctx context.Context, tenant, member string) (int, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	t, err := s.pool.Exec(ctx, `DELETE FROM pending_states WHERE tenant=$1 AND member=$2`, tenant, member)
	return int(t.RowsAffected()), err
}

func (s *PG) Members(ctx context.Context) ([][2]string, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT tenant, member FROM grants WHERE NOT reviewer ORDER BY tenant, member`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var p [2]string
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PG) Authorizers(ctx context.Context) ([]string, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT authorized_by FROM grants WHERE reviewer AND NOT authorizer_left AND authorized_by <> '' ORDER BY authorized_by`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PG) MarkAuthorizerLeft(ctx context.Context, authorizedBy string) (int, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	t, err := s.pool.Exec(ctx, `UPDATE grants SET authorizer_left = true WHERE reviewer AND authorized_by = $1`, authorizedBy)
	return int(t.RowsAffected()), err
}

func (s *PG) PutUnconfirmed(ctx context.Context, k Key, at time.Time) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.pool.Exec(ctx, `INSERT INTO unconfirmed_revocations (tenant, member, connection, at) VALUES ($1,$2,$3,$4)
ON CONFLICT (tenant, member, connection) DO UPDATE SET at = EXCLUDED.at`, k.Tenant, k.Member, k.Connection, at)
	return err
}

func (s *PG) ClearUnconfirmed(ctx context.Context, k Key) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.pool.Exec(ctx, `DELETE FROM unconfirmed_revocations WHERE tenant=$1 AND member=$2 AND connection=$3`, k.Tenant, k.Member, k.Connection)
	return err
}

func (s *PG) Unconfirmed(ctx context.Context, tenant, member string) ([]string, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT connection FROM unconfirmed_revocations WHERE tenant=$1 AND member=$2 ORDER BY connection`, tenant, member)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TryLock takes a session-level advisory lock on a connection of its own, which it keeps until release: the lock is the
// database's, so it holds across replicas, and it goes if the replica dies (the connection closes).
func (s *PG) TryLock(ctx context.Context, id int64) (func(), bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, id).Scan(&got); err != nil || !got {
		conn.Release()
		return nil, false, err
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, id)
		conn.Release()
	}, true, nil
}
