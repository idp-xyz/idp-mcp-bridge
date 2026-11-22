package grants_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"idp-mcp-bridge/internal/grants"
	"idp-mcp-bridge/internal/grants/pgtest"
)

// stores are the two implementations of the contract.
func stores(t *testing.T) map[string]func() (grants.Store, func() grants.Store) {
	m := map[string]func() (grants.Store, func() grants.Store){
		"memory": func() (grants.Store, func() grants.Store) {
			s := grants.NewMemory()
			return s, func() grants.Store { return s }
		},
	}
	if pgtest.Enabled() {
		m["postgres"] = func() (grants.Store, func() grants.Store) {
			_, url := pgtest.Scratch(t)
			open := func() grants.Store {
				s, err := grants.Open(context.Background(), url)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Close)
				return s
			}
			return open(), open
		}
	}
	return m
}

var ctx = context.Background()

func grant(tenant, member, conn string) grants.Grant {
	return grants.Grant{Key: grants.Key{Tenant: tenant, Member: member, Connection: conn}, SealedAccess: []byte("sealed-a"), SealedRefresh: []byte("sealed-r"),
		AccessExpires: time.Now().Add(time.Hour).Truncate(time.Microsecond), Issuer: "https://as.example.com", Scope: "read", CreatedAt: time.Now().Truncate(time.Microsecond), RefreshedAt: time.Now().Truncate(time.Microsecond)}
}

func TestEveryStoreKeepsGrantsPerTenantMemberAndConnection(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s, _ := mk()
			g := grant("acme", "bob", "notes")
			if _, err := s.Get(ctx, g.Key); !errors.Is(err, grants.ErrNotFound) {
				t.Fatal(err)
			}
			if err := s.Put(ctx, g); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(ctx, g.Key)
			if err != nil || string(got.SealedAccess) != "sealed-a" || string(got.SealedRefresh) != "sealed-r" || got.Scope != "read" || got.Issuer != g.Issuer || !got.AccessExpires.Equal(g.AccessExpires) {
				t.Fatalf("%+v %v", got, err)
			}
			// a grant without a refresh token or an expiry
			g2 := grant("acme", "bob", "crm")
			g2.SealedRefresh, g2.AccessExpires = nil, time.Time{}
			_ = s.Put(ctx, g2)
			if got, _ := s.Get(ctx, g2.Key); len(got.SealedRefresh) != 0 || !got.AccessExpires.IsZero() {
				t.Fatalf("%+v", got)
			}
			// the key is all three: nothing is found for a neighbour
			for _, k := range []grants.Key{{Tenant: "other", Member: "bob", Connection: "notes"}, {Tenant: "acme", Member: "alice", Connection: "notes"}, {Tenant: "acme", Member: "bob", Connection: "x"}} {
				if _, err := s.Get(ctx, k); !errors.Is(err, grants.ErrNotFound) {
					t.Errorf("%v: %v", k, err)
				}
			}
			// an upsert replaces
			g.Scope, g.NeededScope, g.ReauthReason = "read write", "read write", grants.ReasonInsufficientScope
			_ = s.Put(ctx, g)
			if got, _ := s.Get(ctx, g.Key); got.Scope != "read write" || got.ReauthReason != "insufficient_scope" || got.NeededScope != "read write" {
				t.Fatalf("%+v", got)
			}
			_ = s.Put(ctx, grant("acme", "carol", "notes"))
			_ = s.Put(ctx, grant("other", "bob", "notes"))
			list, _ := s.ForMember(ctx, "acme", "bob")
			if len(list) != 2 || list[0].Connection != "crm" || list[1].Connection != "notes" {
				t.Fatalf("%+v", list)
			}
			if n, err := s.DeleteMember(ctx, "acme", "bob"); err != nil || n != 2 {
				t.Fatalf("%d %v", n, err)
			}
			if n, _ := s.DeleteConnection(ctx, "notes"); n != 2 { // carol's and the other tenant's bob
				t.Fatalf("%d", n)
			}
			if err := s.Delete(ctx, g.Key); err != nil {
				t.Fatal("deleting what is not there is not an error")
			}
		})
	}
}

// Locked is what keeps a refresh token from being spent twice: two callers, two replicas, one at a time.
func TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s1, open := mk()
			s2 := open()
			g := grant("acme", "bob", "notes")
			g.Scope = "0"
			_ = s1.Put(ctx, g)
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s := s1
					if i%2 == 1 {
						s = s2
					}
					err := s.Locked(ctx, g.Key, func(cur grants.Grant) (grants.Grant, grants.Action, error) {
						n, _ := strconv.Atoi(cur.Scope)
						time.Sleep(2 * time.Millisecond) // a read-modify-write that would lose updates without the lock
						cur.Scope = strconv.Itoa(n + 1)
						return cur, grants.Update, nil
					})
					if err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			if got, _ := s1.Get(ctx, g.Key); got.Scope != "20" {
				t.Fatalf("%s updates survived of 20: the lock does not serialize", got.Scope)
			}
			boom := errors.New("boom")
			err := s1.Locked(ctx, g.Key, func(cur grants.Grant) (grants.Grant, grants.Action, error) {
				cur.Scope = "changed"
				return cur, grants.Update, boom
			})
			if !errors.Is(err, boom) {
				t.Fatal(err)
			}
			if got, _ := s1.Get(ctx, g.Key); got.Scope != "20" {
				t.Fatal("an error of the function changed the row")
			}
			if err := s1.Locked(ctx, g.Key, func(cur grants.Grant) (grants.Grant, grants.Action, error) { return cur, grants.Keep, nil }); err != nil {
				t.Fatal(err)
			}
			if err := s1.Locked(ctx, g.Key, func(cur grants.Grant) (grants.Grant, grants.Action, error) { return cur, grants.Delete, nil }); err != nil {
				t.Fatal(err)
			}
			if err := s1.Locked(ctx, g.Key, func(cur grants.Grant) (grants.Grant, grants.Action, error) { return cur, grants.Keep, nil }); !errors.Is(err, grants.ErrNotFound) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestPendingStatesAreTakenOnceOnlyByTheirOwnerAndSweptWhenTheyExpire(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s, _ := mk()
			st := grants.State{Hash: make([]byte, 32), Key: grants.Key{Tenant: "acme", Member: "bob", Connection: "notes"}, SealedVerifier: []byte("v"), Issuer: "i",
				RedirectURI: "r", Scope: "read", ClientID: "c", Resource: "res", Expires: time.Now().Add(time.Minute)}
			st.Hash[0] = 1
			if err := s.PutState(ctx, st); err != nil {
				t.Fatal(err)
			}
			for _, who := range [][2]string{{"acme", "alice"}, {"other", "bob"}} {
				if _, err := s.TakeState(ctx, st.Hash, who[0], who[1]); !errors.Is(err, grants.ErrNotFound) {
					t.Fatalf("%v: %v", who, err)
				}
			}
			got, err := s.TakeState(ctx, st.Hash, "acme", "bob")
			if err != nil || got.Connection != "notes" || string(got.SealedVerifier) != "v" || got.Resource != "res" || got.ClientID != "c" {
				t.Fatalf("%+v %v", got, err)
			}
			if _, err := s.TakeState(ctx, st.Hash, "acme", "bob"); !errors.Is(err, grants.ErrNotFound) {
				t.Fatal("a state was taken twice")
			}
			// concurrent takers: exactly one gets it
			st.Hash[1] = 2
			_ = s.PutState(ctx, st)
			var wg sync.WaitGroup
			var mu sync.Mutex
			won := 0
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := s.TakeState(ctx, st.Hash, "acme", "bob"); err == nil {
						mu.Lock()
						won++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if won != 1 {
				t.Fatalf("%d takers got the same state", won)
			}
			st.Hash[2] = 3
			st.Expires = time.Now().Add(-time.Hour)
			_ = s.PutState(ctx, st)
			if n, err := s.SweepStates(ctx, time.Now()); err != nil || n != 1 {
				t.Fatalf("%d %v", n, err)
			}
		})
	}
}

func TestRegistrationsAreKeptPerConnectionIssuerAndRedirect(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s, _ := mk()
			if _, err := s.GetRegistration(ctx, "c", "i", "r"); !errors.Is(err, grants.ErrNotFound) {
				t.Fatal(err)
			}
			r := grants.Registration{Connection: "c", Issuer: "i", RedirectURI: "r", ClientID: "id", SealedSecret: []byte("s"), AuthMethod: "client_secret_post"}
			_ = s.PutRegistration(ctx, r)
			r.ClientID = "id2"
			_ = s.PutRegistration(ctx, r)
			if got, err := s.GetRegistration(ctx, "c", "i", "r"); err != nil || got.ClientID != "id2" || string(got.SealedSecret) != "s" {
				t.Fatalf("%+v %v", got, err)
			}
			if _, err := s.GetRegistration(ctx, "c", "i2", "r"); !errors.Is(err, grants.ErrNotFound) {
				t.Fatal("another issuer's registration was found")
			}
			if all, _ := s.Registrations(ctx); len(all) != 1 {
				t.Fatalf("%v", all)
			}
		})
	}
}

func TestMigrationsAreAppliedOnceByTheOwnerUnderALock(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	url := pgtest.Raw(t)
	// replicas of the Job that start together on a fresh database: the advisory lock makes them take turns, so the migration is
	// applied once in all and nobody fails on a table another has just made
	var wg sync.WaitGroup
	counts := make([]int, 4)
	for i := range counts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := grants.Migrate(ctx, url)
			if err != nil {
				t.Error(err)
			}
			counts[i] = len(a)
		}()
	}
	wg.Wait()
	if total := counts[0] + counts[1] + counts[2] + counts[3]; total != 2 { // the two migrations, once each
		t.Fatalf("the migration was applied %d times in all: %v", total, counts)
	}
}

// ADR-0001 D25: the server is the least-privilege role. It reads and writes the three tables and can do nothing to the schema.
func TestTheServiceRoleCanOnlyReadAndWriteTheThreeTablesAndCannotChangeTheSchema(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	owner, svc := pgtest.Scratch(t)
	s, err := grants.Open(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Put(ctx, grant("acme", "bob", "notes")); err != nil {
		t.Fatalf("the app role cannot write grants: %v", err)
	}
	conn, err := pgx.Connect(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, stmt := range []string{
		`CREATE TABLE evil (x int)`, `CREATE SCHEMA evil`, `DROP TABLE grants`, `ALTER TABLE grants ADD COLUMN x int`, `ALTER TABLE grants DISABLE ROW LEVEL SECURITY`,
		`TRUNCATE grants`, `DROP TABLE pending_states`, `CREATE INDEX evil ON grants (scope)`, `DROP TABLE schema_migrations`, `DELETE FROM schema_migrations`,
		`INSERT INTO schema_migrations (version, name) VALUES (99, 'x')`, `CREATE ROLE evil`, `CREATE FUNCTION evil() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
	} {
		if _, err := conn.Exec(ctx, stmt); err == nil {
			t.Errorf("the service role ran %q", stmt)
		}
	}
	// what it may do: the four privileges on the three tables, and read the version
	for _, stmt := range []string{`SELECT count(*) FROM grants`, `UPDATE grants SET scope = 'x'`, `DELETE FROM pending_states`, `INSERT INTO client_registrations VALUES ('c','i','r','id',NULL,'none')`, `SELECT max(version) FROM schema_migrations`} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Errorf("%q: %v", stmt, err)
		}
	}
	// and the owner's URL is refused as a service URL: the server does not run with the power to change the schema
	if _, err := grants.Open(ctx, owner); err == nil || !strings.Contains(err.Error(), "refusing to run") {
		t.Fatalf("the server opened as the owner: %v", err)
	}
}

func TestTheServerNeverMigratesAndRefusesASchemaThatIsNotTheOneItExpects(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	owner, svc := pgtest.Scratch(t)
	// older than expected: the owner removes the record of the migration
	oc, err := pgx.Connect(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer oc.Close(ctx)
	if _, err := oc.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 2`); err != nil { // one behind
		t.Fatal(err)
	}
	if _, err := grants.Open(ctx, svc); err == nil || !strings.Contains(err.Error(), "binary needs") {
		t.Fatalf("a schema one version behind: %v", err)
	}
	if _, err := oc.Exec(ctx, `DELETE FROM schema_migrations`); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Open(ctx, svc); err == nil || !strings.Contains(err.Error(), "binary needs") {
		t.Fatalf("a schema older than expected: %v", err)
	}
	// newer than expected
	if _, err := oc.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES (1, 'a'), (2, 'b'), (3, 'c')`); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Open(ctx, svc); err == nil || !strings.Contains(err.Error(), "binary needs") {
		t.Fatalf("a schema newer than expected: %v", err)
	}
}

func TestEnsureLoginMakesARoleThatIsNotAnOwnerAndRefusesBadNames(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	owner, _ := pgtest.Scratch(t)
	// a name that is new every time, so that a refusal is the check's and not "role exists"
	fresh := "Bad" + strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, bad := range []string{"", fresh, "a b", "a;drop", "a-b"} {
		if err := grants.EnsureLogin(ctx, owner, bad, "pw"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	unlock := pgtest.RoleLock(t)
	defer unlock()
	if err := grants.EnsureLogin(ctx, owner, "idp_bridge_it_svc", "it-service-password"); err != nil { // again: an update
		t.Fatal(err)
	}
}

// A connection's reviewer grant is a row of its own: the same person's member grant and the reviewer grant do not meet, offboarding a
// member leaves it, withdrawing the connection takes it (ADR-0001 D33).
func TestAReviewerGrantIsOfTheConnectionAndNeverOfAMember(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s, _ := mk()
			member := grant("acme", "ops", "notes")
			rv := grant("", "", "notes")
			rv.Key.Reviewer, rv.AuthorizedBy, rv.SealedAccess = true, "acme/ops", []byte("reviewer-sealed")
			if err := s.Put(ctx, member); err != nil {
				t.Fatal(err)
			}
			if err := s.Put(ctx, rv); err != nil {
				t.Fatal(err)
			}
			gm, _ := s.Get(ctx, member.Key)
			gr, err := s.Get(ctx, rv.Key)
			if err != nil || string(gm.SealedAccess) != "sealed-a" || string(gr.SealedAccess) != "reviewer-sealed" || !gr.Reviewer || gr.AuthorizedBy != "acme/ops" {
				t.Fatalf("%+v %+v %v", gm, gr, err)
			}
			if list, _ := s.ForMember(ctx, "acme", "ops"); len(list) != 1 || list[0].Reviewer {
				t.Fatalf("a member's list holds the reviewer grant: %+v", list)
			}
			// locked, updated and deleted by their own keys
			if err := s.Locked(ctx, rv.Key, func(g grants.Grant) (grants.Grant, grants.Action, error) {
				g.Scope = "changed"
				return g, grants.Update, nil
			}); err != nil {
				t.Fatal(err)
			}
			if gm, _ = s.Get(ctx, member.Key); gm.Scope != "read" {
				t.Fatal("updating the reviewer grant changed the member's")
			}
			if n, _ := s.DeleteMember(ctx, "acme", "ops"); n != 1 {
				t.Fatalf("%d", n)
			}
			if _, err := s.Get(ctx, rv.Key); err != nil {
				t.Fatal("offboarding the member removed the reviewer grant")
			}
			_ = s.Put(ctx, member)
			if err := s.Delete(ctx, rv.Key); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, member.Key); err != nil {
				t.Fatal("deleting the reviewer grant removed the member's")
			}
			_ = s.Put(ctx, rv)
			if n, _ := s.DeleteConnection(ctx, "notes"); n != 2 {
				t.Fatalf("withdrawing the connection removed %d grants, want both", n)
			}
		})
	}
}

// The database itself refuses a row that is both or neither: a reviewer grant has no tenant and member, a member's has both.
func TestTheDatabaseRefusesARowThatIsNeitherAMembersNorTheConnectionsReviewer(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	_, svc := pgtest.Scratch(t)
	s, err := grants.Open(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, g := range map[string]grants.Grant{
		"a reviewer grant of a member":  func() grants.Grant { g := grant("acme", "bob", "notes"); g.Reviewer = true; return g }(),
		"a member grant of nobody":      grant("", "", "notes"),
		"a member grant with no member": grant("acme", "", "notes"),
	} {
		if err := s.Put(ctx, g); err == nil {
			t.Errorf("%s: stored", name)
		}
	}
}
