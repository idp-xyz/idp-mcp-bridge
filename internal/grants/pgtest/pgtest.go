// Package pgtest gives the tests a scratch database on a real PostgreSQL. It is for tests only. Set IDP_TEST_PG_OWNER_URL to a
// superuser URL of a throwaway cluster (`make test-integration` starts one on a random loopback port and removes it again);
// without it the tests that need a database are skipped, as in idp-web, idp-mcp and idp-host.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"idp-mcp-bridge/internal/grants"
)

// Enabled says whether a database is configured for the tests.
func Enabled() bool { return os.Getenv("IDP_TEST_PG_OWNER_URL") != "" }

// Raw creates a database of its own and returns its URL as the cluster's superuser, nothing applied. It is dropped when the test
// ends.
func Raw(t testing.TB) string {
	t.Helper()
	base := os.Getenv("IDP_TEST_PG_OWNER_URL")
	if base == "" {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "idp_bridge_it_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	u, _ := url.Parse(base)
	u.Path = "/" + name
	return u.String()
}

// Scratch is Raw, migrated as the owner and with the login role of the service made: it returns the owner's URL (which the
// cluster's superuser stands for) and the service's URL, the least-privilege role the server must run as.
func Scratch(t testing.TB) (ownerURL, serviceURL string) {
	t.Helper()
	ownerURL = Raw(t)
	ctx := context.Background()
	// roles belong to the cluster, not to the database: tests of several packages create the same role at the same time
	unlock := RoleLock(t)
	defer unlock()
	if _, err := grants.Migrate(ctx, ownerURL); err != nil {
		t.Fatal(err)
	}
	if err := grants.EnsureLogin(ctx, ownerURL, "idp_bridge_it_svc", "it-service-password"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(ownerURL)
	u.User = url.UserPassword("idp_bridge_it_svc", "it-service-password")
	return ownerURL, u.String()
}

// RoleLock takes the lock that serializes what creates roles in the cluster (Scratch does it for itself) and returns the function
// that releases it.
func RoleLock(t testing.TB) (unlock func()) {
	t.Helper()
	base := os.Getenv("IDP_TEST_PG_OWNER_URL")
	if base == "" {
		t.Skip("IDP_TEST_PG_OWNER_URL not set (make test-integration)")
	}
	ctx := context.Background()
	lock, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_lock(72591)`); err != nil {
		t.Fatal(err)
	}
	return func() { lock.Close(ctx) } // closing the connection releases the lock
}
