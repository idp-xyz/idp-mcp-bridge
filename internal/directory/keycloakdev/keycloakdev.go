// Package keycloakdev is the directory adapter for Keycloak, FOR DEVELOPMENT AND TESTS ONLY (ADR-0001 D39). Keycloak is the platform's
// identity provider while it is being built; the one it ships with is not chosen, and it will bring its own adapter (a SCIM
// `GET /Users/{id}`, or its directory API). Nothing outside this package depends on Keycloak's admin API.
//
// It is a confidential client with a service account (it needs the realm's view-users role): a token from the token endpoint by the
// client-credentials grant, then GET {url}/admin/realms/{realm}/users/{id}. Only clear answers are answers: 404 with Keycloak's
// own "User not found" is a deleted account (a 404 for a wrong realm is not); `enabled: false` is disabled; a tenant attribute that
// is another tenant than the grant's is moved; the same tenant and enabled is present; everything else is unknown.
package keycloakdev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"idp-mcp-bridge/internal/directory"
)

// Config of the adapter.
type Config struct {
	// URL is Keycloak's base address (https://keycloak.example.com), Realm the realm, ClientID and ClientSecret the service account's.
	URL, Realm, ClientID, ClientSecret string
	// TenantAttribute is the user attribute that holds the tenant (default tenant_id).
	TenantAttribute string
	HTTP            *http.Client
	Now             func() time.Time
}

// Directory is the adapter.
type Directory struct {
	c    Config
	mu   sync.Mutex
	tok  string
	till time.Time
}

// New makes the adapter; it does not contact Keycloak.
func New(c Config) (*Directory, error) {
	if c.URL == "" || c.Realm == "" || c.ClientID == "" || c.ClientSecret == "" || c.HTTP == nil {
		return nil, errors.New("keycloak-dev directory: URL, realm, client id, client secret and an HTTP client are required")
	}
	if c.TenantAttribute == "" {
		c.TenantAttribute = "tenant_id"
	}
	c.URL = strings.TrimSuffix(c.URL, "/")
	return &Directory{c: c}, nil
}

func (d *Directory) now() time.Time {
	if d.c.Now != nil {
		return d.c.Now()
	}
	return time.Now()
}

var errUnknown = errors.New("the directory did not give an answer")

func (d *Directory) token(ctx context.Context, force bool) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !force && d.tok != "" && d.now().Before(d.till) {
		return d.tok, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {d.c.ClientID}, "client_secret": {d.c.ClientSecret}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.c.URL+"/realms/"+url.PathEscape(d.c.Realm)+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.c.HTTP.Do(req)
	if err != nil {
		return "", errUnknown
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &t) != nil || t.AccessToken == "" {
		return "", errUnknown
	}
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 60
	}
	d.tok, d.till = t.AccessToken, d.now().Add(time.Duration(t.ExpiresIn)*time.Second-30*time.Second)
	return d.tok, nil
}

func (d *Directory) get(ctx context.Context, member, token string) (*http.Response, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.c.URL+"/admin/realms/"+url.PathEscape(d.c.Realm)+"/users/"+url.PathEscape(member), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := d.c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body, err
}

// Lookup implements directory.Directory.
func (d *Directory) Lookup(ctx context.Context, tenant, member string) (directory.Status, error) {
	if member == "" || strings.ContainsAny(member, "/\x00") {
		return directory.Unknown, errUnknown
	}
	tok, err := d.token(ctx, false)
	if err != nil {
		return directory.Unknown, err
	}
	resp, body, err := d.get(ctx, member, tok)
	if err == nil && resp.StatusCode == http.StatusUnauthorized { // the token was revoked or the clocks differ: one new one
		if tok, err = d.token(ctx, true); err == nil {
			resp, body, err = d.get(ctx, member, tok)
		}
	}
	if err != nil {
		return directory.Unknown, errUnknown
	}
	switch resp.StatusCode {
	case http.StatusNotFound:
		var e struct {
			Error string `json:"error"`
		}
		// Keycloak says "User not found" for a user, and something else ("Realm not found.") for the rest: only the first is an answer
		if json.Unmarshal(body, &e) == nil && e.Error == "User not found" {
			return directory.Deleted, nil
		}
		return directory.Unknown, errUnknown
	case http.StatusOK:
	default:
		return directory.Unknown, fmt.Errorf("%w (HTTP %d)", errUnknown, resp.StatusCode)
	}
	var u struct {
		ID         string              `json:"id"`
		Enabled    *bool               `json:"enabled"`
		Attributes map[string][]string `json:"attributes"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&u) != nil || u.ID != member || u.Enabled == nil {
		return directory.Unknown, errUnknown // does not look like the user
	}
	if !*u.Enabled {
		return directory.Disabled, nil
	}
	attr := u.Attributes[d.c.TenantAttribute]
	if len(attr) == 0 {
		return directory.Unknown, errUnknown // no tenant to compare: no answer
	}
	if attr[0] != tenant {
		return directory.Moved, nil
	}
	return directory.Present, nil
}
