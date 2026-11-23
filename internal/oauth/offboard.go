package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"idp-mcp-bridge/internal/api"
	"idp-mcp-bridge/internal/auth"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/grants"
)

// Reasons a member is offboarded: the fixed set of the route, the reconciliation and the command (ADR-0001 D38).
const (
	ReasonUserDeleted   = "user_deleted"
	ReasonUserDisabled  = "user_disabled"
	ReasonTenantChanged = "tenant_changed"
	ReasonOperator      = "operator"
	ReasonOther         = "other"
)

// Reasons is the set of reasons a caller may give.
var Reasons = map[string]bool{ReasonUserDeleted: true, ReasonUserDisabled: true, ReasonTenantChanged: true, ReasonOperator: true, ReasonOther: true}

// Counters keeps counts by name and labels (label pairs); bridge.Metrics is the one that runs.
type Counters interface {
	Inc(name string, n int, labels ...string)
}

func (s *Service) inc(name string, n int, labels ...string) {
	if s.Counters != nil && n > 0 {
		s.Counters.Inc(name, n, labels...)
	}
}

// OffboardRequest is a member who left. Connection, if set, limits it to one connection (the operator's command); then it is not a
// departure: the pending authorizations and the reviewer accounts are left alone.
type OffboardRequest struct {
	Tenant, Member, Connection string
	Reason                     string
	// Source is who asked: route, reconcile or command. Caller is the azp of the service that called the route.
	Source, Caller string
}

// OffboardResult says what was done, in counts and nothing else: no token, no address.
type OffboardResult struct {
	GrantsRemoved     int `json:"grants_removed"`
	RevocationsFailed int `json:"revocations_failed"`
	StatesRemoved     int `json:"-"`
	ReviewerMarked    int `json:"reviewer_grants_marked"`
}

func hashOf(owner string) string {
	h := sha256.Sum256([]byte(owner))
	return hex.EncodeToString(h[:4])
}

// Offboard removes everything the bridge holds for a member who left (ADR-0001 D38): on every connection the tokens are revoked at
// the third party, where it can be done (the refresh token first), and the grant is deleted whether or not that worked; the
// member's pending authorizations go; the reviewer accounts the member authorized are marked, never revoked (D40). It is idempotent:
// a member with nothing to remove, or one removed before, is a success with zeros. It writes the audit line and the counts.
func (s *Service) Offboard(ctx context.Context, req OffboardRequest) (OffboardResult, error) {
	var res OffboardResult
	gs, err := s.Store.ForMember(ctx, req.Tenant, req.Member)
	if err != nil {
		return res, err
	}
	who := auth.Subject{Tenant: req.Tenant, Member: req.Member}
	for _, g := range gs {
		if req.Connection != "" && g.Connection != req.Connection {
			continue
		}
		if c, ok := s.conn(g.Connection); ok {
			res.RevocationsFailed += s.revoke(ctx, who, c, g)
		}
		if err := s.Store.Delete(ctx, g.Key); err != nil {
			return res, err
		}
		res.GrantsRemoved++
	}
	if req.Connection == "" {
		if res.StatesRemoved, err = s.Store.DeleteMemberStates(ctx, req.Tenant, req.Member); err != nil {
			return res, err
		}
		if res.ReviewerMarked, err = s.Store.MarkAuthorizerLeft(ctx, req.Tenant+"/"+req.Member); err != nil {
			return res, err
		}
	}
	reason := req.Reason
	if !Reasons[reason] {
		reason = ReasonOther
	}
	if s.Log != nil {
		// the member as the audit line names them everywhere: a hash prefix, never the subject
		s.Log.Info("audit", "event", "offboard", "tenant", req.Tenant, "member", hashOf(req.Tenant+"/"+req.Member), "reason", reason, "source", req.Source,
			"caller", req.Caller, "connection", req.Connection, "grants", res.GrantsRemoved, "revocationsFailed", res.RevocationsFailed, "states", res.StatesRemoved)
		if res.ReviewerMarked > 0 {
			s.Log.Warn("the operator who authorized a reviewer account left: re-authorize it", "tenant", req.Tenant, "accounts", res.ReviewerMarked)
		}
	}
	s.inc("offboard_total", 1, "reason", reason, "source", req.Source)
	s.inc("offboard_grants_removed_total", res.GrantsRemoved, "reason", reason)
	s.inc("offboard_revocation_failed_total", res.RevocationsFailed, "reason", reason)
	s.inc("reviewer_authorizer_left_total", res.ReviewerMarked)
	return res, nil
}

// ---- GitHub's revocation (ADR-0001 D42) ----

const (
	defaultGitHubAPI = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
)

func (s *Service) githubBase() string {
	if s.GitHubAPI != "" {
		return strings.TrimSuffix(s.GitHubAPI, "/")
	}
	return defaultGitHubAPI
}

// revokeGitHub revokes with GitHub's own API: DELETE /applications/{client_id}/grant removes the member's whole authorization of the
// application, DELETE /applications/{client_id}/token one access token; both with the application's id and secret and the access
// token in the body. The whole grant for a member who disconnects or left; only the one token for tokens that a new grant replaced,
// because the grant of the same user and application is the new one's too, and deleting it would revoke what was just issued.
// If the grant endpoint fails the token endpoint is tried; 204 is revoked, 404 and 422 are "already gone", anything else is a failure.
// If the access token has expired and a refresh token exists, one is refreshed first (not for superseded tokens): the API names the
// authorization by an access token it recognises, and a refresh is the only way to present one; its result is revoked at once.
func (s *Service) revokeGitHub(ctx context.Context, who auth.Subject, c config.Connection, g grants.Grant, superseded bool, keep []string) int {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cl := c.Authorization.Client
	b, err := os.ReadFile(cl.SecretFile)
	if err != nil || strings.TrimSpace(string(b)) == "" {
		s.logf("revocation skipped", who, c, fail(CodeClientUnsupported, "the client secret file cannot be read"))
		return 1
	}
	secret := strings.TrimSpace(string(b))
	plain, err := s.Sealer.Open(g.SealedAccess, g.Key)
	if err != nil {
		s.logf("revocation skipped", who, c, err)
		return 1
	}
	access := string(plain)
	if slices.Contains(keep, access) {
		return 0
	}
	if !superseded && len(g.SealedRefresh) > 0 && !g.AccessExpires.IsZero() && !g.AccessExpires.After(s.now()) {
		if fresh, rerr := s.renew(ctx, g.Key, who, c, ""); rerr == nil && fresh != "" {
			access = fresh
		}
	}
	kinds := []string{"grant", "token"}
	if superseded {
		kinds = []string{"token"}
	}
	for _, kind := range kinds {
		switch s.githubDelete(ctx, who, c, secret, kind, access) {
		case "revoked", "gone":
			return 0
		}
	}
	return 1
}

// githubDelete makes one call and says "revoked", "gone" or "failed". Only the code is logged.
func (s *Service) githubDelete(ctx context.Context, who auth.Subject, c config.Connection, secret, kind, access string) string {
	cl := c.Authorization.Client
	body, _ := json.Marshal(map[string]string{"access_token": access})
	h := http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-GitHub-Api-Version": {githubAPIVersion},
		"Content-Type":         {"application/json"},
		"Authorization":        {"Basic " + base64.StdEncoding.EncodeToString([]byte(cl.ID+":"+secret))},
	}
	resp, err := s.F.Do(ctx, http.MethodDelete, s.githubBase()+"/applications/"+url.PathEscape(cl.ID)+"/"+kind, h, body)
	if err != nil {
		s.logf("revocation at GitHub failed ("+kind+")", who, c, err)
		return "failed"
	}
	switch resp.Status {
	case http.StatusNoContent:
		return "revoked"
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		if s.Log != nil {
			s.Log.Info("the authorization is already gone at GitHub", "connection", c.ID, "tenant", who.Tenant, "endpoint", kind, "status", resp.Status)
		}
		return "gone"
	}
	if s.Log != nil {
		s.Log.Warn("revocation at GitHub failed", "connection", c.ID, "tenant", who.Tenant, "endpoint", kind, "status", resp.Status)
	}
	return "failed"
}

// OffboardAPI adapts Service to api.Offboarder (the route's source is "route", its caller the service's azp).
type OffboardAPI struct{ S *Service }

// Offboard implements api.Offboarder.
func (a OffboardAPI) Offboard(ctx context.Context, r api.OffboardRequest) (api.OffboardResult, error) {
	res, err := a.S.Offboard(ctx, OffboardRequest{Tenant: r.Tenant, Member: r.Member, Reason: r.Reason, Source: "route", Caller: r.Caller})
	return api.OffboardResult{GrantsRemoved: res.GrantsRemoved, RevocationsFailed: res.RevocationsFailed, ReviewerMarked: res.ReviewerMarked}, err
}

// AuthorizerLeft is the departure of an operator who holds no grant of his own but authorized a reviewer account (found by the
// reconciliation, ADR-0001 D40): the accounts are marked, never revoked, and the alert is raised. It writes an audit line.
func (s *Service) AuthorizerLeft(ctx context.Context, tenant, member, reason, source string) (int, error) {
	n, err := s.Store.MarkAuthorizerLeft(ctx, tenant+"/"+member)
	if err != nil {
		return 0, err
	}
	if !Reasons[reason] {
		reason = ReasonOther
	}
	if s.Log != nil {
		s.Log.Info("audit", "event", "authorizer_left", "tenant", tenant, "member", hashOf(tenant+"/"+member), "reason", reason, "source", source, "accounts", n)
		if n > 0 {
			s.Log.Warn("the operator who authorized a reviewer account left: re-authorize it", "tenant", tenant, "accounts", n)
		}
	}
	s.inc("reviewer_authorizer_left_total", n)
	return n, nil
}
