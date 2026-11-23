// Package githubdouble is a double of the two endpoints of GitHub's REST API that revoke an application's user authorization:
// DELETE /applications/{client_id}/grant and DELETE /applications/{client_id}/token, authenticated with the application's id and
// secret (Basic) and given the access token in a JSON body. It records every request. It is not used by the service.
package githubdouble

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Request is what the double received.
type Request struct {
	Method, Path string
	Header       http.Header
	AccessToken  string // from the JSON body
	User, Pass   string // the Basic credentials
}

// Server is the double.
type Server struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []Request
	// ClientID and Secret are what the Basic credentials must be (else 401).
	ClientID, Secret string
	// Status is what each endpoint answers: "grant" and "token"; 204 if not set.
	Status map[string]int
}

// New starts a double; Close it.
func New(clientID, secret string) *Server {
	s := &Server{ClientID: clientID, Secret: secret, Status: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Origin is host:port, for the test-origin exemption.
func (s *Server) Origin() string { return strings.TrimPrefix(s.Server.URL, "http://") }

// Requests returns what was received.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var b struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(body, &b)
	u, p, _ := r.BasicAuth()
	req := Request{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), AccessToken: b.AccessToken, User: u, Pass: p}
	s.mu.Lock()
	s.reqs = append(s.reqs, req)
	status := map[string]int{}
	for k, v := range s.Status {
		status[k] = v
	}
	s.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method != http.MethodDelete || len(parts) != 3 || parts[0] != "applications" || (parts[2] != "grant" && parts[2] != "token") {
		http.NotFound(w, r)
		return
	}
	if u != s.ClientID || p != s.Secret || parts[1] != s.ClientID {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if b.AccessToken == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	code := status[parts[2]]
	if code == 0 {
		code = http.StatusNoContent
	}
	w.WriteHeader(code)
}
