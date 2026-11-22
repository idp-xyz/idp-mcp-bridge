// Package mcptest plays the gateway for the tests: it signs the caller assertions the bridge verifies, with a key of
// its own, and builds the requests the gateway sends. It is not used by the service.
package mcptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"idp-mcp-bridge/internal/mcp"
)

// Gateway signs assertions as idp-mcp's gateway does (ADR-0001 D44 there).
type Gateway struct {
	Key *ecdsa.PrivateKey
	n   atomic.Int64
	Now func() time.Time
}

// New makes a gateway with a fresh key.
func New() *Gateway {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Gateway{Key: k, Now: time.Now}
}

// PEM is the gateway's public key as the bridge is given it.
func (g *Gateway) PEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&g.Key.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Sign makes the assertion for a tools/call with these params (without _meta), for the audience.
func (g *Gateway) Sign(audience, subject, tenant string, params map[string]json.RawMessage) string {
	kid, _ := mcp.KeyID(&g.Key.PublicKey)
	digest, err := mcp.RequestDigest("tools/call", params)
	if err != nil {
		panic(err)
	}
	now := g.Now()
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": mcp.AssertionType, "kid": kid})
	c, _ := json.Marshal(map[string]any{"iss": "idp-mcp-gateway:test", "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("j%d-%d", g.n.Add(1), now.UnixNano()), "sub": subject, "tenant_id": tenant, "roles": []string{"host-user"}, "client": "idp-host", "actor": "idp-host", "req": digest})
	input := enc(h) + "." + enc(c)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, g.Key, sum[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc(sig)
}

// Meta is the _meta every request carries.
const Meta = `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}`

// CallBody is the body of a tools/call as the gateway sends it: the arguments (a JSON object), the caller
// assertion signed for audience, and the extra _meta members extra (a JSON object body without braces, or "").
func (g *Gateway) CallBody(audience, subject, tenant, tool, args, extra string) string {
	return g.CallBodyParams(audience, subject, tenant, map[string]json.RawMessage{"name": json.RawMessage(fmt.Sprintf("%q", tool)), "arguments": json.RawMessage(args)}, extra)
}

// CallBodyParams is CallBody for params the caller chose (name, arguments and whatever else a client may send); the
// assertion is over them as the gateway signs them, without _meta.
func (g *Gateway) CallBodyParams(audience, subject, tenant string, params map[string]json.RawMessage, extra string) string {
	a := g.Sign(audience, subject, tenant, params)
	meta := Meta + `,"io.idp.telos/caller-assertion":"` + a + `"`
	if extra != "" {
		meta += "," + extra
	}
	all := map[string]json.RawMessage{"_meta": json.RawMessage("{" + meta + "}")}
	for k, v := range params {
		all[k] = v
	}
	p, _ := json.Marshal(all)
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + string(p) + `}`
}

// ListBody is the body of a tools/list.
func ListBody() string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{` + Meta + `}}}`
}

// Post sends body to h at path as the gateway would (the headers of the 2026-07-28 transport) and decodes the answer.
func Post(h http.Handler, path, body string, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	var b struct{ Method string }
	_ = json.Unmarshal([]byte(body), &b)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
	r.Header.Set("Mcp-Method", b.Method)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}
