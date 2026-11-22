package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"idp-mcp-bridge/internal/addr"
)

type resolver map[string][]string

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range r[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if out == nil {
		return nil, errors.New("no such host")
	}
	return out, nil
}

type dials struct {
	mu   sync.Mutex
	list []string
}

func (d *dials) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.list = append(d.list, address)
	d.mu.Unlock()
	return nil, errors.New("not connected")
}

func get(c *http.Client, raw string) error {
	req, _ := http.NewRequest(http.MethodGet, raw, nil)
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestEveryAnswerOfANameMustBePublicAndTheConnectionIsToTheCheckedAddress(t *testing.T) {
	d := &dials{}
	c := NewClient(Options{Dial: d.dial, Resolver: resolver{
		"public.example.com": {"93.184.216.34"},
		"mixed.example.com":  {"93.184.216.34", "10.0.0.5"},
		"v6.example.com":     {"2606:2800:220:1:248:1893:25c8:1946"},
		"mapped.example.com": {"::ffff:127.0.0.1"},
		"nat64.example.com":  {"64:ff9b::7f00:1"},
		"link.example.com":   {"169.254.169.254"},
	}})
	for _, name := range []string{"mixed", "mapped", "nat64", "link"} {
		err := get(c, "https://"+name+".example.com/mcp")
		if !errors.Is(err, addr.ErrNotPublic) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(d.list) != 0 {
		t.Fatalf("connected to %v", d.list)
	}
	_ = get(c, "https://public.example.com/mcp")
	_ = get(c, "https://v6.example.com/mcp")
	if len(d.list) != 2 || d.list[0] != "93.184.216.34:443" || d.list[1] != "[2606:2800:220:1:248:1893:25c8:1946]:443" {
		t.Fatalf("dialed %v", d.list)
	}
	// a literal that is not public, a name that does not resolve
	if err := get(c, "https://10.1.1.1/mcp"); !errors.Is(err, addr.ErrNotPublic) {
		t.Errorf("a private literal: %v", err)
	}
	if err := get(c, "https://nowhere.example.com/mcp"); !errors.Is(err, ErrConnect) {
		t.Errorf("an unknown name: %v", err)
	}
}

func TestOnlyPort80And443AreDialedUnlessTheOriginIsATestOrigin(t *testing.T) {
	d := &dials{}
	c := NewClient(Options{Dial: d.dial, Resolver: resolver{"public.example.com": {"93.184.216.34"}}})
	if err := get(c, "https://public.example.com:8443/mcp"); !errors.Is(err, addr.ErrNotPublic) || len(d.list) != 0 {
		t.Fatalf("%v %v", err, d.list)
	}
}

func TestATestOriginIsExemptExactlyAndNothingElseIs(t *testing.T) {
	d := &dials{}
	c := NewClient(Options{Dial: d.dial, TestOrigins: map[string]bool{"127.0.0.1:9999": true}})
	_ = get(c, "http://127.0.0.1:9999/mcp")
	if len(d.list) != 1 {
		t.Fatalf("the test origin was not dialed: %v", d.list)
	}
	for _, other := range []string{"http://127.0.0.1:9998/", "http://127.0.0.2:9999/", "http://[::1]:9999/"} {
		if err := get(c, other); !errors.Is(err, addr.ErrNotPublic) {
			t.Errorf("%s: %v", other, err)
		}
	}
	if len(d.list) != 1 {
		t.Fatalf("dialed %v", d.list)
	}
}

func TestARedirectIsNotFollowedAndNothingIsSentToItsTarget(t *testing.T) {
	var hits int
	victim := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer victim.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL, http.StatusTemporaryRedirect)
	}))
	defer front.Close()
	// the front is exempt, the victim (also loopback) is not: even a client that followed would be stopped at the dial
	c := NewClient(Options{TestOrigins: map[string]bool{strings.TrimPrefix(front.URL, "http://"): true}})
	req, _ := http.NewRequest(http.MethodPost, front.URL, strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || hits != 0 {
		t.Fatalf("status %d, the target was reached %d times", resp.StatusCode, hits)
	}
	// and the dialer alone refuses the target
	if err := get(c, victim.URL); !errors.Is(err, addr.ErrNotPublic) {
		t.Fatalf("%v", err)
	}
}

func TestTheEnvironmentsProxyIsNeverUsed(t *testing.T) {
	var hits int
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "direct") }))
	defer target.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	c := NewClient(Options{TestOrigins: map[string]bool{strings.TrimPrefix(target.URL, "http://"): true}})
	resp, err := c.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "direct" || hits != 0 {
		t.Fatalf("%q, the proxy saw %d requests", b, hits)
	}
}

func TestAConfiguredProxyIsTheOnlyAddressDialedUncheckedAndTheTargetIsNotDialedDirectly(t *testing.T) {
	var gotURL string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		_, _ = io.WriteString(w, "via the proxy")
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	// the proxy is a loopback address, which the rules would refuse: it is dialed because it is the proxy, by exact host and port
	d := &dials{}
	c := NewClient(Options{Proxy: pu, Resolver: resolver{"third.example.com": {"93.184.216.34"}}, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		d.dial(ctx, n, a)
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}, TestOrigins: map[string]bool{}})
	req, _ := http.NewRequest(http.MethodGet, "http://third.example.com:80/x", nil)
	// (plain http, so that the proxy double need not speak CONNECT: the point is where the connection goes)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "via the proxy" || gotURL != "http://third.example.com:80/x" || len(d.list) != 1 || d.list[0] != strings.TrimPrefix(proxy.URL, "http://") {
		t.Fatalf("%q %q dialed %v", b, gotURL, d.list)
	}
}
