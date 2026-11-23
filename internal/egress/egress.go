// Package egress is the only way the bridge connects to the outside: the HTTP client toward third parties (and, in B2,
// toward their authorization servers). It makes the connection to an address it has checked, with the rules of
// internal/addr, and follows no redirect (ADR-0001 D6, D7).
//
// The check is made at the connection, not only at the configuration: a name that was public when the file was read
// can resolve to a private address later (or to one public and one private address, which is what an attacker who
// controls the name's DNS sends). The connection is made to an address from the answer, given as an IP, so nothing
// resolves the name a second time between the check and the connection; TLS then verifies the certificate against the
// name of the request, not the address.
package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"idp-mcp-bridge/internal/addr"
)

// ErrNotPublic is wrapped by every refusal of an address; errors.Is(err, addr.ErrNotPublic) holds for it.
var ErrNotPublic = addr.ErrNotPublic

// ErrConnect is wrapped by the failures that are not a refusal: a name that does not resolve, a connection that fails.
var ErrConnect = errors.New("the connection could not be made")

// Resolver is what the dialer needs of a resolver; net.DefaultResolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options of NewClient.
type Options struct {
	// TestOrigins are exact host:port pairs exempt from the port and public-address rules, for acceptance only
	// (IDP_BRIDGE_TEST_ORIGINS). Nothing else is exempted: not another port on the host, not another host.
	TestOrigins map[string]bool
	Resolver    Resolver // default: the system resolver
	// DialFamily is which address families a checked dial uses and which goes first (IDP_BRIDGE_DIAL_FAMILY, ADR-0001
	// D43). Default: prefer-ipv4.
	DialFamily DialFamily
	// Dial makes the connection to an address that has been checked; default net.Dialer. A seam for tests.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Proxy is the corporate egress proxy, if the operator's network has one (IDP_BRIDGE_EGRESS_PROXY). With a proxy the
	// bridge connects to the proxy and to nothing else, so it cannot check the address the proxy then reaches: that
	// is the proxy's job, and the operator's NetworkPolicy admits the proxy and nothing else (ADR-0001 D7). The
	// addresses in the configuration file are checked as before; a name's answers are not.
	Proxy *url.URL
	// ResponseHeaderTimeout bounds the wait for the third party's answer to begin (default 30 s).
	ResponseHeaderTimeout time.Duration
	TLS                   *tls.Config // extra trust, for tests
}

// NewClient returns an http.Client that dials through the address rules, follows no redirect, does not read
// HTTP(S)_PROXY from the environment, does not decompress (a body is read with a limit, and a compressed one would
// be a bomb under it) and sends no cookies.
func NewClient(o Options) *http.Client {
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Dial == nil {
		o.Dial = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	if o.ResponseHeaderTimeout == 0 {
		o.ResponseHeaderTimeout = 30 * time.Second
	}
	proxyHost := ""
	var proxyFn func(*http.Request) (*url.URL, error)
	if o.Proxy != nil {
		port := o.Proxy.Port()
		if port == "" {
			port = "80"
			if o.Proxy.Scheme == "https" {
				port = "443"
			}
		}
		proxyHost = net.JoinHostPort(o.Proxy.Hostname(), port)
		proxyFn = http.ProxyURL(o.Proxy)
	}
	d := &dialer{o: o, proxyHost: strings.ToLower(proxyHost)}
	tr := &http.Transport{
		Proxy:                 proxyFn, // nil: no proxy, and never the environment's
		DialContext:           d.dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: o.ResponseHeaderTimeout,
		DisableCompression:    true,
		TLSClientConfig:       o.TLS,
	}
	// No redirect is followed. A third party that moves its endpoint is a change of configuration, which an operator
	// makes; following it would carry the member's token to wherever the answer pointed, and the address rules
	// would only have judged the first address (ADR-0001 D7).
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type dialer struct {
	o         Options
	proxyHost string
}

// dial is the transport's DialContext. With a proxy configured it is asked for the proxy's address and only that one
// is allowed unchecked, and by exact host and port; every other address, which the transport would only ask for if
// it ignored the proxy, goes through the check.
func (d *dialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.proxyHost != "" && strings.ToLower(address) == d.proxyHost {
		return d.o.Dial(ctx, network, address)
	}
	return d.checked(ctx, network, address)
}

func (d *dialer) checked(ctx context.Context, _, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnect, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, fmt.Errorf("%w: port %q", ErrConnect, portText)
	}
	host = strings.ToLower(host)
	exempt := d.o.TestOrigins[net.JoinHostPort(host, portText)]
	// the port is checked again here, as the literal is, so that a mistake in the parser does not open the dialer
	if !exempt && port != 443 && port != 80 {
		return nil, fmt.Errorf("%w: port %d", ErrNotPublic, port)
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = d.o.Resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, fmt.Errorf("%w: lookup: %v", ErrConnect, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no address for %s", ErrConnect, host)
	}
	if !exempt {
		// ANY answer that is not public refuses the connection: a name with one private answer among its public ones
		// is a name its owner controls.
		for _, ip := range ips {
			if !addr.Public(ip) {
				return nil, fmt.Errorf("%w: %s resolves to %s", ErrNotPublic, host, ip)
			}
		}
	}
	c, err := dialRace(ctx, d.o.Dial, d.o.DialFamily, ips, port)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnect, err)
	}
	return c, nil
}
