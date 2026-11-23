package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"idp-mcp-bridge/internal/app"
	"idp-mcp-bridge/internal/config"
	"idp-mcp-bridge/internal/egress"
	"idp-mcp-bridge/internal/upstream"
)

// settings are what the environment says; the connections come from the file it names.
type settings struct {
	listen, apiListen, metrics string
	baseURL                    string
	callerKeys                 []byte
	configFile                 string
	testOrigins                map[string]bool
	dialFamily                 egress.DialFamily
	proxy                      *url.URL
	maxResult, maxStream       int64
	callTimeout                time.Duration
}

func env(getenv func(string) string, k, def string) string {
	if v := getenv(k); v != "" {
		return v
	}
	return def
}

// listenAddr checks an address to listen on: a non-loopback one needs IDP_BRIDGE_PRIVATE_NETWORK=true, the operator's
// statement that only the gateway (or, for the API, the Workspace) can reach it (ADR-0001 D18).
func listenAddr(name, v string, private bool) error {
	host, _, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && !private {
		return fmt.Errorf("refusing to listen on %s (%s) without IDP_BRIDGE_PRIVATE_NETWORK=true: only the gateway and the Workspace may reach this server, and the network policy is what says so", v, name)
	}
	return nil
}

func bytesSetting(getenv func(string) string, name string, def int64) (int64, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 || n > 16<<20 {
		return 0, fmt.Errorf("%s must be a number of bytes from 1 to 16777216, not %q", name, v)
	}
	return n, nil
}

// loadSettings reads and checks every setting; any error is a configuration error (exit status 2).
func loadSettings(getenv func(string) string) (*settings, error) {
	s := &settings{
		listen:    env(getenv, "IDP_BRIDGE_LISTEN", "127.0.0.1:8680"),
		apiListen: env(getenv, "IDP_BRIDGE_API_LISTEN", "127.0.0.1:8681"),
		metrics:   env(getenv, "IDP_BRIDGE_METRICS", "127.0.0.1:9680"),
		baseURL:   strings.TrimSuffix(getenv("IDP_BRIDGE_BASE_URL"), "/"),
	}
	private := getenv("IDP_BRIDGE_PRIVATE_NETWORK") == "true"
	for _, c := range [][2]string{{"IDP_BRIDGE_LISTEN", s.listen}, {"IDP_BRIDGE_API_LISTEN", s.apiListen}, {"IDP_BRIDGE_METRICS", s.metrics}} {
		if err := listenAddr(c[0], c[1], private); err != nil {
			return nil, err
		}
	}
	if s.listen == s.apiListen || s.listen == s.metrics || s.apiListen == s.metrics {
		return nil, errors.New("IDP_BRIDGE_LISTEN, IDP_BRIDGE_API_LISTEN and IDP_BRIDGE_METRICS must be three different addresses")
	}
	var err error
	if s.testOrigins, err = parseTestOrigins(getenv("IDP_BRIDGE_TEST_ORIGINS")); err != nil {
		return nil, fmt.Errorf("invalid IDP_BRIDGE_TEST_ORIGINS: %w", err)
	}
	if s.dialFamily, err = egress.ParseDialFamily(getenv("IDP_BRIDGE_DIAL_FAMILY")); err != nil {
		return nil, fmt.Errorf("invalid IDP_BRIDGE_DIAL_FAMILY: %w", err)
	}
	if s.configFile = getenv("IDP_BRIDGE_CONFIG_FILE"); s.configFile == "" {
		return nil, errors.New("IDP_BRIDGE_CONFIG_FILE is not set: the file that lists the connections")
	}
	// The gateway's keys and the audience are required: there is no mode in which the caller is taken as it arrives, because
	// the caller decides whose token is used (ADR-0001 D2).
	keysFile := getenv("IDP_BRIDGE_CALLER_KEYS_FILE")
	if keysFile == "" {
		return nil, errors.New("IDP_BRIDGE_CALLER_KEYS_FILE is not set: the gateway's public key (PEM, P-256); the bridge does not run without a way to know who the caller is")
	}
	if s.callerKeys, err = os.ReadFile(keysFile); err != nil {
		return nil, fmt.Errorf("IDP_BRIDGE_CALLER_KEYS_FILE: %w", err)
	}
	if s.baseURL == "" {
		return nil, errors.New("IDP_BRIDGE_BASE_URL is not set: the address the gateway registers the bridge at, for the audience of its assertions")
	}
	if err := app.ValidateBaseURL(s.baseURL); err != nil {
		return nil, fmt.Errorf("IDP_BRIDGE_BASE_URL: %w", err)
	}
	if p := getenv("IDP_BRIDGE_EGRESS_PROXY"); p != "" {
		u, err := url.Parse(p)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
			return nil, errors.New("IDP_BRIDGE_EGRESS_PROXY must be an http or https address of the form http://host:port, without credentials")
		}
		s.proxy = u
	}
	if s.maxResult, err = bytesSetting(getenv, "IDP_BRIDGE_MAX_RESULT_BYTES", upstream.DefaultMaxResult); err != nil {
		return nil, err
	}
	if s.maxStream, err = bytesSetting(getenv, "IDP_BRIDGE_MAX_STREAM_BYTES", upstream.DefaultMaxStream); err != nil {
		return nil, err
	}
	if s.maxResult > s.maxStream {
		return nil, errors.New("IDP_BRIDGE_MAX_RESULT_BYTES is larger than IDP_BRIDGE_MAX_STREAM_BYTES: an event cannot be longer than the stream it is in")
	}
	s.callTimeout = 60 * time.Second
	if v := getenv("IDP_BRIDGE_CALL_TIMEOUT_S"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 600 {
			return nil, fmt.Errorf("IDP_BRIDGE_CALL_TIMEOUT_S must be 1 to 600, not %q", v)
		}
		s.callTimeout = time.Duration(n) * time.Second
	}
	return s, nil
}

// parseTestOrigins reads IDP_BRIDGE_TEST_ORIGINS: comma-separated host:port pairs, each an exact origin that may be
// contacted although it is not a public address, not on port 443 or not https (idp-web ADR-0001 D14, which this is
// copied from). A wildcard, a missing port or an empty host is an error: a loose entry would exempt more than was meant.
func parseTestOrigins(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, port, err := net.SplitHostPort(item)
		if err != nil || host == "" {
			return nil, fmt.Errorf("%q is not host:port", item)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("%q has no valid port", item)
		}
		if strings.ContainsAny(host, "*?%") {
			return nil, fmt.Errorf("%q: only exact hosts are accepted", item)
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.String()
		} else {
			host = strings.ToLower(host)
		}
		out[net.JoinHostPort(host, strconv.Itoa(p))] = true
	}
	return out, nil
}

// connections loads the file the settings name.
func (s *settings) connections() ([]config.Connection, error) {
	return config.Load(s.configFile, config.Options{TestOrigins: s.testOrigins})
}
