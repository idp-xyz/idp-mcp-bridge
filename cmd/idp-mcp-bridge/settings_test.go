package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func goodEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "caller.pub")
	if err := os.WriteFile(keys, []byte("not checked here"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"IDP_BRIDGE_CONFIG_FILE": filepath.Join(dir, "c.yaml"), "IDP_BRIDGE_CALLER_KEYS_FILE": keys,
		"IDP_BRIDGE_BASE_URL": "http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/"}
}

func TestTheDefaultSettingsAreValidAndLoopbackOnly(t *testing.T) {
	s, err := loadSettings(envOf(goodEnv(t)))
	if err != nil {
		t.Fatal(err)
	}
	if s.listen != "127.0.0.1:8680" || s.apiListen != "127.0.0.1:8681" || s.metrics != "127.0.0.1:9680" || s.baseURL != "http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680" ||
		s.maxResult != 1<<20 || s.maxStream != 4<<20 || s.callTimeout.Seconds() != 60 {
		t.Fatalf("%+v", s)
	}
}

func TestEachMissingOrInvalidSettingIsAConfigurationError(t *testing.T) {
	cases := []struct {
		name string
		mod  map[string]string
		want string
	}{
		{"no config file", map[string]string{"IDP_BRIDGE_CONFIG_FILE": ""}, "IDP_BRIDGE_CONFIG_FILE"},
		{"no gateway keys: the caller would be taken on trust", map[string]string{"IDP_BRIDGE_CALLER_KEYS_FILE": ""}, "IDP_BRIDGE_CALLER_KEYS_FILE is not set"},
		{"a keys file that is not there", map[string]string{"IDP_BRIDGE_CALLER_KEYS_FILE": "/nonexistent"}, "IDP_BRIDGE_CALLER_KEYS_FILE"},
		{"no base url", map[string]string{"IDP_BRIDGE_BASE_URL": ""}, "IDP_BRIDGE_BASE_URL"},
		{"a base url with a path", map[string]string{"IDP_BRIDGE_BASE_URL": "http://bridge:8680/mcp"}, "IDP_BRIDGE_BASE_URL"},
		{"a base url that is not http", map[string]string{"IDP_BRIDGE_BASE_URL": "ftp://bridge"}, "IDP_BRIDGE_BASE_URL"},
		{"a public listen address without the private network statement", map[string]string{"IDP_BRIDGE_LISTEN": "0.0.0.0:8680"}, "IDP_BRIDGE_PRIVATE_NETWORK"},
		{"a public api address without the statement", map[string]string{"IDP_BRIDGE_API_LISTEN": "0.0.0.0:8681"}, "IDP_BRIDGE_PRIVATE_NETWORK"},
		{"a listen address that is not an address", map[string]string{"IDP_BRIDGE_LISTEN": "8680"}, "IDP_BRIDGE_LISTEN"},
		{"two servers on one address", map[string]string{"IDP_BRIDGE_API_LISTEN": "127.0.0.1:8680"}, "three different"},
		{"a wildcard test origin", map[string]string{"IDP_BRIDGE_TEST_ORIGINS": "*.example.com:1"}, "IDP_BRIDGE_TEST_ORIGINS"},
		{"a test origin without a port", map[string]string{"IDP_BRIDGE_TEST_ORIGINS": "127.0.0.1"}, "IDP_BRIDGE_TEST_ORIGINS"},
		{"a proxy with credentials", map[string]string{"IDP_BRIDGE_EGRESS_PROXY": "http://u:p@proxy:3128"}, "IDP_BRIDGE_EGRESS_PROXY"},
		{"a proxy that is not http", map[string]string{"IDP_BRIDGE_EGRESS_PROXY": "socks5://proxy:1080"}, "IDP_BRIDGE_EGRESS_PROXY"},
		{"a result limit of zero", map[string]string{"IDP_BRIDGE_MAX_RESULT_BYTES": "0"}, "IDP_BRIDGE_MAX_RESULT_BYTES"},
		{"a stream limit over 16 MiB", map[string]string{"IDP_BRIDGE_MAX_STREAM_BYTES": "99999999"}, "IDP_BRIDGE_MAX_STREAM_BYTES"},
		{"an event limit above the stream limit", map[string]string{"IDP_BRIDGE_MAX_RESULT_BYTES": "5000000"}, "cannot be longer"},
		{"a call timeout of zero", map[string]string{"IDP_BRIDGE_CALL_TIMEOUT_S": "0"}, "IDP_BRIDGE_CALL_TIMEOUT_S"},
	}
	for _, c := range cases {
		e := goodEnv(t)
		for k, v := range c.mod {
			e[k] = v
		}
		if _, err := loadSettings(envOf(e)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %s", c.name, err, c.want)
		}
	}
	// the statement makes a non-loopback address valid
	e := goodEnv(t)
	e["IDP_BRIDGE_LISTEN"], e["IDP_BRIDGE_API_LISTEN"], e["IDP_BRIDGE_METRICS"], e["IDP_BRIDGE_PRIVATE_NETWORK"] = "0.0.0.0:8680", "0.0.0.0:8681", "0.0.0.0:9680", "true"
	if _, err := loadSettings(envOf(e)); err != nil {
		t.Fatal(err)
	}
}

func TestTestOriginsAreParsedIntoTheFormTheDialerCompares(t *testing.T) {
	m, err := parseTestOrigins(" 127.0.0.1:9000, LOCALHOST:9001 ,[::1]:9002,,")
	if err != nil || len(m) != 3 || !m["127.0.0.1:9000"] || !m["localhost:9001"] || !m["[::1]:9002"] {
		t.Fatalf("%v %v", m, err)
	}
}
