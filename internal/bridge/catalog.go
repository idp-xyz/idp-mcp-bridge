package bridge

import (
	"encoding/json"
	"sync"
	"time"

	"idp-mcp-bridge/internal/upstream"
)

// Defaults of the tool catalog (ADR-0001 D34).
const (
	// CatalogTTL is how long the bridge trusts the definitions it last listed: after it, a call to a tool refreshes them first.
	CatalogTTL = 5 * time.Minute
	// CatalogMinRefresh is the shortest time between two refreshes that a call causes: a model that calls tools that do not exist
	// cannot turn the bridge into a source of listings.
	CatalogMinRefresh = 30 * time.Second
)

// catalog is what the bridge knows of a connection's tools as far as the Mcp-Param-* headers go: for each tool the headers its
// definition declares, as of the last listing. A tool that is not in it, or an entry older than the TTL, is "unknown", and a call to
// an unknown tool sends no Mcp-Param-* headers.
type catalog struct {
	mu      sync.Mutex
	specs   map[string]upstream.ParamSpec
	at      time.Time
	lastTry time.Time
}

// set replaces the catalog with the tools of a listing (the result's `tools` array).
func (c *catalog) set(result json.RawMessage, now time.Time) {
	var r struct {
		Tools []struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if json.Unmarshal(result, &r) != nil {
		return
	}
	specs := make(map[string]upstream.ParamSpec, len(r.Tools))
	for _, t := range r.Tools {
		spec, reason := upstream.ParseParamSpec(t.InputSchema)
		if reason != "" {
			spec = nil // an invalid annotation: the tool is known, and has no headers
		}
		specs[t.Name] = spec
	}
	c.mu.Lock()
	c.specs, c.at = specs, now
	c.mu.Unlock()
}

// get returns the headers a tool declares; known is false for a tool the catalog does not have, or when it is stale.
func (c *catalog) get(name string, now time.Time) (spec upstream.ParamSpec, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.specs == nil || now.Sub(c.at) >= CatalogTTL {
		return nil, false
	}
	spec, known = c.specs[name]
	return spec, known
}

// mayRefresh says whether a refresh may be made now, and records that one is.
func (c *catalog) mayRefresh(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.lastTry.IsZero() && now.Sub(c.lastTry) < CatalogMinRefresh {
		return false
	}
	c.lastTry = now
	return true
}
