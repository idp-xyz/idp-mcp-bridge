// Package migrations embeds the bridge's schema migrations (applied in file name order at start, or by `idp-mcp-bridge migrate`).
package migrations

import "embed"

// FS holds NNNN_name.sql files.
//
//go:embed *.sql
var FS embed.FS
