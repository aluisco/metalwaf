// Package frontend exposes the compiled React SPA as an embedded file-system.
// Build the UI first:
//
//	cd internal/frontend/web && npm run build
package frontend

import "embed"

// FS contains the compiled React SPA from web/dist.
// Mount it on the admin HTTP mux; serve index.html for all unknown paths
// so the SPA router handles client-side navigation.
//
//go:embed web/dist
var FS embed.FS
