package certificates

import (
	"context"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/acme/autocert"

	"github.com/metalwaf/metalwaf/internal/database"
)

// acmeCachePrefix is prepended to every key written to the settings table
// to namespace ACME state away from user-visible settings.
const acmeCachePrefix = "acme:"

// dbCache implements autocert.Cache using the Store's settings table.
// Blobs are base64-encoded before storage so they survive as text values.
type dbCache struct {
	store database.Store
}

// NewDBCache returns an autocert.Cache backed by the database settings table.
// No separate table is needed — the key-value settings table is sufficient.
func NewDBCache(store database.Store) autocert.Cache {
	return &dbCache{store: store}
}

func (c *dbCache) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := c.store.GetSetting(ctx, acmeCachePrefix+key)
	if err != nil {
		return nil, fmt.Errorf("acme cache get: %w", err)
	}
	if v == "" {
		return nil, autocert.ErrCacheMiss
	}
	data, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("acme cache decode %q: %w", key, err)
	}
	return data, nil
}

func (c *dbCache) Put(ctx context.Context, key string, data []byte) error {
	return c.store.SetSetting(ctx,
		acmeCachePrefix+key,
		base64.StdEncoding.EncodeToString(data),
	)
}

func (c *dbCache) Delete(ctx context.Context, key string) error {
	// Set to empty string — subsequent Get returns ErrCacheMiss because v == "".
	return c.store.SetSetting(ctx, acmeCachePrefix+key, "")
}
