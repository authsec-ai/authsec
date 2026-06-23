// Package fakes provides per-test-programmable httptest servers and in-process
// Redis for the integration harness. All fakes are started once per test binary
// in TestMain and torn down after m.Run().
package fakes

import (
	"net/http/httptest"

	"github.com/alicebob/miniredis/v2"
)

// Fakes owns all external-dependency stubs for one test binary.
type Fakes struct {
	Hydra    *HydraFake
	JWKS     *JWKSFake
	MiniRedis *miniredis.Miniredis
}

// Start creates all fakes and returns the populated struct.
// Caller must set env vars (HYDRA_ADMIN_URL, ICP_SERVICE_URL, REDIS_URL)
// from the returned fakes BEFORE calling config.LoadConfig.
func Start() (*Fakes, error) {
	hydra := newHydraFake()
	hydra.server = httptest.NewServer(hydra)

	jwks := newJWKSFake()
	jwks.server = httptest.NewServer(jwks)

	mr, err := miniredis.Run()
	if err != nil {
		return nil, err
	}

	return &Fakes{
		Hydra:     hydra,
		JWKS:      jwks,
		MiniRedis: mr,
	}, nil
}

// Stop shuts all fakes down. Call in TestMain after m.Run().
func (f *Fakes) Stop() {
	if f.Hydra != nil && f.Hydra.server != nil {
		f.Hydra.server.Close()
	}
	if f.JWKS != nil && f.JWKS.server != nil {
		f.JWKS.server.Close()
	}
	if f.MiniRedis != nil {
		f.MiniRedis.Close()
	}
}

// HydraAdminURL returns the URL to set as HYDRA_ADMIN_URL.
func (f *Fakes) HydraAdminURL() string { return f.Hydra.server.URL }

// ICPServiceURL returns the URL to set as ICP_SERVICE_URL.
func (f *Fakes) ICPServiceURL() string { return f.JWKS.server.URL }

// RedisURL returns redis:// URL for the miniredis instance.
func (f *Fakes) RedisURL() string { return "redis://" + f.MiniRedis.Addr() }
