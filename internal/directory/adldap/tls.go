package adldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// ErrSkipVerifyRefused is returned when insecure_skip_verify is set while the
// process is in production. Lab and development may still opt out, and that
// opt-out is logged by the caller.
var ErrSkipVerifyRefused = fmt.Errorf("insecure_skip_verify is refused when ENVIRONMENT is production")

// TLSOptions is the certificate policy for LDAPS and StartTLS.
type TLSOptions struct {
	ServerName string
	// SkipVerify is the existing skip_verify / insecure_skip_verify flag.
	SkipVerify bool
	// CAPEM is an optional PEM bundle of trusted CAs. Empty uses the system pool.
	CAPEM []byte
	// Production refuses SkipVerify. The caller reads the process environment
	// (config.AppConfig.Environment); this package does not.
	Production bool
}

// Plan describes the TLS handshake the dialer will use.
type Plan struct {
	Config  *tls.Config
	Warning string
}

// PlanTLS builds a verifying client config. SkipVerify is honoured only outside
// production, and then only with a warning the caller must log.
func PlanTLS(opts TLSOptions) (Plan, error) {
	if opts.SkipVerify && opts.Production {
		return Plan{}, ErrSkipVerifyRefused
	}
	cfg := &tls.Config{
		ServerName: opts.ServerName,
		MinVersion: tls.VersionTLS12,
	}
	var warning string
	if opts.SkipVerify {
		cfg.InsecureSkipVerify = true
		warning = "AD TLS certificate verification is disabled (insecure_skip_verify); do not use this outside a lab"
	}
	if len(bytesTrim(opts.CAPEM)) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(opts.CAPEM) {
			return Plan{}, fmt.Errorf("AD CA bundle is not valid PEM")
		}
		cfg.RootCAs = pool
	}
	return Plan{Config: cfg, Warning: warning}, nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
