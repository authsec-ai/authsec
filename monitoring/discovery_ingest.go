package monitoring

import (
	"errors"
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// discoveryIngestAuthEnforced is 1 when the discovery ingress refuses calls
// without a valid ingest token (IGA_DISCOVERY_INGEST_AUTH=enforce) and 0 in off
// or warn, labelled with the mode. One series at a time. Alert on
// `discovery_ingest_auth_enforced == 0`: warn is a rollout stage, not a
// protected ingress.
var (
	discoveryIngestAuthEnforced = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "discovery_ingest_auth_enforced",
		Help: "1 when the discovery ingress enforces ingest tokens (IGA_DISCOVERY_INGEST_AUTH=enforce), 0 in off or warn; labelled with the mode.",
	}, []string{"mode"})
	discoveryIngestAuthRegister sync.Once
)

// SetDiscoveryIngestAuthMode publishes the ingress auth mode as
// discovery_ingest_auth_enforced. It registers the gauge with the default
// registry (what /authsec/metrics serves) on first use, so it does not depend
// on InitMetrics having run.
func SetDiscoveryIngestAuthMode(mode string, enforced bool) {
	discoveryIngestAuthRegister.Do(func() {
		if err := prometheus.Register(discoveryIngestAuthEnforced); err != nil {
			var are prometheus.AlreadyRegisteredError
			if !errors.As(err, &are) {
				log.Printf("could not register discovery_ingest_auth_enforced: %v", err)
			}
		}
	})
	discoveryIngestAuthEnforced.Reset()
	v := 0.0
	if enforced {
		v = 1
	}
	discoveryIngestAuthEnforced.WithLabelValues(mode).Set(v)
}
