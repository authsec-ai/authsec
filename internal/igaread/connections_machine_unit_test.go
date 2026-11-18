package igaread

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// A machine (authsec-cli daemon, discovery source vm_sensor) is a connection
// like a cluster: connected while it reports, never "scanned", only removable.
func TestConnMachine(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-30 * time.Second)
	old := now.Add(-2 * time.Hour)
	src := func(hb *time.Time, enabled bool) *models.DiscoverySource {
		return &models.DiscoverySource{ID: uuid.New(), DisplayName: "victus-lin", ClusterName: "victus-lin",
			Enabled: enabled, LastHeartbeatAt: hb, CreatedAt: now.Add(-time.Hour)}
	}

	c := connMachine(src(&recent, true), 3, now)
	if c.Provider != ConnProviderMachine || c.ScopeKind != "machine" || c.Name != "victus-lin" || c.NativeID != "victus-lin" {
		t.Fatalf("identity: %+v", c)
	}
	if c.Connection.State != connConnected || c.Scan.State != connScanFinished || !c.Discovery.Ready {
		t.Fatalf("reporting machine: %+v %+v %+v", c.Connection, c.Scan, c.Discovery)
	}
	if c.ScopeSummary != "3 agents" || c.Graph.State != connGraphNA || c.Coverage.State != connCovUnknown || len(c.Coverage.Gaps) != 0 {
		t.Fatalf("summary, graph, coverage: %q %+v %+v", c.ScopeSummary, c.Graph, c.Coverage)
	}
	if c.Scan.ReportsEverySeconds == nil || *c.Scan.ReportsEverySeconds != 60 || c.Scan.HeartbeatAt == nil {
		t.Fatalf("report cadence: %+v", c.Scan)
	}
	if c.Capabilities != (ConnectionCapabilities{Revoke: true}) {
		t.Fatalf("capabilities: %+v", c.Capabilities)
	}

	c = connMachine(src(nil, true), 0, now)
	if c.Connection.State != connNotVerified || *c.Connection.ReasonCode != connReasonNoHeartbeat ||
		c.Scan.State != connScanNever || c.Discovery.Ready || c.ScopeSummary != "no agents yet" {
		t.Fatalf("never reported: %+v %+v %+v %q", c.Connection, c.Scan, c.Discovery, c.ScopeSummary)
	}

	c = connMachine(src(&old, true), 1, now)
	if c.Connection.State != connNotVerified || *c.Connection.ReasonCode != connReasonHeartbeatLost || !c.Discovery.Ready || c.ScopeSummary != "1 agent" {
		t.Fatalf("stopped reporting: %+v %+v %q", c.Connection, c.Discovery, c.ScopeSummary)
	}

	c = connMachine(src(&recent, false), 1, now)
	if c.Connection.State != connRevoked {
		t.Fatalf("disabled: %+v", c.Connection)
	}
}
