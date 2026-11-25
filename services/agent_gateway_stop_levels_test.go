package services

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Each containment level maps to what the gateway refuses: identity-wide
// levels refuse the identity and its workloads, a gateway stop refuses the
// named caller, and the narrower cloud-side levels refuse nothing at the
// gateway (they must not widen into an identity-wide refusal).
func TestContainmentGatewayStopsPerLevel(t *testing.T) {
	ident := uuid.New()
	wl := uuid.New().String()
	workloadsOf := map[uuid.UUID][]string{ident: {wl}}
	row := func(level, target string) containmentStopRow {
		return containmentStopRow{ID: uuid.New(), IdentityID: ident, Level: level, Target: target}
	}
	for _, lvl := range []string{agentcontain.LevelIdentity, agentcontain.LevelEntra, agentcontain.LevelKubernetes} {
		got := containmentGatewayStops([]containmentStopRow{row(lvl, "")}, workloadsOf)
		if len(got) != 2 || got[0].Selector.IdentityID != ident.String() || got[1].Selector.WorkloadID != wl || got[0].Kind != "" {
			t.Fatalf("%s: %+v", lvl, got)
		}
	}
	if got := containmentGatewayStops([]containmentStopRow{row(agentcontain.LevelModel, "")}, workloadsOf); len(got) != 2 || got[0].Kind != agentgateway.KindModel {
		t.Fatalf("model: %+v", got)
	}
	w := row(agentcontain.LevelWorkload, "")
	w.WorkloadIDs = pq.StringArray{"ABC"}
	if got := containmentGatewayStops([]containmentStopRow{w}, workloadsOf); len(got) != 1 || got[0].Selector.WorkloadID != "abc" {
		t.Fatalf("workload: %+v", got)
	}
	if got := containmentGatewayStops([]containmentStopRow{row(agentcontain.LevelGateway, " spiffe://td/agent ")}, workloadsOf); len(got) != 1 ||
		got[0].Selector.ClientID != "spiffe://td/agent" || got[0].Selector.IdentityID != "" {
		t.Fatalf("gateway with target: %+v", got)
	}
	if got := containmentGatewayStops([]containmentStopRow{row(agentcontain.LevelGateway, "")}, workloadsOf); len(got) != 2 || got[0].Selector.IdentityID != ident.String() {
		t.Fatalf("gateway without target: %+v", got)
	}
	for _, lvl := range []string{agentcontain.LevelKey, agentcontain.LevelSessionsBefore, agentcontain.LevelChain,
		agentcontain.LevelSourceIdentity, agentcontain.LevelPlatform} {
		if got := containmentGatewayStops([]containmentStopRow{row(lvl, "AKIAEXAMPLE")}, workloadsOf); len(got) != 0 {
			t.Fatalf("%s must not stop anything at the gateway: %+v", lvl, got)
		}
	}
}
