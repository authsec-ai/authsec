package services

import (
	"fmt"

	"github.com/authsec-ai/authsec/models"
)

// RejectWorkloadAuthority refuses every basis except a human registration.
//
// The database CHECK iga_agent_instances_workload_authority_chk is the
// enforcement point: a row cannot set workload_id unless the basis is
// human_registration and the actor, owner and classification version are
// present. This function is the same rule in Go, so a writer fails before
// the insert instead of learning it from a constraint error. A candidate
// join and a weak name match both fail here, and neither is written onto
// an authoritative instance.
func RejectWorkloadAuthority(basis string) error {
	if basis == models.WorkloadLinkBasisHuman {
		return nil
	}
	return fmt.Errorf("workload authority requires %s, got %q", models.WorkloadLinkBasisHuman, basis)
}
