package services

import "github.com/authsec-ai/authsec/models"

// AllowsAuthoritativeUse reports whether evidence at this trust level may drive
// v2 policy generation, an authoritative graph edge, an ownership claim or an
// enrollment credential. unverified_legacy never may. The unauthenticated
// discovery ingress writes that value, so a forged sighting cannot cross this
// gate by choosing its own name.
func AllowsAuthoritativeUse(trust string) bool {
	switch trust {
	case models.EvidenceTrustAuthenticatedCollector, models.EvidenceTrustHumanAsserted:
		return true
	default:
		return false
	}
}

// PolicyEvidence is one candidate fact considered for v2 policy input.
type PolicyEvidence struct {
	Name  string
	Trust string
}

// SelectPolicyInputs drops evidence that is not authoritative. Callers that
// build policy, edges, ownership or enrollment credentials must use the
// returned slice and not the input.
func SelectPolicyInputs(in []PolicyEvidence) []PolicyEvidence {
	out := make([]PolicyEvidence, 0, len(in))
	for _, item := range in {
		if AllowsAuthoritativeUse(item.Trust) {
			out = append(out, item)
		}
	}
	return out
}
