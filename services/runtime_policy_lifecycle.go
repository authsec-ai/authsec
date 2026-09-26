package services

import "github.com/authsec-ai/authsec/models"

// runtimePolicyEdges is the §13.1 state machine. A6 performs the edges up
// to approved. The simulator sets simulated. Delivery owns published,
// superseded and revoked. A new draft is a new revision, not an edge back
// to draft.
var runtimePolicyEdges = map[[2]string]bool{
	{models.RuntimePolicyStateDraft, models.RuntimePolicyStateValidated}:      true,
	{models.RuntimePolicyStateValidated, models.RuntimePolicyStateSimulated}:  true,
	{models.RuntimePolicyStateSimulated, models.RuntimePolicyStateApproved}:   true,
	{models.RuntimePolicyStateApproved, models.RuntimePolicyStatePublished}:   true,
	{models.RuntimePolicyStatePublished, models.RuntimePolicyStateSuperseded}: true,
	{models.RuntimePolicyStatePublished, models.RuntimePolicyStateRevoked}:    true,
}

// RuntimePolicyTransitionAllowed reports whether a revision may move from
// one state to another. Same-state and every edge not in the table are forbidden.
func RuntimePolicyTransitionAllowed(from, to string) bool {
	return runtimePolicyEdges[[2]string{from, to}]
}
