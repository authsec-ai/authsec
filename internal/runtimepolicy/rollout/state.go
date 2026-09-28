// Package rollout maps collector receipts onto the §15.2 control states and
// the publication target states.
//
// Control states, the spec's exact list: requested, supported, staged,
// active, verified, degraded, failed, unsupported.
//
// Target states add the rollout vocabulary used by GET /rollouts: pending,
// delivered, rolled_back. delivered maps onto staged. A target is protected
// only when every required control is verified on the current delivery revision.
package rollout

import "strings"

const (
	Requested   = "requested"
	Supported   = "supported"
	Staged      = "staged"
	Active      = "active"
	Verified    = "verified"
	Degraded    = "degraded"
	Failed      = "failed"
	Unsupported = "unsupported"

	Pending    = "pending"
	Delivered  = "delivered"
	RolledBack = "rolled_back"
	Paused     = "paused"
)

// ControlStates is the §15.2 list, in spec order.
func ControlStates() []string {
	return []string{Requested, Supported, Staged, Active, Verified, Degraded, Failed, Unsupported}
}

// TargetStates is the rollout list reported per target.
func TargetStates() []string {
	return []string{Pending, Delivered, Staged, Active, Verified, Degraded, Failed, Unsupported, RolledBack, Paused}
}

// Control is one reported control.
type Control struct {
	Kind  string
	State string
}

// MapControlState maps a reported state onto §15.2.
// Unknown states become unsupported. rolled_back is a target state, not a
// control success, so a control reported that way is failed.
func MapControlState(reported string) string {
	switch strings.ToLower(strings.TrimSpace(reported)) {
	case Requested, "received":
		return Requested
	case Supported:
		return Supported
	case Staged, Delivered:
		return Staged
	case Active, "applying":
		return Active
	case Verified:
		return Verified
	case Degraded:
		return Degraded
	case Failed, "rejected", RolledBack:
		return Failed
	case Unsupported:
		return Unsupported
	case Pending:
		return Requested
	default:
		return Unsupported
	}
}

// Class maps a receipt kind onto a required-control name.
func Class(kind string) string {
	k := strings.ToLower(kind)
	switch {
	case k == "filesystem" || strings.Contains(k, "file"):
		return "filesystem"
	case k == "egress" || strings.Contains(k, "egress") || strings.Contains(k, "netns") || strings.Contains(k, "nft"):
		return "egress"
	case k == "exec" || strings.Contains(k, "exec") || strings.Contains(k, "priv"):
		return "exec"
	case k == "secret" || strings.Contains(k, "secret") || strings.Contains(k, "broker"):
		return "secret"
	case k == "admission" || strings.Contains(k, "admission"):
		return "admission"
	default:
		return k
	}
}

// Protected reports whether every required control has a verified receipt.
func Protected(required []string, controls []Control) bool {
	if len(required) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, c := range controls {
		if MapControlState(c.State) == Verified {
			have[Class(c.Kind)] = true
		}
	}
	for _, req := range required {
		if !have[Class(req)] {
			return false
		}
	}
	return true
}

// TargetState is the aggregate for one target with no receipt yet, or from
// its latest receipt. phase is the publication rollout phase.
func TargetState(phase, receiptState string, required []string, controls []Control) string {
	switch phase {
	case Paused:
		if receiptState == "" {
			return Paused
		}
	case RolledBack:
		return RolledBack
	}
	if strings.EqualFold(receiptState, RolledBack) {
		return RolledBack
	}
	if len(controls) == 0 && receiptState == "" {
		return Pending
	}
	if Protected(required, controls) {
		return Verified
	}
	mapped := MapControlState(receiptState)
	if receiptState == "" {
		mapped = ""
	}
	worst := mapped
	rank := map[string]int{Failed: 5, Unsupported: 4, Degraded: 3, Requested: 2, Staged: 1, Active: 1, Verified: 0}
	for _, c := range controls {
		st := MapControlState(c.State)
		if rank[st] > rank[worst] {
			worst = st
		}
	}
	switch worst {
	case Failed:
		return Failed
	case Unsupported:
		return Unsupported
	case Degraded:
		return Degraded
	case Staged, Active:
		return worst
	case "":
		return Pending
	default:
		if strings.EqualFold(receiptState, Delivered) {
			return Delivered
		}
		return Pending
	}
}
