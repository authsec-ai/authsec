package services

import "sync/atomic"

// Ownership mode (decision, Aditya, 2026-10-13): the workspace admin owns
// everything. In admin mode there are no owner reviews, owner notices, owner
// rules or missing_owner findings; the owner gate passes. The owner tables,
// routes and code stay in place, unused, so "owners" mode brings the flow
// back unchanged.
//
// cmd/main.go sets admin mode at startup. The process default before that is
// owners, so library callers and the existing R1a tests keep the owner flow.
const (
	GovOwnershipAdmin  = "admin"
	GovOwnershipOwners = "owners"
)

var govOwnershipOff atomic.Bool

// GovOwnershipEnabled reports whether the owner flow runs (owners mode).
func GovOwnershipEnabled() bool { return !govOwnershipOff.Load() }

// SetGovOwnershipMode sets the mode and returns a function restoring the
// previous one (tests).
func SetGovOwnershipMode(mode string) (restore func()) {
	prev := govOwnershipOff.Load()
	govOwnershipOff.Store(mode == GovOwnershipAdmin)
	return func() { govOwnershipOff.Store(prev) }
}
