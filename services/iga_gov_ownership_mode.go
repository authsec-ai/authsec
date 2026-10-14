package services

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// Ownership mode (decision, Aditya, 2026-10-13): the workspace admin owns
// everything. In admin mode there are no owner reviews, owner notices, owner
// rules or missing_owner findings; the owner gate passes. The owner tables,
// routes and code stay in place, unused, so "owners" mode brings the flow
// back unchanged.
//
// The process default is owners, so library callers and the existing tests
// keep the Phase 3 R1a behaviour; cmd/main.go sets the mode from
// IGA_POLICY_OWNERSHIP (admin when unset).
const (
	GovOwnershipAdmin  = "admin"
	GovOwnershipOwners = "owners"
	GovOwnershipEnv    = "IGA_POLICY_OWNERSHIP"
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

// GovOwnershipModeFromEnv reads IGA_POLICY_OWNERSHIP: admin (default) or
// owners. Any other value is an error, never silently one or the other.
func GovOwnershipModeFromEnv() (string, error) {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(GovOwnershipEnv)))
	switch v {
	case "", GovOwnershipAdmin:
		return GovOwnershipAdmin, nil
	case GovOwnershipOwners:
		return GovOwnershipOwners, nil
	}
	return GovOwnershipAdmin, fmt.Errorf("%s=%q: want admin or owners; using admin", GovOwnershipEnv, v)
}
