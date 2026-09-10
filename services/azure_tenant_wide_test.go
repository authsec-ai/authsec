package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azureonboard"
)

// The tenant-wide Reader grant is one role assignment at the tenant root
// management group instead of one per subscription. It covers subscriptions
// created later, which is the whole reason it exists -- nobody has to come back
// and repeat a portal click path every time the business adds a subscription.
//
// It is also the only thing in this codebase that can briefly hold the widest
// role in Azure RBAC. Reaching the root scope can require raising the operator's
// own account to root User Access Administrator, and that privilege DOES NOT
// EXPIRE: if it is not handed back, it stays. So two properties are asserted
// here far more carefully than the happy path:
//
//   - it happens only when an operator asked for it, never by inference;
//   - whether the privilege came back is reported, loudly, either way.

// Nothing infers the tenant-wide path. A run that did not ask for it must reach
// for subscriptions, and must not touch the elevation API at all.
func TestTenantWide_IsNeverChosenByDefault(t *testing.T) {
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:    []azureonboard.Subscription{sub(subA, "Production")},
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.runWide(t, false)

	if st.TenantWide {
		t.Fatal("status claims tenant-wide on a run that did not ask for it")
	}
	if st.Elevation != nil {
		t.Fatalf("elevation reported on a per-subscription run: %+v", st.Elevation)
	}
	for _, forbidden := range []string{"elevate", "rootElevation", "delete"} {
		if strings.Contains(c.seq(), forbidden) {
			t.Errorf("called %q without being asked: %s", forbidden, c.seq())
		}
	}
	if !strings.Contains(c.seq(), "assign:/subscriptions/"+subA) {
		t.Errorf("did not assign per subscription: %s", c.seq())
	}
}

// Asked for, and the operator already holds the privilege: one assignment at the
// root management group, and the elevation API is never touched.
func TestTenantWide_AlreadyPrivilegedAssignsOnceAndNeverElevates(t *testing.T) {
	rootScope := azureonboard.RootManagementGroupScope(testTenant)
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:    []azureonboard.Subscription{sub(subA, "Production"), sub(subB, "Staging")},
		assign:     ok,
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.runWide(t, true)

	if !st.TenantWide {
		t.Fatal("status does not record that this was tenant-wide")
	}
	if st.Elevation != nil {
		t.Fatalf("elevated despite the plain assignment succeeding: %+v", st.Elevation)
	}
	if got := c.seq(); !strings.Contains(got, "assign:"+rootScope) {
		t.Fatalf("did not assign at the root management group: %s", got)
	}
	// Exactly one assignment. The point of this path is that it is not N.
	if n := strings.Count(c.seq(), "assign:"); n != 1 {
		t.Fatalf("made %d assignments, want 1: %s", n, c.seq())
	}
	if st.ReaderAssigned != 1 || st.ReaderFailed != 0 {
		t.Fatalf("counts wrong: %+v", st)
	}

	// The subscription count comes from what the APPLICATION can read after the
	// grant -- not from the assignment, which is one grant at a scope that is
	// not a subscription at all.
	//
	// Leaving it at zero is what the console rendered as "Subscriptions found
	// none visible" on a real run that had just made five of them readable.
	if st.Subscriptions != len(c.appSubs) {
		t.Errorf("Subscriptions = %d, want %d -- the count must come from what the "+
			"application can read", st.Subscriptions, len(c.appSubs))
	}
	if !st.ARMReaderOK {
		t.Errorf("ARM should have verified: %v", st.Problems)
	}
}

// Asked for, privilege not held: elevate, assign, and GIVE IT BACK. The order is
// the safety argument, so the order is what is asserted.
func TestTenantWide_ElevatesThenReturnsThePrivilege(t *testing.T) {
	granted := false
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:  []azureonboard.Subscription{sub(subA, "Production")},
		assign: func(scope string) azureonboard.AssignmentResult {
			if !granted {
				return denied(scope)
			}
			return ok(scope)
		},
		elevate: func() error { granted = true; return nil },
		rootElev: func() (string, error) {
			if !granted {
				// Nobody else's elevation is in the way.
				return "", nil
			}
			return testElevID, nil
		},
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.runWide(t, true)

	// The call ORDER is TestTenantWide_ElevatesRetriesAndRemoves's job -- it
	// owns the primitive. What is unique here is that the chain surfaces the
	// raise in its status, which is the only place an operator will see it.
	if st.Elevation == nil {
		t.Fatal("a privilege raise happened and was not reported")
	}
	if !st.Elevation.Elevated {
		t.Errorf("elevation not recorded as elevated: %+v", st.Elevation)
	}
	if !st.Elevation.Removed {
		t.Errorf("privilege was not given back: %+v", st.Elevation)
	}
	if st.ReaderAssigned != 1 {
		t.Errorf("Reader not assigned: %+v", st)
	}
	// And the count still comes from the application's own view, not from the
	// single root-scope assignment.
	if st.Subscriptions != len(c.appSubs) {
		t.Errorf("Subscriptions = %d, want %d", st.Subscriptions, len(c.appSubs))
	}
	// Nothing alarming to say when it was returned cleanly.
	for _, p := range st.Problems {
		if strings.Contains(p, "STILL ROOT USER ACCESS ADMINISTRATOR") {
			t.Errorf("warned about a privilege that was returned: %q", p)
		}
	}
}

// Raised and NOT returned. This is the one outcome that needs a human, because
// root User Access Administrator does not expire -- so it must be impossible to
// miss in the status.
func TestTenantWide_UnreturnedPrivilegeIsReportedLoudly(t *testing.T) {
	granted := false
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:  []azureonboard.Subscription{sub(subA, "Production")},
		assign: func(scope string) azureonboard.AssignmentResult {
			if !granted {
				return denied(scope)
			}
			return ok(scope)
		},
		elevate: func() error { granted = true; return nil },
		rootElev: func() (string, error) {
			if !granted {
				return "", nil
			}
			return testElevID, nil
		},
		// The removal fails. Azure kept the privilege.
		deleteRole: func(string) error { return errors.New("network went away") },
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.runWide(t, true)

	if st.Elevation == nil || !st.Elevation.Elevated {
		t.Fatalf("elevation not reported: %+v", st.Elevation)
	}
	if st.Elevation.Removed {
		t.Fatal("removal failed and yet is reported as done -- this is the dangerous lie")
	}

	joined := strings.Join(st.Problems, " | ")
	if !strings.Contains(joined, "STILL ROOT USER ACCESS ADMINISTRATOR") {
		t.Fatalf("an unreturned root privilege was not surfaced: %q", joined)
	}
	// And it must say how to undo it by hand.
	if !strings.Contains(joined, "Access management for Azure resources") {
		t.Fatalf("no instructions for removing it: %q", joined)
	}
}

// Azure refuses to elevate -- the operator is not a Global Administrator -- and
// the run must not claim otherwise.
//
// Deliberately narrow. That a partial run still finishes, fails ARM and passes
// Graph is TestAutoSetup_ReportsTheHalfThatWorked's job, and asserting it again
// here only means two tests break when one thing changes. What is unique to this
// case is the pair below: nothing was taken, so nothing may be reported as taken
// and nothing may be reported as owed back.
func TestTenantWide_RefusedElevationIsNotReportedAsTaken(t *testing.T) {
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:    nil, // nothing readable, because nothing was granted
		assign:     denied,
		elevate:    func() error { return azureonboard.ErrNotGlobalAdmin },
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.runWide(t, true)

	if st.Elevation != nil && st.Elevation.Elevated {
		t.Errorf("claims to have elevated when Azure refused: %+v", st.Elevation)
	}
	if strings.Contains(strings.Join(st.Problems, " "), "STILL ROOT USER ACCESS") {
		t.Error("warned about a privilege that was never taken")
	}
}

// An elevation this code did not create is never removed. Someone else may be
// relying on it, and taking it away would be an unrelated privilege change made
// silently.
func TestTenantWide_PreexistingElevationIsLeftAlone(t *testing.T) {
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:  []azureonboard.Subscription{sub(subA, "Production")},
		assign:   denied,
		// Already held before this run.
		rootElev:   func() (string, error) { return testElevID, nil },
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.runWide(t, true)

	// That it neither elevates nor deletes is
	// TestTenantWide_PreexistingElevationIsNeverRemoved's job. This one is about
	// the chain reporting it.
	if st.Elevation == nil || !st.Elevation.AlreadyHeld {
		t.Fatalf("did not report the pre-existing elevation: %+v", st.Elevation)
	}
	if st.Elevation.Removed {
		t.Error("claims to have removed a privilege that was not ours")
	}
}
