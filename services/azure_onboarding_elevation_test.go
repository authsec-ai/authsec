package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
)

// The tenant-wide reader path can briefly hold the widest role in Azure RBAC.
// Its safety is entirely a property of the ORDER in which it acts, and order is
// invisible to a reader of the result -- a run that elevated when it should not
// have looks identical to one that did the right thing. So these tests assert
// the call sequence itself, not just the outcome.

/* --------------------------------- the fake --------------------------------- */

// fakeAzureClient records the sequence of Microsoft calls and lets each one be
// scripted. Only the methods the tenant-wide path uses are meaningful; the rest
// exist to satisfy azureonboard.Client.
type fakeAzureClient struct {
	assign      func(scope string) azureonboard.AssignmentResult
	elevate     func() error
	rootElev    func() (string, error)
	deleteRole  func(id string) error
	calls       []string
	deletedIDs  []string
	assignedSco []string
}

func (f *fakeAzureClient) record(s string) { f.calls = append(f.calls, s) }

func (f *fakeAzureClient) AssignRole(
	_ context.Context, _, scope, _, _ string,
) azureonboard.AssignmentResult {
	f.record("assign")
	f.assignedSco = append(f.assignedSco, scope)
	if f.assign != nil {
		return f.assign(scope)
	}
	return azureonboard.AssignmentResult{Scope: scope, Error: "unscripted"}
}

func (f *fakeAzureClient) ElevateAccess(_ context.Context, _ string) error {
	f.record("elevate")
	if f.elevate != nil {
		return f.elevate()
	}
	return nil
}

func (f *fakeAzureClient) RootElevation(_ context.Context, _, _ string) (string, error) {
	f.record("rootElevation")
	if f.rootElev != nil {
		return f.rootElev()
	}
	return "", nil
}

func (f *fakeAzureClient) DeleteRoleAssignment(_ context.Context, _, id string) error {
	f.record("delete")
	f.deletedIDs = append(f.deletedIDs, id)
	if f.deleteRole != nil {
		return f.deleteRole(id)
	}
	return nil
}

// Unused by this path.
func (f *fakeAzureClient) ExchangeCode(context.Context, string, string) (*azureonboard.TokenSet, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) Refresh(context.Context, string) (*azureonboard.TokenSet, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) ClientCredentials(context.Context, string) (*azureonboard.TokenSet, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) RefreshForTenant(context.Context, string, string) (*azureonboard.TokenSet, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) GraphToken(context.Context, string) (*azureonboard.TokenSet, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) ListTenants(context.Context, string) ([]azureonboard.Tenant, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) ListSubscriptions(context.Context, string) ([]azureonboard.Subscription, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) ProbeGraphCapabilities(context.Context, string) []azureonboard.GraphCapability {
	return nil
}
func (f *fakeAzureClient) ReadOwnApp(context.Context, string, string) (*azureonboard.AppRegistration, error) {
	return nil, errors.New("not used")
}
func (f *fakeAzureClient) ResolveSignInName(context.Context, string, string) (*azureonboard.SignInName, error) {
	return nil, errors.New("not used")
}

/* -------------------------------- harness -------------------------------- */

const (
	testTenant    = "11111111-1111-1111-1111-111111111111"
	testPrincipal = "22222222-2222-2222-2222-222222222222"
	testOperator  = "33333333-3333-3333-3333-333333333333"
	testElevID    = "/providers/Microsoft.Authorization/roleAssignments/44444444-4444-4444-4444-444444444444"
)

// run drives the tenant-wide path against a fake, with the propagation backoff
// shrunk so the retries do not cost 29 real seconds.
func run(t *testing.T, f *fakeAzureClient) *AssignReaderResult {
	t.Helper()
	allowRootElevation(t)

	restore := armPropagationBackoff
	armPropagationBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { armPropagationBackoff = restore })

	// Only the Microsoft client is needed: this path touches no database, and
	// readerSetup is pure.
	svc := &AzureOnboardService{azure: f}

	return svc.assignReaderTenantWide(
		context.Background(), testTenant,
		&azureonboard.TokenSet{AccessToken: "user", PrincipalObjectID: testOperator},
		&azureonboard.TokenSet{AccessToken: "app", PrincipalObjectID: testPrincipal},
		testPrincipal,
	)
}

func ok(scope string) azureonboard.AssignmentResult {
	return azureonboard.AssignmentResult{Scope: scope, OK: true}
}

func denied(scope string) azureonboard.AssignmentResult {
	return azureonboard.AssignmentResult{Scope: scope, Error: "AuthorizationFailed"}
}

func seq(f *fakeAzureClient) string { return strings.Join(f.calls, ",") }

/* --------------------------------- tests --------------------------------- */

// The privilege the operator already has must be tried first, and must be
// enough on its own. An operator who can already do this is never elevated.
func TestTenantWide_AlreadyPrivileged_NeverElevates(t *testing.T) {
	f := &fakeAzureClient{assign: ok}
	res := run(t, f)

	if got := seq(f); got != "assign" {
		t.Fatalf("expected a single assign and nothing else, got %q", got)
	}
	if !res.AllOK || !res.TenantWide {
		t.Fatalf("expected a successful tenant-wide grant, got %+v", res)
	}
	if res.Elevation != nil {
		t.Fatalf("elevation must not even be attempted when the plain assign works: %+v", res.Elevation)
	}
	if res.Fallback != nil {
		t.Fatal("no fallback should be attached to a success")
	}
	want := azureonboard.RootManagementGroupScope(testTenant)
	if res.Assigned[0].Scope != want {
		t.Fatalf("expected the root management group scope %q, got %q", want, res.Assigned[0].Scope)
	}
}

// The ordinary path: refused, nobody else's elevation in the way, elevate,
// retry, succeed, and give it back.
func TestTenantWide_ElevatesRetriesAndRemoves(t *testing.T) {
	attempt := 0
	granted := false
	f := &fakeAzureClient{
		assign: func(scope string) azureonboard.AssignmentResult {
			attempt++
			if attempt == 1 {
				return denied(scope)
			}
			return ok(scope)
		},
		// Absent before elevateAccess, present the moment it returns -- what ARM
		// does. The second lookup is the id being captured while we still know
		// for certain that a grant exists.
		rootElev: func() (string, error) {
			if granted {
				return testElevID, nil
			}
			return "", nil
		},
	}
	f.elevate = func() error { granted = true; return nil }

	res := run(t, f)

	if got := seq(f); got != "assign,rootElevation,elevate,rootElevation,assign,delete" {
		t.Fatalf("wrong call sequence: %q", got)
	}
	if !res.AllOK {
		t.Fatalf("expected success after elevating, got %+v", res)
	}
	el := res.Elevation
	if el == nil || !el.Attempted || !el.Elevated || !el.Removed {
		t.Fatalf("expected attempted+elevated+removed, got %+v", el)
	}
	if el.Error != "" {
		t.Fatalf("expected no error on a clean run, got %q", el.Error)
	}
	if len(f.deletedIDs) != 1 || f.deletedIDs[0] != testElevID {
		t.Fatalf("expected exactly the elevation to be deleted, got %v", f.deletedIDs)
	}
}

// The safety test. An elevation that was already there belongs to somebody
// else's decision. Removing it would revoke standing access AuthSec never
// granted -- so this path must not elevate and must not delete.
func TestTenantWide_PreexistingElevationIsNeverRemoved(t *testing.T) {
	f := &fakeAzureClient{
		assign:   denied,
		rootElev: func() (string, error) { return testElevID, nil },
	}
	res := run(t, f)

	if got := seq(f); got != "assign,rootElevation" {
		t.Fatalf("must stop after finding a pre-existing elevation, got %q", got)
	}
	if len(f.deletedIDs) != 0 {
		t.Fatalf("deleted an elevation it did not create: %v", f.deletedIDs)
	}
	el := res.Elevation
	if el == nil || !el.AlreadyHeld || el.Elevated {
		t.Fatalf("expected already_held and not elevated, got %+v", el)
	}
	if res.AllOK || res.Fallback == nil {
		t.Fatal("a refusal must report failure and attach the manual instructions")
	}
}

// Most operators are not Global Administrators. That is a clean refusal, not an
// error condition -- and nothing must be deleted on the way out.
func TestTenantWide_NotGlobalAdmin_FallsBackCleanly(t *testing.T) {
	f := &fakeAzureClient{
		assign:  denied,
		elevate: func() error { return azureonboard.ErrNotGlobalAdmin },
	}
	res := run(t, f)

	if got := seq(f); got != "assign,rootElevation,elevate" {
		t.Fatalf("wrong call sequence: %q", got)
	}
	if len(f.deletedIDs) != 0 {
		t.Fatalf("nothing was elevated, so nothing may be deleted: %v", f.deletedIDs)
	}
	el := res.Elevation
	if el == nil || el.Elevated || el.Removed {
		t.Fatalf("expected an unelevated refusal, got %+v", el)
	}
	if !strings.Contains(el.Error, "Global Administrator") {
		t.Fatalf("the error should name the missing role, got %q", el.Error)
	}
	if res.AllOK || res.Fallback == nil {
		t.Fatal("expected failure plus fallback instructions")
	}
}

// Elevation must be given back even when the thing it was raised for never
// succeeds. This is the leak that would otherwise leave a human holding root
// User Access Administrator indefinitely.
func TestTenantWide_RemovesElevationEvenWhenAssignmentNeverSucceeds(t *testing.T) {
	f := &fakeAzureClient{
		assign:   denied,
		rootElev: func() (string, error) { return testElevID, nil },
	}
	// Absent on the pre-check, present on the post-check.
	first := true
	f.rootElev = func() (string, error) {
		if first {
			first = false
			return "", nil
		}
		return testElevID, nil
	}

	res := run(t, f)

	if res.AllOK {
		t.Fatal("assignment never succeeded; result must not claim success")
	}
	el := res.Elevation
	if el == nil || !el.Elevated || !el.Removed {
		t.Fatalf("elevation must be removed on the failure path too, got %+v", el)
	}
	if len(f.deletedIDs) != 1 {
		t.Fatalf("expected exactly one delete, got %v", f.deletedIDs)
	}
	if res.Fallback == nil {
		t.Fatal("expected the manual instructions after exhausting retries")
	}
}

// Regression. A production-shaped simulation reported removed:true while root
// User Access Administrator was still assigned: the cleanup re-derived the
// assignment id from a filter, the filter matched nothing, and "not found" was
// read as "already gone".
//
// Removed:true must mean a DELETE was issued and accepted -- nothing weaker.
func TestTenantWide_LookupMissDoesNotCountAsRemoved(t *testing.T) {
	attempt := 0
	f := &fakeAzureClient{
		assign: func(scope string) azureonboard.AssignmentResult {
			attempt++
			if attempt == 1 {
				return denied(scope)
			}
			return ok(scope)
		},
		// Never finds the elevation -- as happens when the lookup filters on the
		// wrong principal, which is exactly what the simulation did.
		rootElev: func() (string, error) { return "", nil },
	}
	res := run(t, f)

	el := res.Elevation
	if el == nil || !el.Elevated {
		t.Fatalf("expected an elevation to have happened, got %+v", el)
	}
	if el.Removed {
		t.Fatal("nothing was deleted, so Removed must be false -- this is the bug")
	}
	if len(f.deletedIDs) != 0 {
		t.Fatalf("nothing could be located, so nothing should be deleted: %v", f.deletedIDs)
	}
	if !strings.Contains(el.Error, "no matching assignment could be found") {
		t.Fatalf("the operator must be told the role may still be assigned, got %q", el.Error)
	}
}

// When removal itself fails there is nothing more the code can do, so the one
// thing it owes the operator is an unmissable message naming the manual fix.
func TestTenantWide_FailedRemovalIsReportedLoudly(t *testing.T) {
	first := true
	f := &fakeAzureClient{
		assign: ok,
		rootElev: func() (string, error) {
			if first {
				first = false
				return "", nil
			}
			return testElevID, nil
		},
		deleteRole: func(string) error { return errors.New("network unreachable") },
	}
	// Force the elevation path: refuse the first assign, accept the second.
	attempt := 0
	f.assign = func(scope string) azureonboard.AssignmentResult {
		attempt++
		if attempt == 1 {
			return denied(scope)
		}
		return ok(scope)
	}

	res := run(t, f)

	el := res.Elevation
	if el == nil || !el.Elevated {
		t.Fatalf("expected an elevation to have happened, got %+v", el)
	}
	if el.Removed {
		t.Fatal("removal failed, so Removed must be false")
	}
	if !strings.Contains(el.Error, "FAILED to remove") ||
		!strings.Contains(el.Error, "Access management for Azure resources") {
		t.Fatalf("the error must name the manual fix, got %q", el.Error)
	}
	// The grant itself did succeed, and that stays true.
	if !res.AllOK {
		t.Fatal("a failed cleanup must not retroactively fail the grant")
	}
}

// allowRootElevation turns on the deployment switch that permits raising the
// operator to root User Access Administrator.
//
// It is off in production until the path has been exercised against a real
// tenant, so every test that drives the elevation has to ask for it. A test
// that forgets exercises the gate instead of the thing it meant to test, and
// says so loudly rather than passing for the wrong reason.
func allowRootElevation(t *testing.T) {
	t.Helper()
	t.Setenv(azureAllowRootElevationEnv, "true")
}

// With the switch OFF -- the shipping default -- a refused assignment must not
// elevate anything, must say why, and must hand back the manual instructions.
func TestTenantWide_ElevationIsOffUnlessTheDeploymentAllowsIt(t *testing.T) {
	t.Setenv(azureAllowRootElevationEnv, "")

	f := &fakeAzureClient{assign: denied}
	svc := &AzureOnboardService{azure: f}
	res := svc.assignReaderTenantWide(
		context.Background(), testTenant,
		&azureonboard.TokenSet{AccessToken: "user", PrincipalObjectID: testOperator},
		&azureonboard.TokenSet{AccessToken: "app", PrincipalObjectID: testPrincipal},
		testPrincipal,
	)

	// One attempt with the privilege the operator already has, and nothing else.
	if got := seq(f); got != "assign" {
		t.Fatalf("calls = %q; with elevation disabled nothing beyond the plain assign may run", got)
	}
	if res.Elevation == nil {
		t.Fatal("the refusal must still be explained")
	}
	if res.Elevation.Attempted || res.Elevation.Elevated {
		t.Fatalf("elevated with the switch off: %+v", res.Elevation)
	}
	if !strings.Contains(res.Elevation.Error, azureAllowRootElevationEnv) {
		t.Errorf("does not name the switch that would enable it: %q", res.Elevation.Error)
	}
	// An operator who cannot be elevated still needs a way forward.
	if res.Fallback == nil {
		t.Error("no fallback instructions were attached")
	}
	if res.AllOK {
		t.Error("reported success having granted nothing")
	}
}

// And with it on, the elevation happens -- so the gate is the only difference.
func TestTenantWide_ElevationRunsWhenAllowed(t *testing.T) {
	allowRootElevation(t)

	f := &fakeAzureClient{assign: denied}
	svc := &AzureOnboardService{azure: f}
	svc.assignReaderTenantWide(
		context.Background(), testTenant,
		&azureonboard.TokenSet{AccessToken: "user", PrincipalObjectID: testOperator},
		&azureonboard.TokenSet{AccessToken: "app", PrincipalObjectID: testPrincipal},
		testPrincipal,
	)
	if !strings.Contains(seq(f), "elevate") {
		t.Fatalf("the switch is on and nothing elevated: %q", seq(f))
	}
}

// An ElevateAccess error and a failed elevation are not the same thing.
//
// The call is a write. A timeout, a reset, or a 5xx after ARM applied it all
// return an error while leaving the operator holding root User Access
// Administrator. This path used to return immediately on any error -- before
// the removal defer was registered -- so nothing ever took it back, and the
// status said elevated:false while the privilege was live.
func TestTenantWide_AmbiguousElevationFailureIsStillGivenBack(t *testing.T) {
	const strayID = "/providers/Microsoft.Authorization/roleAssignments/stray"

	// First lookup (step 2, "does one already exist?") finds nothing, which is
	// what lets the flow proceed. The second, after the failed elevate, finds
	// the elevation that applied anyway.
	lookups := 0
	f := &fakeAzureClient{
		assign:  denied,
		elevate: func() error { return errors.New("Post \"https://management.azure.com/...\": EOF") },
		rootElev: func() (string, error) {
			lookups++
			if lookups == 1 {
				return "", nil
			}
			return strayID, nil
		},
	}
	res := run(t, f)

	if got := seq(f); got != "assign,rootElevation,elevate,rootElevation,delete" {
		t.Fatalf("the elevation was not looked for or not removed: %q", got)
	}
	if len(f.deletedIDs) != 1 || f.deletedIDs[0] != strayID {
		t.Fatalf("wrong assignment deleted: %v", f.deletedIDs)
	}

	el := res.Elevation
	if el == nil {
		t.Fatal("no elevation outcome reported")
	}
	if !el.Elevated {
		t.Error("reported elevated:false while an elevation had in fact applied -- " +
			"the exact claim that made this invisible")
	}
	if !el.Removed {
		t.Error("the elevation that applied was not reported as removed")
	}
	if !strings.Contains(el.Error, "applied despite the error") {
		t.Errorf("the outcome does not say what happened: %q", el.Error)
	}
}

// ErrNotGlobalAdmin is a clean refusal: ARM applied nothing, so looking is
// wasted work and deleting would be wrong. Guards against a fix that probes
// after every failure.
func TestTenantWide_CleanRefusalIsNotProbedForAStrayElevation(t *testing.T) {
	lookups := 0
	f := &fakeAzureClient{
		assign:   denied,
		elevate:  func() error { return azureonboard.ErrNotGlobalAdmin },
		rootElev: func() (string, error) { lookups++; return "", nil },
	}
	run(t, f)

	if lookups != 1 {
		t.Errorf("looked for an elevation %d times after a refusal that provably "+
			"applied nothing; want 1 (the pre-flight check only)", lookups)
	}
	if len(f.deletedIDs) != 0 {
		t.Errorf("deleted something after a clean refusal: %v", f.deletedIDs)
	}
}

// If the read-back itself fails, the operator has to be told to go and look --
// silently reporting a clean failure would hide a privilege that may be live.
func TestTenantWide_UnconfirmableElevationSaysToCheckByHand(t *testing.T) {
	lookups := 0
	f := &fakeAzureClient{
		assign:  denied,
		elevate: func() error { return errors.New("EOF") },
		rootElev: func() (string, error) {
			lookups++
			if lookups == 1 {
				return "", nil
			}
			return "", errors.New("ARM unreachable")
		},
	}
	res := run(t, f)

	el := res.Elevation
	if el == nil {
		t.Fatal("no elevation outcome reported")
	}
	if !strings.Contains(el.Error, "remove it by hand") {
		t.Errorf("does not tell the operator to check: %q", el.Error)
	}
	if el.Elevated {
		t.Error("claimed the elevation applied when that could not be established")
	}
}
