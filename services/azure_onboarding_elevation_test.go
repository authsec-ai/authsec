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
	f := &fakeAzureClient{
		assign: func(scope string) azureonboard.AssignmentResult {
			attempt++
			if attempt == 1 {
				return denied(scope)
			}
			return ok(scope)
		},
		rootElev: func() (string, error) {
			// Absent before elevating, present afterwards -- what ARM would say.
			if attempt >= 2 {
				return testElevID, nil
			}
			return "", nil
		},
	}
	res := run(t, f)

	if got := seq(f); got != "assign,rootElevation,elevate,assign,rootElevation,delete" {
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
