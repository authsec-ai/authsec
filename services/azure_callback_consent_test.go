package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// A connector row is a claim that a tenant granted admin consent. Everything
// downstream reads it as fact, and /api/azure/callback is unauthenticated by
// necessity -- so the conditions under which that row gets written are the
// security boundary of this feature, not an implementation detail.
//
// The automatic setup arrives at that boundary in TWO callbacks, because one
// /authorize call cannot both return an ARM code and grant Microsoft Graph
// application permissions. Leg one signs in. Leg two consents. These tests hold
// the line at each.
//
// The fakes live in azure_auto_setup_test.go.

// loginService builds a service with no seeded consent, so a row appearing is
// unambiguous.
func loginService(t *testing.T, c *chainClient) (*AzureOnboardService, *fakeRepo, uuid.UUID) {
	t.Helper()
	repo := newFakeRepo()
	svc := &AzureOnboardService{
		repo:        repo,
		vault:       newFakeVault(),
		azure:       c,
		clientID:    "test-client",
		redirectURI: "http://localhost:8080/api/azure/callback",
	}
	return svc, repo, uuid.MustParse(testWorkspaceStr)
}

func loginState(t *testing.T, auto bool) string {
	t.Helper()
	st, err := azureonboard.NewLoginState(auto, false)
	if err != nil {
		t.Fatalf("mint login state: %v", err)
	}
	return st
}

func consentState(t *testing.T, auto bool) string {
	t.Helper()
	st, err := azureonboard.NewConsentState(testTenant, auto, false)
	if err != nil {
		t.Fatalf("mint consent state: %v", err)
	}
	return st
}

/* ------------------------------- leg one ------------------------------- */

// The plain sign-in is reachable from the UNAUTHENTICATED /login route. It must
// leave nothing behind but the operator's own session -- otherwise anyone who
// can reach the deployment could sign in with a tenant of their choosing and
// file it into a workspace they hold no rights in.
func TestFinishLogin_PlainSignInNeverWritesAConnectorRow(t *testing.T) {
	c := &chainClient{exchangeTenant: testTenant}
	svc, repo, ws := loginService(t, c)

	res, err := svc.finishLogin(
		context.Background(),
		&models.AzureOAuthState{State: loginState(t, false), WorkspaceID: ws},
		// Even with Microsoft reporting a grant, a plain state must record
		// nothing: that state was not minted behind discovery:admin.
		AzureCallbackInput{Code: "code", AdminConsent: "True"},
	)
	if err != nil {
		t.Fatalf("finishLogin: %v", err)
	}

	if res.Step != "logged_in" || res.SessionID == "" {
		t.Fatalf("expected a plain sign-in, got %+v", res)
	}
	if repo.upserts != 0 {
		t.Fatalf("wrote %d connector row(s) from the unauthenticated path", repo.upserts)
	}
	if res.ConsentRedirect != "" {
		t.Fatalf("plain sign-in tried to redirect onward: %q", res.ConsentRedirect)
	}
	if res.Connector != nil || res.AutoSetup || res.AutoSetupWanted {
		t.Fatalf("plain sign-in reported consent work: %+v", res)
	}
}

// Leg one of the automatic setup records NOTHING and starts NOTHING. It has an
// ARM token and a tenant id; it does not have a grant. An earlier version wrote
// the connector row here, on the mistaken belief that prompt=admin_consent could
// merge both into one screen -- Microsoft rejects that value outright, and the
// row would have claimed a grant that never happened.
func TestFinishLogin_AutoSignInRedirectsToConsentAndWritesNothing(t *testing.T) {
	c := &chainClient{exchangeTenant: testTenant}
	svc, repo, ws := loginService(t, c)

	res, err := svc.finishLogin(
		context.Background(),
		&models.AzureOAuthState{State: loginState(t, true), WorkspaceID: ws},
		AzureCallbackInput{Code: "code"},
	)
	if err != nil {
		t.Fatalf("finishLogin: %v", err)
	}

	if repo.upserts != 0 {
		t.Fatalf("wrote a connector row before anything was consented (%d)", repo.upserts)
	}
	if res.AutoSetup {
		t.Fatal("started the chain before consent")
	}
	if res.SessionID == "" {
		t.Fatal("the session must be kept: the second leg needs it")
	}

	// It must point at the admin consent endpoint for the tenant the TOKEN
	// named, carrying a state marked as the second leg.
	if !strings.Contains(res.ConsentRedirect, "/"+testTenant+"/v2.0/adminconsent") {
		t.Fatalf("consent redirect does not name the signed-in tenant: %q", res.ConsentRedirect)
	}
	// .default is what makes admin consent grant the declared APPLICATION
	// permissions. A named delegated scope would grant something else entirely.
	if !strings.Contains(res.ConsentRedirect, "graph.microsoft.com%2F.default") {
		t.Fatalf("consent redirect does not ask for graph .default: %q", res.ConsentRedirect)
	}
	if !strings.Contains(res.ConsentRedirect, "consent%3Aauto%3A"+testTenant) {
		t.Fatalf("consent redirect state is not marked auto: %q", res.ConsentRedirect)
	}

	// And that state must be redeemable -- a redirect whose state was never
	// stored sends the operator to Microsoft for a callback that will be
	// rejected on return.
	var stored *models.AzureOAuthState
	for _, st := range repo.states {
		if azureonboard.ConsentStateAutoSetup(st.State) {
			stored = st
		}
	}
	if stored == nil {
		t.Fatal("no auto consent state was stored")
	}
	if stored.TenantID != testTenant || stored.WorkspaceID != ws {
		t.Fatalf("stored state does not match: %+v", stored)
	}
	if stored.Purpose != models.AzureOAuthPurposeConsent {
		t.Fatalf("stored state purpose = %q, want consent", stored.Purpose)
	}
}

// A token with no tid claim names no tenant. Guessing one would send an
// administrator to consent in the wrong directory.
func TestFinishLogin_AutoSignInWithNoTenantClaimGoesNowhere(t *testing.T) {
	c := &chainClient{exchangeTenant: ""}
	svc, repo, ws := loginService(t, c)

	res, err := svc.finishLogin(
		context.Background(),
		&models.AzureOAuthState{State: loginState(t, true), WorkspaceID: ws},
		AzureCallbackInput{Code: "code"},
	)
	if err != nil {
		t.Fatalf("finishLogin: %v", err)
	}
	if repo.upserts != 0 || res.ConsentRedirect != "" {
		t.Fatalf("acted on an unknown tenant: %+v", res)
	}
	if res.AutoSetupSkipped == "" {
		t.Fatal("skipped silently; the operator needs the reason")
	}
	// The session still works, so the manual path remains open.
	if res.SessionID == "" {
		t.Fatal("lost the session")
	}
}

/* ------------------------------- leg two ------------------------------- */

// The grant, as Microsoft reports it. admin_consent=True is the only value that
// means consent happened; anything else must leave no row.
func TestFinishConsent_WithoutTheGrantWritesNothing(t *testing.T) {
	for _, adminConsent := range []string{"", "False", "false", "maybe"} {
		c := &chainClient{}
		svc, repo, ws := loginService(t, c)
		state := consentState(t, true)

		_, err := svc.finishConsent(
			context.Background(),
			&models.AzureOAuthState{State: state, WorkspaceID: ws, TenantID: testTenant},
			testTenant,
			AzureCallbackInput{AdminConsent: adminConsent},
		)
		if !errors.Is(err, azureonboard.ErrConsentDenied) {
			t.Errorf("admin_consent=%q: err = %v, want ErrConsentDenied", adminConsent, err)
		}
		if repo.upserts != 0 {
			t.Errorf("admin_consent=%q: wrote a connector row anyway", adminConsent)
		}
	}
}

// The grant, with the auto marker: the row is written and the caller is told to
// start the chain. The service does not start it itself -- the chain needs the
// sign-in session id, and only a request can read the cookie carrying it.
func TestFinishConsent_AutoStateAsksTheCallerToRunTheChain(t *testing.T) {
	c := &chainClient{}
	svc, repo, ws := loginService(t, c)

	res, err := svc.finishConsent(
		context.Background(),
		&models.AzureOAuthState{State: consentState(t, true), WorkspaceID: ws, TenantID: testTenant},
		testTenant,
		AzureCallbackInput{AdminConsent: "True"},
	)
	if err != nil {
		t.Fatalf("finishConsent: %v", err)
	}
	if repo.upserts != 1 {
		t.Fatalf("connector rows written = %d, want 1", repo.upserts)
	}
	if res.Connector == nil || res.Connector.TenantID != testTenant {
		t.Fatalf("wrong tenant recorded: %+v", res.Connector)
	}
	if !res.Created {
		t.Error("a first consent should report created")
	}
	if !res.AutoSetupWanted {
		t.Fatal("an auto consent state must ask for the chain")
	}
}

// The ordinary per-tenant consent, unmarked: the row is written and nothing else
// happens. This is the path an operator uses for a tenant they do not
// administer, where Reader is somebody else's job and assigning it unasked
// would be a write nobody authorised.
func TestFinishConsent_PlainStateDoesNotRunTheChain(t *testing.T) {
	c := &chainClient{}
	svc, repo, ws := loginService(t, c)

	res, err := svc.finishConsent(
		context.Background(),
		&models.AzureOAuthState{State: consentState(t, false), WorkspaceID: ws, TenantID: testTenant},
		testTenant,
		AzureCallbackInput{AdminConsent: "True"},
	)
	if err != nil {
		t.Fatalf("finishConsent: %v", err)
	}
	if repo.upserts != 1 {
		t.Fatalf("connector rows written = %d, want 1", repo.upserts)
	}
	if res.AutoSetupWanted {
		t.Fatal("a plain consent must not trigger the chain")
	}
}

// Microsoft names the tenant on the consent callback, and it must agree with
// both of ours. A mismatch is the one case where a redirect could otherwise
// record a grant against the wrong directory.
func TestFinishConsent_RejectsATenantMismatch(t *testing.T) {
	other := "99999999-9999-9999-9999-999999999999"
	c := &chainClient{}
	svc, repo, ws := loginService(t, c)

	_, err := svc.finishConsent(
		context.Background(),
		&models.AzureOAuthState{State: consentState(t, true), WorkspaceID: ws, TenantID: testTenant},
		testTenant,
		AzureCallbackInput{AdminConsent: "True", Tenant: other},
	)
	if !errors.Is(err, azureonboard.ErrTenantMismatch) {
		t.Fatalf("err = %v, want ErrTenantMismatch", err)
	}
	if repo.upserts != 0 {
		t.Fatal("wrote a row for a mismatched tenant")
	}
}

/* ------------------------- both legs, end to end ------------------------- */

// The whole automatic setup, driven the way the controller drives it: sign in,
// follow the redirect, consent, run the chain.
func TestAutoSetup_BothLegsThenTheChain(t *testing.T) {
	restore := autoSetupRBACSettle
	autoSetupRBACSettle = time.Millisecond
	t.Cleanup(func() { autoSetupRBACSettle = restore })

	c := &chainClient{
		exchangeTenant: testTenant,
		tenants:        []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:       []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:        []azureonboard.Subscription{sub(subA, "Production")},
		graphRoles:     azureonboard.RequiredGraphRoles(),
	}
	svc, repo, ws := loginService(t, c)

	// Leg one.
	first, err := svc.finishLogin(
		context.Background(),
		&models.AzureOAuthState{State: loginState(t, true), WorkspaceID: ws},
		AzureCallbackInput{Code: "code"},
	)
	if err != nil {
		t.Fatalf("leg one: %v", err)
	}
	if first.ConsentRedirect == "" {
		t.Fatal("leg one did not hand over a consent redirect")
	}
	sessionID := first.SessionID

	// The state leg one stored is what leg two redeems.
	var consent *models.AzureOAuthState
	for _, st := range repo.states {
		if azureonboard.ConsentStateAutoSetup(st.State) {
			consent = st
		}
	}
	if consent == nil {
		t.Fatal("leg one stored no consent state")
	}

	// Leg two.
	second, err := svc.finishConsent(
		context.Background(), consent, testTenant,
		AzureCallbackInput{AdminConsent: "True", Tenant: testTenant},
	)
	if err != nil {
		t.Fatalf("leg two: %v", err)
	}
	if !second.AutoSetupWanted {
		t.Fatal("leg two did not ask for the chain")
	}

	// What the controller does with that: start it with the session from leg
	// one's cookie.
	if !svc.StartAutoSetup(ws, sessionID, testTenant, false) {
		t.Fatal("chain refused to start")
	}
	t.Cleanup(func() {
		autoSetup.mu.Lock()
		delete(autoSetup.run, sessionID)
		autoSetup.mu.Unlock()
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		st, ok := svc.SetupStatus(sessionID)
		if ok && st.FinishedAt != nil {
			if st.State != "done" {
				t.Fatalf("run finished as %q: %v", st.State, st.Problems)
			}
			if !st.ARMReaderOK || !st.GraphOK || st.ReaderAssigned != 1 {
				t.Fatalf("run did not complete the work: %+v", st)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("background run never finished; last status %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
