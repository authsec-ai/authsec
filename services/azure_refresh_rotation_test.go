package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/google/uuid"
)

// Entra rotates a refresh token on redemption: the reply carries a new one and
// the token presented is superseded. It keeps working for a short grace period
// and then stops.
//
// Both halves of that cost real failures against a live tenant, so both are
// pinned here:
//
//   - redeeming once per subscription presented the same stored token N+1 times.
//     The first two landed inside the grace window and the rest came back
//     AADSTS65001 "has not consented", which reads like a consent problem and is
//     nothing of the kind. Five subscriptions, one granted, four refused.
//   - the replacement was discarded every time, so a session became unusable
//     once its access token expired -- again with an error naming consent.

// The chain must redeem the refresh token ONCE, no matter how many
// subscriptions there are.
func TestAutoSetup_RedeemsTheRefreshTokenOncePerRun(t *testing.T) {
	many := []azureonboard.Subscription{
		sub(subA, "Production"),
		sub(subB, "Staging"),
		sub("cccccccc-cccc-cccc-cccc-cccccccccccc", "Sponsorship"),
		sub("dddddddd-dddd-dddd-dddd-dddddddddddd", "Sponsorship"),
		sub("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", "Sponsorship"),
	}
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   many,
		appSubs:    many,
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if got := c.refreshRedemptions(); got != 1 {
		t.Fatalf("redeemed the refresh token %d times for %d subscriptions, want 1.\ncalls: %s",
			got, len(many), c.seq())
	}
	if st.Subscriptions != len(many) {
		t.Fatalf("subscriptions = %d, want %d", st.Subscriptions, len(many))
	}
	if st.ReaderAssigned != len(many) || st.ReaderFailed != 0 {
		t.Fatalf("assigned %d, failed %d, want all %d granted: %v",
			st.ReaderAssigned, st.ReaderFailed, len(many), st.Problems)
	}

	// One assignment per subscription, each at its own ARM scope. A bare
	// subscription id here would reach Azure as an invalid scope.
	calls := c.seq()
	for _, s := range many {
		if !strings.Contains(calls, "assign:/subscriptions/"+s.SubscriptionID) {
			t.Errorf("no assignment at /subscriptions/%s", s.SubscriptionID)
		}
	}
}

// A refused assignment is reported per subscription, not collapsed -- and still
// only costs one redemption.
func TestAutoSetup_ReportsEveryRefusedSubscription(t *testing.T) {
	many := []azureonboard.Subscription{
		sub(subA, "Production"),
		sub(subB, "Staging"),
	}
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   many,
		assign:     denied,
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if got := c.refreshRedemptions(); got != 1 {
		t.Errorf("redemptions = %d, want 1", got)
	}
	if st.ReaderFailed != len(many) || st.ReaderAssigned != 0 {
		t.Fatalf("assigned %d, failed %d, want 0 and %d: %+v",
			st.ReaderAssigned, st.ReaderFailed, len(many), st)
	}
	// Each refusal named, so an operator can see WHICH subscription needs
	// somebody with Owner on it.
	joined := strings.Join(st.Problems, " | ")
	for _, s := range many {
		if !strings.Contains(joined, s.SubscriptionID) {
			t.Errorf("problems do not name subscription %s: %q", s.SubscriptionID, joined)
		}
	}
}

// A tenant the operator can see but holds no subscriptions in is not an error,
// and must say so rather than reporting a silent zero.
func TestAutoSetup_SaysSoWhenNoSubscriptionsAreVisible(t *testing.T) {
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   nil,
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.Subscriptions != 0 || st.ReaderAssigned != 0 {
		t.Fatalf("counts wrong: %+v", st)
	}
	if !st.GraphOK {
		t.Error("the directory is still worth onboarding with no subscriptions")
	}
	joined := strings.Join(st.Problems, " | ")
	if !strings.Contains(joined, "no subscriptions") {
		t.Fatalf("problems do not explain the zero: %q", joined)
	}
}

// The replacement token must reach the secrets store, or the next call presents
// a superseded one.
func TestAssignReader_KeepsTheRotatedRefreshToken(t *testing.T) {
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
	}
	ws := uuid.MustParse(testWorkspaceStr)
	repo := newFakeRepo()
	vlt := newFakeVault()
	svc := &AzureOnboardService{repo: repo, vault: vlt, azure: c}

	sessionID, err := svc.saveSession(ws, &azureonboard.TokenSet{
		AccessToken:  "user",
		RefreshToken: "original",
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, _, err := repo.UpsertConsent(ws, testTenant, "", ""); err != nil {
		t.Fatalf("seed consent: %v", err)
	}

	if _, err := svc.AssignReader(context.Background(), ws, sessionID, testTenant, "", false); err != nil {
		t.Fatalf("AssignReader: %v", err)
	}

	stored, err := vlt.ReadSecret(azureSessionPath(ws, sessionID))
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	got, _ := stored["refresh_token"].(string)
	if got == "original" {
		t.Fatal("the superseded refresh token is still stored; the next call will be refused")
	}
	if got != "rotated-1" {
		t.Fatalf("stored refresh token = %q, want the rotated one", got)
	}

	// A second call must present the REPLACEMENT, not the original. This is the
	// assertion the live failure reduces to.
	if _, err := svc.AssignReader(context.Background(), ws, sessionID, testTenant, "", false); err != nil {
		t.Fatalf("second AssignReader: %v", err)
	}
	presented := c.refreshTokensPresented()
	if len(presented) != 2 {
		t.Fatalf("redemptions = %d, want 2", len(presented))
	}
	if presented[1] != "rotated-1" {
		t.Fatalf("second call presented %q, want the rotated token from the first",
			presented[1])
	}
}

// The write-back must not extend a session past the bound it was created with.
func TestKeepRotatedRefresh_PreservesTheSessionEnd(t *testing.T) {
	c := &chainClient{}
	ws := uuid.MustParse(testWorkspaceStr)
	vlt := newFakeVault()
	svc := &AzureOnboardService{repo: newFakeRepo(), vault: vlt, azure: c}

	sessionID, err := svc.saveSession(ws, &azureonboard.TokenSet{
		AccessToken:  "user",
		RefreshToken: "original",
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := azureSessionPath(ws, sessionID)
	before, _ := vlt.ReadSecret(path)
	ends, _ := before["session_ends"].(string)
	if ends == "" {
		t.Fatal("seeded session carries no end")
	}

	svc.keepRotatedRefresh(ws, sessionID, &azureonboard.TokenSet{
		AccessToken:  "user2",
		RefreshToken: "rotated-1",
		ExpiresAt:    time.Now().Add(24 * time.Hour), // longer than the session
	})

	after, _ := vlt.ReadSecret(path)
	if got, _ := after["session_ends"].(string); got != ends {
		t.Fatalf("session_ends changed from %q to %q", ends, got)
	}
	if got, _ := after["refresh_token"].(string); got != "rotated-1" {
		t.Fatalf("refresh token = %q, want rotated-1", got)
	}
}

// Nothing to rotate, nothing to write: a token set with no refresh token must
// not blank the stored one.
func TestKeepRotatedRefresh_IgnoresAnEmptyReplacement(t *testing.T) {
	ws := uuid.MustParse(testWorkspaceStr)
	vlt := newFakeVault()
	svc := &AzureOnboardService{repo: newFakeRepo(), vault: vlt, azure: &chainClient{}}

	sessionID, err := svc.saveSession(ws, &azureonboard.TokenSet{
		AccessToken:  "user",
		RefreshToken: "original",
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc.keepRotatedRefresh(ws, sessionID, &azureonboard.TokenSet{AccessToken: "user2"})
	svc.keepRotatedRefresh(ws, sessionID, nil)

	after, _ := vlt.ReadSecret(azureSessionPath(ws, sessionID))
	if got, _ := after["refresh_token"].(string); got != "original" {
		t.Fatalf("refresh token = %q, want it left alone", got)
	}
}

// A session id that was never minted here must not reach the secrets store at
// all -- the id lands in a path.
func TestKeepRotatedRefresh_RefusesAnUnmintedSessionID(t *testing.T) {
	ws := uuid.MustParse(testWorkspaceStr)
	vlt := newFakeVault()
	svc := &AzureOnboardService{repo: newFakeRepo(), vault: vlt, azure: &chainClient{}}

	for _, bad := range []string{"", "../../etc/passwd", "has spaces", strings.Repeat("a", 200)} {
		svc.keepRotatedRefresh(ws, bad, &azureonboard.TokenSet{RefreshToken: "rotated"})
	}
	if len(vlt.data) != 0 {
		t.Fatalf("wrote %d secret(s) for session ids that were never minted", len(vlt.data))
	}
}

// Two failure paths the chain has and nothing exercised.
//
// The fake carried tenantErr and graphErr fields that no test ever set: dead
// scaffolding that also marked exactly these two untested branches. Using them
// is a better answer than deleting them.

// The tenant listing failing is fatal to the run -- everything after it acts in
// a tenant this account may not be able to reach.
func TestAutoSetup_TenantListingFailureStopsTheRun(t *testing.T) {
	c := &chainClient{
		tenantErr:  errors.New("arm refused the tenant list"),
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.State != "failed" {
		t.Fatalf("state = %q, want failed", st.State)
	}
	if strings.Contains(c.seq(), "assign") {
		t.Fatalf("assigned a role without knowing the tenant is reachable: %s", c.seq())
	}
	if !strings.Contains(strings.Join(st.Problems, " "), "arm refused the tenant list") {
		t.Fatalf("problems do not carry the cause: %v", st.Problems)
	}
}

// Graph failing is NOT fatal. It is the consent plane, independent of ARM, and a
// tenant whose subscriptions were just made readable is still onboarded.
func TestAutoSetup_GraphFailureIsReportedButNotFatal(t *testing.T) {
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:  []azureonboard.Subscription{sub(subA, "Production")},
		graphErr: errors.New("token endpoint refused the app"),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.State != "done" {
		t.Fatalf("state = %q, want done -- the ARM half succeeded", st.State)
	}
	if !st.ARMReaderOK {
		t.Error("ARM verified and must be reported as such despite Graph failing")
	}
	if st.GraphOK {
		t.Error("Graph failed and must not be reported as usable")
	}
	if !strings.Contains(strings.Join(st.Problems, " "), "token endpoint refused the app") {
		t.Fatalf("problems do not carry the Graph cause: %v", st.Problems)
	}
}
