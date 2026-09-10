package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// The automatic setup chain runs unattended, on a background goroutine, and it
// WRITES to a customer's Azure subscription. Two properties matter more than the
// happy path:
//
//   - it must never act in a tenant the signed-in account cannot see, because
//     the tenant id it starts from is a token claim rather than something a
//     human chose;
//   - it must never reach for the tenant-wide elevation path, which briefly
//     grants User Access Administrator at the root scope. That is defensible
//     when a person asks for it and indefensible when a background job decides
//     it on their behalf.
//
// Everything else it does is reporting, and a partial result is the normal
// outcome -- so the tests assert that the halves are reported independently
// rather than collapsed into one verdict.

/* --------------------------------- fakes --------------------------------- */

// fakeVault is a map. The chain only needs the session it was handed to survive
// being read back.
type fakeVault struct {
	mu   sync.Mutex
	data map[string]map[string]interface{}
}

func newFakeVault() *fakeVault {
	return &fakeVault{data: map[string]map[string]interface{}{}}
}

func (v *fakeVault) WriteSecret(path string, data map[string]interface{}) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	copied := make(map[string]interface{}, len(data))
	for k, val := range data {
		copied[k] = val
	}
	v.data[path] = copied
	return nil
}

func (v *fakeVault) ReadSecret(path string) (map[string]interface{}, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, ok := v.data[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return d, nil
}

func (v *fakeVault) DeleteSecret(path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.data, path)
	return nil
}

// fakeRepo is an in-memory AzureConnectorRepository. Only what the chain reads
// back is modelled; the rest records that it was called.
type fakeRepo struct {
	mu sync.Mutex

	connectors map[string]*models.AzureConnector
	states     map[string]*models.AzureOAuthState
	subs       map[string][]models.AzureSubscription

	armCalls   []bool
	graphCalls []bool
	upserts    int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		connectors: map[string]*models.AzureConnector{},
		states:     map[string]*models.AzureOAuthState{},
		subs:       map[string][]models.AzureSubscription{},
	}
}

func (r *fakeRepo) UpsertConsent(ws uuid.UUID, tenantID, display, domain string) (*models.AzureConnector, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upserts++
	key := ws.String() + "/" + tenantID
	if c, ok := r.connectors[key]; ok {
		return c, false, nil
	}
	c := &models.AzureConnector{WorkspaceID: ws, TenantID: tenantID, DisplayName: display, Domain: domain}
	r.connectors[key] = c
	return c, true, nil
}

func (r *fakeRepo) SetARMResult(ws uuid.UUID, tenantID string, ok bool, reason string) (*models.AzureConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.armCalls = append(r.armCalls, ok)
	c := r.connectors[ws.String()+"/"+tenantID]
	if c == nil {
		return nil, errors.New("no connector")
	}
	c.ARMReaderOK = ok
	return c, nil
}

func (r *fakeRepo) SetGraphResult(ws uuid.UUID, tenantID string, ok bool, granted []string, reason string) (*models.AzureConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.graphCalls = append(r.graphCalls, ok)
	c := r.connectors[ws.String()+"/"+tenantID]
	if c == nil {
		return nil, errors.New("no connector")
	}
	return c, nil
}

func (r *fakeRepo) UpsertSubscriptions(ws uuid.UUID, tenantID string, subs []models.AzureSubscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs[ws.String()+"/"+tenantID] = subs
	return nil
}

func (r *fakeRepo) SetSubscriptionReader(uuid.UUID, string, map[string]bool) error { return nil }

func (r *fakeRepo) ListSubscriptions(ws uuid.UUID, tenantID string) ([]models.AzureSubscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.subs[ws.String()+"/"+tenantID], nil
}

func (r *fakeRepo) SetPrincipalObjectID(uuid.UUID, string, string) error { return nil }

func (r *fakeRepo) Get(ws uuid.UUID, tenantID string) (*models.AzureConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.connectors[ws.String()+"/"+tenantID]
	if !ok {
		return nil, errors.New("record not found")
	}
	return c, nil
}

func (r *fakeRepo) List(ws uuid.UUID) ([]models.AzureConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []models.AzureConnector
	for _, c := range r.connectors {
		if c.WorkspaceID == ws {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (r *fakeRepo) ConnectedTenantIDs(ws uuid.UUID) (map[string]bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]bool{}
	for _, c := range r.connectors {
		if c.WorkspaceID == ws {
			out[c.TenantID] = true
		}
	}
	return out, nil
}

func (r *fakeRepo) CreateState(st *models.AzureOAuthState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[st.State] = st
	return nil
}

func (r *fakeRepo) ConsumeState(state string) (*models.AzureOAuthState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.states[state]
	if !ok {
		return nil, errors.New("invalid state")
	}
	delete(r.states, state)
	return st, nil
}

func (r *fakeRepo) PeekStateWorkspace(state string) (uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.states[state]
	if !ok {
		return uuid.Nil, errors.New("invalid state")
	}
	return st.WorkspaceID, nil
}

func (r *fakeRepo) PurgeExpiredStates() error { return nil }

// chainClient is the Microsoft side of the chain, scripted per call.
type chainClient struct {
	mu sync.Mutex

	tenants   []azureonboard.Tenant
	tenantErr error

	// userSubs is what the OPERATOR's token sees; appSubs is what the
	// APPLICATION's token sees. They are different questions, and conflating
	// them is the bug ValidateARM exists to catch.
	userSubs []azureonboard.Subscription
	appSubs  []azureonboard.Subscription

	assign     func(scope string) azureonboard.AssignmentResult
	graphRoles []string
	graphErr   error

	// exchangeTenant is the tid claim the code exchange returns. Empty means a
	// token with no tid at all, which is what an audience misconfiguration
	// produces and which the callback must refuse to guess around.
	exchangeTenant string

	refreshCalls     int
	presentedRefresh []string

	// The elevation trio, scriptable. The tenant-wide path's safety is a
	// property of the ORDER in which it calls these, and of whether it gives the
	// privilege back.
	elevate    func() error
	rootElev   func() (string, error)
	deleteRole func(id string) error

	calls []string
}

func (c *chainClient) record(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, s)
}

func (c *chainClient) seq() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.calls, ",")
}

func (c *chainClient) ListTenants(context.Context, string) ([]azureonboard.Tenant, error) {
	c.record("listTenants")
	return c.tenants, c.tenantErr
}

// ListSubscriptions answers as the operator or as the application depending on
// which token was presented. The chain uses both, for different steps.
func (c *chainClient) ListSubscriptions(_ context.Context, token string) ([]azureonboard.Subscription, error) {
	c.record("listSubs:" + token)
	if token == "app" {
		return c.appSubs, nil
	}
	return c.userSubs, nil
}

// RefreshForTenant rotates, the way Entra does: every redemption hands back a
// NEW refresh token and supersedes the one presented. The counter is what the
// regression test reads.
func (c *chainClient) RefreshForTenant(_ context.Context, presented, _ string) (*azureonboard.TokenSet, error) {
	c.mu.Lock()
	c.refreshCalls++
	n := c.refreshCalls
	c.presentedRefresh = append(c.presentedRefresh, presented)
	c.mu.Unlock()

	c.record("refreshForTenant")
	return &azureonboard.TokenSet{
		AccessToken:  "user",
		RefreshToken: fmt.Sprintf("rotated-%d", n),
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

func (c *chainClient) refreshRedemptions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshCalls
}

func (c *chainClient) refreshTokensPresented() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.presentedRefresh...)
}

func (c *chainClient) ClientCredentials(context.Context, string) (*azureonboard.TokenSet, error) {
	c.record("clientCredentials")
	return &azureonboard.TokenSet{
		AccessToken:       "app",
		PrincipalObjectID: testPrincipal,
		ExpiresAt:         time.Now().Add(time.Hour),
	}, nil
}

func (c *chainClient) GraphToken(context.Context, string) (*azureonboard.TokenSet, error) {
	c.record("graphToken")
	if c.graphErr != nil {
		return nil, c.graphErr
	}
	return &azureonboard.TokenSet{
		AccessToken:       jwtWithRoles(c.graphRoles),
		PrincipalObjectID: testPrincipal,
		ExpiresAt:         time.Now().Add(time.Hour),
	}, nil
}

func (c *chainClient) AssignRole(_ context.Context, _, scope, _, _ string) azureonboard.AssignmentResult {
	c.record("assign:" + scope)
	if c.assign != nil {
		return c.assign(scope)
	}
	return azureonboard.AssignmentResult{Scope: scope, OK: true}
}

// The elevation trio. Recording is the point: the chain must never call these.
func (c *chainClient) ElevateAccess(context.Context, string) error {
	c.record("elevate")
	if c.elevate != nil {
		return c.elevate()
	}
	return nil
}

func (c *chainClient) RootElevation(context.Context, string, string) (string, error) {
	c.record("rootElevation")
	if c.rootElev != nil {
		return c.rootElev()
	}
	return "", nil
}

func (c *chainClient) DeleteRoleAssignment(_ context.Context, _, id string) error {
	c.record("delete")
	if c.deleteRole != nil {
		return c.deleteRole(id)
	}
	return nil
}

func (c *chainClient) ExchangeCode(context.Context, string, string) (*azureonboard.TokenSet, error) {
	c.record("exchangeCode")
	access := unsignedJWT(map[string]any{"oid": testOperator})
	if c.exchangeTenant != "" {
		access = jwtWithTenant(c.exchangeTenant)
	}
	return &azureonboard.TokenSet{
		AccessToken:  access,
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

func (c *chainClient) Refresh(context.Context, string) (*azureonboard.TokenSet, error) {
	return &azureonboard.TokenSet{AccessToken: "user", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (c *chainClient) ProbeGraphCapabilities(context.Context, string) []azureonboard.GraphCapability {
	return nil
}

func (c *chainClient) ReadOwnApp(context.Context, string, string) (*azureonboard.AppRegistration, error) {
	return nil, errors.New("not used")
}

func (c *chainClient) ResolveSignInName(context.Context, string, string) (*azureonboard.SignInName, error) {
	return nil, errors.New("not used")
}

/* -------------------------------- helpers -------------------------------- */

// jwtWithRoles mints an unsigned token carrying a roles claim. The production
// code reads these claims without verifying the signature -- deliberately, since
// Microsoft handed it the token over TLS moments earlier -- so an unsigned token
// is exactly what the parser expects to see.
func jwtWithRoles(roles []string) string {
	return unsignedJWT(map[string]any{"roles": roles, "oid": testPrincipal})
}

func jwtWithTenant(tenantID string) string {
	return unsignedJWT(map[string]any{"tid": tenantID, "oid": testOperator})
}

func unsignedJWT(claims map[string]any) string {
	body, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(body) + ".sig"
}

func sub(id, name string) azureonboard.Subscription {
	return azureonboard.Subscription{SubscriptionID: id, DisplayName: name, State: "Enabled"}
}

const (
	testWorkspaceStr = "55555555-5555-5555-5555-555555555555"
	subA             = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	subB             = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// chainHarness wires a service against the fakes, with a live session already
// stored and the tenant already consented.
type chainHarness struct {
	svc       *AzureOnboardService
	repo      *fakeRepo
	azure     *chainClient
	workspace uuid.UUID
	session   string
}

func newChainHarness(t *testing.T, c *chainClient) *chainHarness {
	t.Helper()

	ws := uuid.MustParse(testWorkspaceStr)
	repo := newFakeRepo()
	vlt := newFakeVault()
	svc := &AzureOnboardService{repo: repo, vault: vlt, azure: c}

	session, err := svc.saveSession(ws, &azureonboard.TokenSet{
		AccessToken:  "user",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, _, err := repo.UpsertConsent(ws, testTenant, "", ""); err != nil {
		t.Fatalf("seed consent: %v", err)
	}

	// The store is process-global. Claim this session so status is readable, and
	// release it afterwards so tests do not leak into one another.
	autoSetup.begin(session, testTenant)
	t.Cleanup(func() {
		autoSetup.mu.Lock()
		delete(autoSetup.run, session)
		autoSetup.mu.Unlock()
	})

	return &chainHarness{svc: svc, repo: repo, azure: c, workspace: ws, session: session}
}

func (h *chainHarness) run(t *testing.T) AzureSetupStatus {
	t.Helper()
	return h.runWide(t, false)
}

// runWide drives the chain with the tenant-wide Reader strategy chosen or not.
func (h *chainHarness) runWide(t *testing.T, tenantWide bool) AzureSetupStatus {
	t.Helper()
	// The chain's tenant-wide path can reach the privilege raise, which ships
	// disabled. These tests are about the chain, not the gate.
	allowRootElevation(t)

	// The RBAC settle wait is real seconds in production and pointless here.
	restore := autoSetupRBACSettle
	autoSetupRBACSettle = time.Millisecond
	t.Cleanup(func() { autoSetupRBACSettle = restore })

	// Called synchronously. StartAutoSetup's goroutine is tested separately;
	// running the chain inline is what makes these assertions deterministic.
	h.svc.autoSetup(context.Background(), h.workspace, h.session, testTenant, tenantWide)

	st, ok := h.svc.SetupStatus(h.session)
	if !ok {
		t.Fatal("no status recorded for the run")
	}
	return st
}

/* --------------------------------- tests --------------------------------- */

// The tenant the chain acts in comes from a token claim, not from a human
// choosing it. If that tenant is not one the signed-in account can see, nothing
// may be written to it -- and nothing may be attempted in it either.
func TestAutoSetup_RefusesATenantTheAccountCannotSee(t *testing.T) {
	other := "99999999-9999-9999-9999-999999999999"
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: other}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.State != "failed" {
		t.Fatalf("state = %q, want failed", st.State)
	}
	if got := c.seq(); got != "listTenants" {
		t.Fatalf("calls = %q; nothing may be attempted in an unseen tenant", got)
	}
	if st.ReaderAssigned != 0 || st.Subscriptions != 0 {
		t.Fatalf("acted anyway: %+v", st)
	}
	if len(st.Problems) == 0 || !strings.Contains(st.Problems[0], "not in this account") {
		t.Fatalf("problems = %v, want one naming the missing tenant", st.Problems)
	}
}

// The ordinary run: Reader on each subscription the operator can see, then both
// planes verified independently.
func TestAutoSetup_AssignsReaderPerSubscriptionAndVerifiesBothPlanes(t *testing.T) {
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   []azureonboard.Subscription{sub(subA, "Production"), sub(subB, "Staging")},
		appSubs:    []azureonboard.Subscription{sub(subA, "Production"), sub(subB, "Staging")},
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.State != "done" {
		t.Fatalf("state = %q (%s), want done: %v", st.State, st.Step, st.Problems)
	}
	if st.Subscriptions != 2 || st.ReaderAssigned != 2 || st.ReaderFailed != 0 {
		t.Fatalf("counts wrong: %+v", st)
	}
	if !st.ARMReaderOK || !st.GraphOK {
		t.Fatalf("both planes should have passed: %+v", st)
	}
	if len(st.Problems) != 0 {
		t.Fatalf("problems = %v, want none", st.Problems)
	}

	// One assignment per subscription, each at that subscription's own scope.
	calls := c.seq()
	for _, id := range []string{subA, subB} {
		if !strings.Contains(calls, "assign:/subscriptions/"+id) {
			t.Fatalf("no assignment at /subscriptions/%s in %q", id, calls)
		}
	}
	// And the verdicts reached the database, not just the status.
	if len(h.repo.armCalls) == 0 || !h.repo.armCalls[len(h.repo.armCalls)-1] {
		t.Fatalf("arm verdict not persisted as passing: %v", h.repo.armCalls)
	}
	if len(h.repo.graphCalls) == 0 || !h.repo.graphCalls[len(h.repo.graphCalls)-1] {
		t.Fatalf("graph verdict not persisted as passing: %v", h.repo.graphCalls)
	}
}

// The elevation path grants User Access Administrator at the root of the tenant.
// A human may ask for that. A background job may not decide it.
func TestAutoSetup_NeverElevates(t *testing.T) {
	c := &chainClient{
		tenants:  []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs: []azureonboard.Subscription{sub(subA, "Production")},
		// Refused everywhere: the exact condition under which the tenant-wide
		// path WOULD elevate, if this chain used it.
		assign:     denied,
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	h.run(t)

	for _, forbidden := range []string{"elevate", "rootElevation", "delete"} {
		if strings.Contains(c.seq(), forbidden) {
			t.Fatalf("chain called %q; calls were %q", forbidden, c.seq())
		}
	}
	// And it must not have reached for the root management group scope either.
	if strings.Contains(c.seq(), "managementGroups") {
		t.Fatalf("chain assigned at a management group scope: %q", c.seq())
	}
}

// Consent and RBAC are granted by different privileges, so one failing while
// the other succeeds is the normal outcome for an administrator who is Global
// Administrator but not Owner. Reporting only the first failure would hide the
// half that worked.
func TestAutoSetup_ReportsTheHalfThatWorked(t *testing.T) {
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   []azureonboard.Subscription{sub(subA, "Production")},
		assign:     denied,
		appSubs:    nil, // no role assigned, so ARM lists nothing
		graphRoles: azureonboard.RequiredGraphRoles(),
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.State != "done" {
		t.Fatalf("state = %q, want done -- a partial result is still a finished run", st.State)
	}
	if st.ARMReaderOK {
		t.Fatal("ARM must not pass when nothing could be assigned")
	}
	if !st.GraphOK {
		t.Fatal("Graph succeeded and must be reported as such despite the ARM failure")
	}
	if st.ReaderFailed != 1 || st.ReaderAssigned != 0 {
		t.Fatalf("counts wrong: %+v", st)
	}
	if len(st.Problems) < 2 {
		t.Fatalf("problems = %v, want both the refusal and the failed check", st.Problems)
	}
}

// A missing Graph permission is named, not summarised.
func TestAutoSetup_NamesTheMissingGraphPermissions(t *testing.T) {
	c := &chainClient{
		tenants:    []azureonboard.Tenant{{TenantID: testTenant}},
		userSubs:   []azureonboard.Subscription{sub(subA, "Production")},
		appSubs:    []azureonboard.Subscription{sub(subA, "Production")},
		graphRoles: []string{"Application.Read.All"}, // the rest were not granted
	}
	h := newChainHarness(t, c)

	st := h.run(t)

	if st.GraphOK {
		t.Fatal("graph must not pass with permissions missing")
	}
	if len(st.MissingRoles) == 0 {
		t.Fatal("missing roles must be listed")
	}
	joined := strings.Join(st.Problems, " | ")
	if !strings.Contains(joined, "Directory.Read.All") {
		t.Fatalf("problems must name what is missing, got %q", joined)
	}
}

/* ------------------------------ store & guards ----------------------------- */

func TestStartAutoSetup_RefusesBadInputWithoutStartingAnything(t *testing.T) {
	svc := &AzureOnboardService{}

	if svc.StartAutoSetup(uuid.New(), "", testTenant, false) {
		t.Error("an empty session must not start a run")
	}
	if svc.StartAutoSetup(uuid.New(), "session", "not-a-guid", false) {
		t.Error("a tenant that is not a GUID must not start a run")
	}
}

func TestStartAutoSetup_RefusesASecondRunForTheSameSession(t *testing.T) {
	// A replayed callback or a double-clicked link is the case this guards. The
	// cost of getting it wrong is duplicate role assignments.
	const session = "duplicate-run-session"
	autoSetup.begin(session, testTenant)
	t.Cleanup(func() {
		autoSetup.mu.Lock()
		delete(autoSetup.run, session)
		autoSetup.mu.Unlock()
	})

	svc := &AzureOnboardService{}
	if svc.StartAutoSetup(uuid.New(), session, testTenant, false) {
		t.Fatal("a second run started while the first was still marked running")
	}
}

func TestSetupStore_HandsOutACopy(t *testing.T) {
	// The poll handler and the running chain touch the same struct. Returning
	// the pointer would let a caller mutate a live run, and would race.
	const session = "copy-session"
	autoSetup.begin(session, testTenant)
	t.Cleanup(func() {
		autoSetup.mu.Lock()
		delete(autoSetup.run, session)
		autoSetup.mu.Unlock()
	})

	autoSetup.update(session, func(st *AzureSetupStatus) {
		st.Problems = append(st.Problems, "first")
	})

	got, ok := autoSetup.get(session)
	if !ok {
		t.Fatal("status missing")
	}
	got.Problems[0] = "mutated"
	got.State = "tampered"

	again, _ := autoSetup.get(session)
	if again.Problems[0] != "first" || again.State != "running" {
		t.Fatalf("stored status was mutated through the returned value: %+v", again)
	}
}

func TestSetupStore_SweepsFinishedRunsButKeepsRunningOnes(t *testing.T) {
	store := &setupStore{run: map[string]*AzureSetupStatus{}}
	old := time.Now().UTC().Add(-2 * autoSetupTTL)

	store.run["finished"] = &AzureSetupStatus{State: "done", FinishedAt: &old}
	// A run still going is kept regardless of age: the goroutine holds the only
	// other reference, and dropping it would strand a poller on "not found"
	// while work continues.
	store.run["running"] = &AzureSetupStatus{State: "running", StartedAt: old}

	store.mu.Lock()
	store.sweepLocked()
	store.mu.Unlock()

	if _, ok := store.run["finished"]; ok {
		t.Error("an expired finished run should have been swept")
	}
	if _, ok := store.run["running"]; !ok {
		t.Error("a running run must never be swept")
	}
}
