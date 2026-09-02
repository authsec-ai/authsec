package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AWS account onboarding, exercised against a real database.
//
// Everything except the AWS call itself is real: the repository, the upsert,
// the constraints, the secrets-store interaction and the error paths. The AWS
// boundary is stubbed through the Verifier seam, which is the reason that seam
// exists — an onboarding regression must be catchable without an AWS account.
//
// What these tests CANNOT prove, and what still needs a live account: that the
// SDK's assume-role path works against real STS, and that every action in the
// CloudFormation template is a real IAM action. See
// docs/flows/aws-cloud-discovery-onboarding.md.

/* --------------------------------- doubles -------------------------------- */

// memVault is an in-memory secrets store that records what was written,
// deleted, and read — so a test can assert not just the happy path but that a
// failed onboard left nothing behind.
type memVault struct {
	mu      sync.Mutex
	data    map[string]map[string]interface{}
	deleted []string
}

func newMemVault() *memVault {
	return &memVault{data: map[string]map[string]interface{}{}}
}

func (m *memVault) WriteSecret(path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := map[string]interface{}{}
	for k, v := range data {
		cp[k] = v
	}
	m.data[path] = cp
	return nil
}

func (m *memVault) ReadSecret(path string) (map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("no secret at %s", path)
	}
	return v, nil
}

func (m *memVault) DeleteSecret(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, path)
	m.deleted = append(m.deleted, path)
	return nil
}

func (m *memVault) paths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.data))
	for k := range m.data {
		out = append(out, k)
	}
	return out
}

// stubVerifier stands in for STS.
type stubVerifier struct {
	identity *awsdiscovery.Identity
	err      error
	calls    int
	lastReq  awsdiscovery.AssumeRequest
}

func (s *stubVerifier) Verify(_ context.Context, req awsdiscovery.AssumeRequest) (*awsdiscovery.Identity, error) {
	s.calls++
	s.lastReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.identity, nil
}

const (
	testAccount = "429418377036"
	testRoleARN = "arn:aws:iam::429418377036:role/AuthSecCloudDiscovery"
)

func okVerifier() *stubVerifier {
	return &stubVerifier{identity: &awsdiscovery.Identity{
		AccountID: testAccount,
		ARN:       "arn:aws:sts::429418377036:assumed-role/AuthSecCloudDiscovery/authsec-onboarding-abc12345",
		UserID:    "AROAEXAMPLEID:authsec-onboarding-abc12345",
	}}
}

func newOnboarding(db *gorm.DB, v awsdiscovery.Verifier) (*services.AWSOnboardingService, *memVault) {
	mv := newMemVault()
	return services.NewAWSOnboardingService(db, mv).WithVerifier(v), mv
}

func mustMint(t *testing.T, ws uuid.UUID) string {
	t.Helper()
	id, err := services.MintExternalID(ws)
	if err != nil {
		t.Fatalf("mint external id: %v", err)
	}
	return id
}

func validInput(externalID string) services.AWSOnboardInput {
	return services.AWSOnboardInput{
		RoleARN:     testRoleARN,
		ExternalID:  externalID,
		Regions:     []string{"us-east-1", "eu-west-1"},
		DisplayName: "sandbox",
	}
}

/* ---------------------------------- tests --------------------------------- */

// The core acceptance criterion: onboarding completes with only a role ARN and
// an ExternalId, stores no customer key, and the account id comes from AWS
// rather than from anything the caller typed.
func TestAWSOnboardingStoresNoKeyMaterialAndTakesTheAccountFromAWS(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-onboard")
	defer cleanConnectors(t, db, ws)

	svc, mv := newOnboarding(db, okVerifier())
	externalID := mustMint(t, ws)

	c, created, err := svc.Onboard(context.Background(), ws, validInput(externalID), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if !created {
		t.Fatal("first onboard of an account must report created")
	}

	// The account is what STS reported, not an input.
	if c.ScopeID != testAccount {
		t.Fatalf("scope_id should be the account STS reported, got %q", c.ScopeID)
	}
	if c.Provider != models.CloudProviderAWS || c.ScopeKind != models.CloudScopeAccount {
		t.Fatalf("wrong provider/scope_kind: %s/%s", c.Provider, c.ScopeKind)
	}
	if c.Status != models.CloudConnectorActive || c.VerifiedAt == nil {
		t.Fatalf("a proven connection must be active and stamped, got status=%s verified=%v",
			c.Status, c.VerifiedAt)
	}
	t.Logf("PASS: connector %s recorded for account %s", c.ID, c.ScopeID)

	// The ExternalId lives in the secrets store and NOWHERE else.
	if len(mv.paths()) != 1 {
		t.Fatalf("expected exactly one stored secret, got %v", mv.paths())
	}
	stored, err := mv.ReadSecret(c.AuthRef)
	if err != nil {
		t.Fatalf("auth_ref must address the stored secret: %v", err)
	}
	if stored["external_id"] != externalID {
		t.Fatal("the stored secret is not the external id we issued")
	}
	t.Logf("PASS: external id stored at %s and referenced by auth_ref", c.AuthRef)

	// Read the row back RAW from the database and prove the secret is not in it.
	var rawRow string
	if err := db.Raw(`SELECT row_to_json(t)::text FROM cloud_connector t WHERE id = ?`, c.ID).
		Row().Scan(&rawRow); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if strings.Contains(rawRow, externalID) {
		t.Fatal("the external id must never be written into a database column")
	}
	t.Log("PASS: no external id anywhere in the persisted row")

	// And prove it is not in an API response either. auth_ref is the ADDRESS of
	// a secret; publishing where a workspace's credentials live is its own leak.
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), externalID) {
		t.Fatal("the external id must never be serialised to a caller")
	}
	if strings.Contains(string(body), "auth_ref") || strings.Contains(string(body), c.AuthRef) {
		t.Fatal("auth_ref must never be serialised to a caller")
	}
	t.Log("PASS: neither the external id nor auth_ref appears in the serialised connector")

	// The non-secret half is on the row, so a scan needs no secrets-store read
	// to learn which role to assume.
	attrs := c.AWSAttrs()
	if attrs.RoleARN != testRoleARN || attrs.Partition != "aws" {
		t.Fatalf("role arn/partition not recorded: %+v", attrs)
	}
	if len(attrs.Regions) != 2 || attrs.Regions[0] != "us-east-1" {
		t.Fatalf("regions not recorded in order: %v", attrs.Regions)
	}
	if attrs.CallerARN == "" || attrs.TemplateVersion != awsdiscovery.TemplateVersion {
		t.Fatalf("evidence not recorded: %+v", attrs)
	}
	t.Logf("PASS: role, partition, regions and template version recorded in attrs")
}

// Re-onboarding an account already connected must update the same row and must
// NOT reset reconciliation state. A second row would split the account's
// inventory; a reset generation would age out everything the last scan found.
func TestAWSReonboardingUpdatesInPlaceAndPreservesScanState(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-reonboard")
	defer cleanConnectors(t, db, ws)

	svc, mv := newOnboarding(db, okVerifier())
	first, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("first onboard: %v", err)
	}

	// Pretend a scan has run.
	if err := db.Exec(`UPDATE cloud_connector
	                   SET scan_generation = 7, coverage = '{"iam":"reached"}'::jsonb
	                   WHERE id = ?`, first.ID).Error; err != nil {
		t.Fatalf("simulate a scan: %v", err)
	}

	in := validInput(mustMint(t, ws))
	in.Regions = []string{"ap-south-1"}
	second, created, err := svc.Onboard(context.Background(), ws, in, "admin")
	if err != nil {
		t.Fatalf("re-onboard: %v", err)
	}
	if created {
		t.Fatal("re-onboarding a connected account must not report created")
	}
	if second.ID != first.ID {
		t.Fatalf("re-onboard forked the row: %s -> %s", first.ID, second.ID)
	}
	if second.ScanGeneration != 7 {
		t.Fatalf("re-onboard reset scan_generation to %d; every existing row would look stale",
			second.ScanGeneration)
	}
	if !strings.Contains(string(second.Coverage), "reached") {
		t.Fatalf("re-onboard erased coverage: %s", second.Coverage)
	}
	if got := second.AWSAttrs().Regions; len(got) != 1 || got[0] != "ap-south-1" {
		t.Fatalf("re-onboard should refresh the region selection, got %v", got)
	}
	t.Log("PASS: same row, reconciliation state intact, configuration refreshed")

	// One account, one secret path — a re-onboard overwrites rather than
	// orphaning a second entry.
	if len(mv.paths()) != 1 {
		t.Fatalf("re-onboard should reuse the account's secret path, got %v", mv.paths())
	}
	t.Log("PASS: one stored secret per account across re-onboards")

	var rows int64
	db.Raw(`SELECT count(*) FROM cloud_connector WHERE workspace_id = ?`, ws).Scan(&rows)
	if rows != 1 {
		t.Fatalf("expected exactly one connector row, got %d", rows)
	}
}

// The cross-tenant guard. Role ARNs and ExternalIds travel through consoles,
// tickets and screenshots; without the binding, a workspace holding another
// customer's pair could onboard their AWS account into its own inventory.
func TestAWSExternalIDIsUsableOnlyByTheWorkspaceItWasIssuedTo(t *testing.T) {
	db := igaDB(t)
	victim := newWorkspace(t, db, "ws-aws-victim")
	attacker := newWorkspace(t, db, "ws-aws-attacker")
	defer cleanConnectors(t, db, victim)
	defer cleanConnectors(t, db, attacker)

	issuedToVictim := mustMint(t, victim)

	svc, mv := newOnboarding(db, okVerifier())
	_, _, err := svc.Onboard(context.Background(), attacker, validInput(issuedToVictim), "attacker")
	if !errors.Is(err, services.ErrExternalIDNotIssued) {
		t.Fatalf("an external id issued to another workspace must be refused, got %v", err)
	}
	t.Log("PASS: external id issued to another workspace refused")

	if len(mv.paths()) != 0 {
		t.Fatalf("a refused onboard must store nothing, got %v", mv.paths())
	}
	var rows int64
	db.Raw(`SELECT count(*) FROM cloud_connector WHERE workspace_id = ?`, attacker).Scan(&rows)
	if rows != 0 {
		t.Fatalf("a refused onboard must write no row, got %d", rows)
	}
	t.Log("PASS: nothing written and nothing stored")

	// The same value works for the workspace it belongs to, proving the refusal
	// was the binding and not a malformed value.
	if _, _, err := svc.Onboard(context.Background(), victim, validInput(issuedToVictim), "admin"); err != nil {
		t.Fatalf("the issuing workspace must be able to use its own external id: %v", err)
	}
	t.Log("PASS: the same external id works for its own workspace")
}

// A connection that cannot be proven must leave no trace. A connector that
// never worked and one that has stopped working look identical in a console,
// and only the second is an incident.
func TestAWSRefusedAssumeLeavesNoRowAndNoStoredSecret(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-refused")
	defer cleanConnectors(t, db, ws)

	denied := &stubVerifier{err: fmt.Errorf("%w: not authorized to perform sts:AssumeRole (AccessDenied)",
		awsdiscovery.ErrNotAssumable)}
	svc, mv := newOnboarding(db, denied)

	_, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if !errors.Is(err, awsdiscovery.ErrNotAssumable) {
		t.Fatalf("expected a not-assumable error, got %v", err)
	}
	if len(mv.paths()) != 0 {
		t.Fatalf("a failed onboard must store no secret, got %v", mv.paths())
	}
	var rows int64
	db.Raw(`SELECT count(*) FROM cloud_connector WHERE workspace_id = ?`, ws).Scan(&rows)
	if rows != 0 {
		t.Fatalf("a failed onboard must write no row, got %d", rows)
	}
	t.Log("PASS: refused assume left no row and no stored secret")
}

// If the session lands somewhere other than the account the ARN names,
// recording it as a working connection would be the wrong answer.
func TestAWSAccountMismatchIsRefused(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-mismatch")
	defer cleanConnectors(t, db, ws)

	wrong := okVerifier()
	wrong.identity.AccountID = "999999999999"
	svc, mv := newOnboarding(db, wrong)

	_, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err == nil || !strings.Contains(err.Error(), "refusing to onboard") {
		t.Fatalf("a role resolving to a different account must be refused, got %v", err)
	}
	if len(mv.paths()) != 0 {
		t.Fatalf("nothing should have been stored, got %v", mv.paths())
	}
	t.Log("PASS: account mismatch refused before anything was written")
}

// A failed verification records why, and keeps the evidence of when the
// connection last genuinely worked. "We cannot look right now" is not "it is
// gone", so nothing is deleted.
func TestAWSFailedVerificationRecordsTheReasonAndKeepsVerifiedAt(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-verify")
	defer cleanConnectors(t, db, ws)

	stub := okVerifier()
	svc, _ := newOnboarding(db, stub)
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	firstVerified := *c.VerifiedAt

	// The customer edits their trust policy and breaks it.
	stub.err = fmt.Errorf("%w: not authorized (AccessDenied)", awsdiscovery.ErrNotAssumable)
	broken, verr := svc.VerifyConnector(context.Background(), ws, c.ID)
	if verr == nil {
		t.Fatal("verification should have failed")
	}
	if broken == nil {
		t.Fatal("the connector row must travel with the error so a console can render it")
	}
	if broken.Status != models.CloudConnectorError {
		t.Fatalf("status should be error, got %s", broken.Status)
	}
	if broken.LastError == "" {
		t.Fatal("an error state must carry its reason")
	}
	if broken.VerifiedAt == nil || !broken.VerifiedAt.Equal(firstVerified) {
		t.Fatalf("verified_at must survive a failure: %v -> %v", firstVerified, broken.VerifiedAt)
	}
	t.Logf("PASS: status=error, reason recorded, verified_at preserved at %s", firstVerified)

	// The customer fixes it.
	stub.err = nil
	fixed, err := svc.VerifyConnector(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("re-verify: %v", err)
	}
	if fixed.Status != models.CloudConnectorActive || fixed.LastError != "" {
		t.Fatalf("a successful verify must clear the error, got status=%s err=%q",
			fixed.Status, fixed.LastError)
	}
	if !fixed.VerifiedAt.After(firstVerified) {
		t.Fatal("a successful verify must advance verified_at")
	}
	t.Log("PASS: recovery clears the error and advances verified_at")
}

// Deleting a connector purges the secret it addressed.
func TestAWSRevokeConnectorPurgesTheStoredExternalIDButKeepsTheRow(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-revoke")
	defer cleanConnectors(t, db, ws)

	svc, mv := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	path := c.AuthRef

	if err := svc.RevokeConnector(ws, c.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := mv.ReadSecret(path); err == nil {
		t.Fatal("the stored external id must be purged on revoke")
	}
	// Unlike a delete, the row -- and anything discovered through it -- stays,
	// for audit. Only its status and auth_ref change.
	after, err := svc.Connector(ws, c.ID)
	if err != nil {
		t.Fatalf("connector should still be readable after revoke, got %v", err)
	}
	if after.Status != models.CloudConnectorRevoked {
		t.Fatalf("status = %q, want %q", after.Status, models.CloudConnectorRevoked)
	}
	t.Log("PASS: external id purged, connector row and status=revoked kept for audit")
}

// Input the service must refuse before it ever reaches AWS.
func TestAWSOnboardingRejectsBadInputWithoutCallingAWS(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-input")
	defer cleanConnectors(t, db, ws)

	cases := []struct {
		name string
		want string
		in   func(string) services.AWSOnboardInput
	}{
		{"a user ARN is not a role", "is not an IAM role ARN", func(e string) services.AWSOnboardInput {
			in := validInput(e)
			in.RoleARN = "arn:aws:iam::429418377036:user/someone"
			return in
		}},
		{"a made-up region", "is not an AWS region code", func(e string) services.AWSOnboardInput {
			in := validInput(e)
			in.Regions = []string{"moon-central-1"}
			return in
		}},
		{"no regions selected", "at least one AWS region", func(e string) services.AWSOnboardInput {
			in := validInput(e)
			in.Regions = nil
			return in
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := okVerifier()
			svc, mv := newOnboarding(db, stub)
			_, _, err := svc.Onboard(context.Background(), ws, tc.in(mustMint(t, ws)), "admin")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error containing %q, got %v", tc.want, err)
			}
			if stub.calls != 0 {
				t.Fatal("bad input must be refused before any AWS call")
			}
			if len(mv.paths()) != 0 {
				t.Fatal("bad input must store nothing")
			}
			t.Logf("PASS: refused with %q, no AWS call made", err)
		})
	}
}

// Region selection is normalised: trimmed, lowercased, de-duplicated, order
// preserved. Order matters because the first region is the one the assume-role
// probe uses.
func TestAWSRegionsAreNormalisedAndDeduplicated(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-regions")
	defer cleanConnectors(t, db, ws)

	stub := okVerifier()
	svc, _ := newOnboarding(db, stub)

	in := validInput(mustMint(t, ws))
	in.Regions = []string{" US-East-1 ", "eu-west-1", "us-east-1", ""}

	c, _, err := svc.Onboard(context.Background(), ws, in, "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	got := c.AWSAttrs().Regions
	if len(got) != 2 || got[0] != "us-east-1" || got[1] != "eu-west-1" {
		t.Fatalf("expected [us-east-1 eu-west-1], got %v", got)
	}
	if stub.lastReq.Region != "us-east-1" {
		t.Fatalf("the probe should use the first selected region, got %q", stub.lastReq.Region)
	}
	t.Logf("PASS: normalised to %v, probe used %s", got, stub.lastReq.Region)
}

// The session name AWS is asked for must satisfy AWS's own constraint, and
// should identify AuthSec in the customer's CloudTrail.
func TestAWSOnboardingSessionNameIsValidAndAttributable(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-aws-session")
	defer cleanConnectors(t, db, ws)

	stub := okVerifier()
	svc, _ := newOnboarding(db, stub)
	if _, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin"); err != nil {
		t.Fatalf("onboard: %v", err)
	}

	name := stub.lastReq.SessionName
	if !strings.HasPrefix(name, "authsec-") {
		t.Fatalf("session name should identify AuthSec, got %q", name)
	}
	if len(name) < 2 || len(name) > 64 {
		t.Fatalf("session name must be 2-64 chars for AWS, got %d", len(name))
	}
	if err := awsdiscovery.ValidateAssumeRequest(stub.lastReq); err != nil {
		t.Fatalf("the request sent to AWS must satisfy AWS's own constraints: %v", err)
	}
	t.Logf("PASS: session name %q is valid and attributable", name)
}

// The minted ExternalId must satisfy AWS's constraint on sts:ExternalId, or the
// customer's stack will refuse the parameter.
func TestAWSMintedExternalIDSatisfiesAWSConstraints(t *testing.T) {
	ws := uuid.New()
	for i := 0; i < 50; i++ {
		id, err := services.MintExternalID(ws)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if err := awsdiscovery.ValidateExternalID(id); err != nil {
			t.Fatalf("minted id %q is not acceptable to AWS: %v", id, err)
		}
		if err := services.VerifyExternalIDBinding(ws, id); err != nil {
			t.Fatalf("a freshly minted id must verify under its own workspace: %v", err)
		}
		if services.VerifyExternalIDBinding(uuid.New(), id) == nil {
			t.Fatal("a minted id must not verify under a different workspace")
		}
	}
	t.Log("PASS: 50 minted external ids are AWS-valid, self-verifying and workspace-bound")
}

// A tampered ExternalId must not verify. Covers the truncation and
// substitution cases a naive comparison would let through.
func TestAWSTamperedExternalIDIsRejected(t *testing.T) {
	ws := uuid.New()
	id, err := services.MintExternalID(ws)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	nonce, sig, _ := strings.Cut(id, ".")

	for _, bad := range []string{
		"", nonce, sig, nonce + ".", "." + sig,
		nonce + "." + sig[:len(sig)-1],
		nonce + "x." + sig,
		nonce + "." + strings.Repeat("A", len(sig)),
	} {
		if services.VerifyExternalIDBinding(ws, bad) == nil {
			t.Fatalf("tampered external id %q was accepted", bad)
		}
	}
	t.Log("PASS: truncated, substituted and empty external ids all refused")
}

/* --------------------------------- helpers -------------------------------- */

func cleanConnectors(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Helper()
	db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, ws)
}
