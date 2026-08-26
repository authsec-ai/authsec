// Phase 1 governance tests: entitlement provenance and the expiry worker.
//
// These run against a real Postgres through the real repository and service layers,
// because the value of this slice is almost entirely in SQL behaviour that a fake DB
// cannot exercise:
//
//   - the partial unique indexes that allow exactly one OPEN provenance row per
//     entitlement while leaving closed history unconstrained
//   - ON DELETE SET NULL on the grant pointer, which is what lets provenance outlive
//     the grant it describes
//   - the revoked_tokens insert, whose column list was wrong in the pre-existing
//     revocation path and compiled fine anyway
//
// Requires TEST_DATABASE_URL, and skips without it, like the rest of this package.
package ownership

import (
	"database/sql"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

const (
	govRole = "cccccccc-0000-0000-0000-00000000000a"
	govSA   = "dddddddd-0000-0000-0000-00000000000a"
	govUser = "aaaaaaaa-0000-0000-0000-000000000001"
)

// govFixture builds the schema plus a role and a service account to bind it to.
func govFixture(t *testing.T) (*sql.DB, repositories.GovernanceRepository, services.ProvenanceManager, uuid.UUID) {
	t.Helper()
	raw := setupSchema(t)
	seedBaseline(t, raw)
	exec(t, raw, "INSERT INTO roles (id,name,workspace_id) VALUES ($1,'agent-role',$2)", govRole, wsA)
	exec(t, raw, "INSERT INTO service_accounts (id,workspace_id,name,status) VALUES ($1,$2,'sa-1','active')", govSA, wsA)

	repo := repositories.NewGovernanceRepository(gormFor(t, raw))
	return raw, repo, services.NewProvenanceManager(repo), uuid.MustParse(wsA)
}

// bindRole inserts a role binding for the service account and returns its id.
func bindRole(t *testing.T, raw *sql.DB, expiresAt *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if expiresAt == nil {
		exec(t, raw, `INSERT INTO role_bindings (id,workspace_id,role_id,service_account_id,role_name)
		              VALUES ($1,$2,$3,$4,'agent-role')`, id, wsA, govRole, govSA)
	} else {
		exec(t, raw, `INSERT INTO role_bindings (id,workspace_id,role_id,service_account_id,role_name,expires_at)
		              VALUES ($1,$2,$3,$4,'agent-role',$5)`, id, wsA, govRole, govSA, *expiresAt)
	}
	return id
}

func future(d time.Duration) *time.Time { t := time.Now().Add(d); return &t }

func openGrant(t *testing.T, pm services.ProvenanceManager, ws, binding uuid.UUID,
	expires *time.Time, standing bool, justification string) (*models.EntitlementProvenance, error) {
	t.Helper()
	owner := uuid.MustParse(govUser)
	sa := uuid.MustParse(govSA)
	return pm.OpenGrant(nil, ws, services.OpenGrantInput{
		EntitlementType: models.EntitlementRoleBinding,
		RoleBindingID:   &binding,
		Snapshot:        map[string]interface{}{"role": "agent-role", "scope_type": "resource_server"},
		Label:           "agent-role on rs/payments",
		SubjectType:     models.ProvenanceSubjectServiceAccount,
		SubjectID:       sa,
		SubjectLabel:    "sa-1",
		Origin:          models.GrantOriginDiscoveryClaim,
		Justification:   justification,
		Purpose:         "nightly reconciliation",
		GrantedBy:       &owner,
		GrantedByLabel:  "u@a.com",
		ExpiresAt:       expires,
		IsStanding:      standing,
	})
}

/* ------------------------------ provenance ------------------------------ */

// The core of phase 1: a grant now carries why it exists.
func TestOpenGrantRecordsWhy(t *testing.T) {
	raw, repo, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(15*time.Minute))

	p, err := openGrant(t, pm, ws, binding, future(15*time.Minute), false, "")
	if err != nil {
		t.Fatalf("open grant: %v", err)
	}
	if p.Origin != models.GrantOriginDiscoveryClaim || p.Purpose != "nightly reconciliation" {
		t.Errorf("origin/purpose not recorded: %+v", p)
	}

	stored, err := repo.GetProvenance(ws, p.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !stored.IsOpen() {
		t.Error("a freshly opened grant must be open")
	}
	if stored.Lapsed {
		t.Error("a grant expiring in 15 minutes is not lapsed")
	}
}

// PG-4's teeth. A permanent grant is allowed, but somebody has to say why on the
// record — otherwise "standing" becomes the silent default and certification has
// nothing to push back on.
func TestStandingGrantRequiresJustification(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, nil)

	if _, err := openGrant(t, pm, ws, binding, nil, true, ""); err == nil {
		t.Fatal("a standing grant with no justification must be refused")
	}

	p, err := openGrant(t, pm, ws, binding, nil, true, "shared build agent, reviewed quarterly")
	if err != nil {
		t.Fatalf("a justified standing grant should be allowed: %v", err)
	}
	if !p.IsStanding || p.ExpiresAt != nil {
		t.Errorf("expected a standing grant with no expiry, got %+v", p)
	}
}

// A grant must either expire or be an explicit, justified exception. Silence is not
// an option — that is what "ephemeral by default" means in practice.
func TestGrantMustExpireOrBeExplicitlyStanding(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, nil)

	if _, err := openGrant(t, pm, ws, binding, nil, false, "just because"); err == nil {
		t.Fatal("a grant with neither an expiry nor is_standing must be refused")
	}
}

// Recording an already-lapsed grant would hand the expiry worker something to revoke
// on its very next tick, which is never what a caller meant.
func TestOpenGrantRefusesAPastExpiry(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, nil)
	past := time.Now().Add(-time.Hour)

	if _, err := openGrant(t, pm, ws, binding, &past, false, ""); err == nil {
		t.Fatal("an expiry in the past must be refused")
	}
}

// One OPEN record per entitlement. Without this a retried provision would
// double-record and every "why" query would return two conflicting answers.
func TestOnlyOneOpenProvenancePerEntitlement(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))

	if _, err := openGrant(t, pm, ws, binding, future(time.Hour), false, ""); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := openGrant(t, pm, ws, binding, future(time.Hour), false, "")
	if err == nil {
		t.Fatal("a second OPEN record for the same binding must be refused")
	}
}

// THE key design property: provenance outlives the grant it describes. An expired
// binding is deleted, and that is exactly the moment the record of it starts to
// matter.
func TestProvenanceSurvivesTheGrantItDescribes(t *testing.T) {
	raw, repo, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))

	p, err := openGrant(t, pm, ws, binding, future(time.Hour), false, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pm.CloseGrant(nil, ws, services.CloseGrantInput{
		RoleBindingID: &binding, Via: models.RevokedViaExpiry, Reason: "lapsed",
	}); err != nil {
		t.Fatalf("close: %v", err)
	}
	exec(t, raw, "DELETE FROM role_bindings WHERE id = $1", binding)

	stored, err := repo.GetProvenance(ws, p.ID)
	if err != nil {
		t.Fatalf("provenance must survive the binding being deleted: %v", err)
	}
	if stored.RoleBindingID != nil {
		t.Error("the live pointer should be nulled by ON DELETE SET NULL")
	}
	// Everything a reviewer needs is still readable from the snapshot.
	if stored.Label == "" || stored.Origin == "" || stored.SubjectLabel == "" {
		t.Errorf("the evidence was lost with the pointer: %+v", stored)
	}
	if stored.RevokedVia != models.RevokedViaExpiry {
		t.Errorf("revoked_via = %q, want expiry", stored.RevokedVia)
	}
}

// Closing is idempotent and a missing record is not an error: every revocation path
// can be retried, and a grant predating provenance has no record to close.
func TestCloseGrantIsIdempotentAndTolerantOfNoRecord(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))

	if _, err := openGrant(t, pm, ws, binding, future(time.Hour), false, ""); err != nil {
		t.Fatalf("open: %v", err)
	}
	closed, err := pm.CloseGrant(nil, ws, services.CloseGrantInput{
		RoleBindingID: &binding, Via: models.RevokedViaAdmin, Reason: "revoked by admin",
	})
	if err != nil || !closed {
		t.Fatalf("first close should report closed=true, got closed=%v err=%v", closed, err)
	}

	closed, err = pm.CloseGrant(nil, ws, services.CloseGrantInput{
		RoleBindingID: &binding, Via: models.RevokedViaAdmin, Reason: "again",
	})
	if err != nil {
		t.Fatalf("a repeated close must not error: %v", err)
	}
	if closed {
		t.Error("the second close should report closed=false — there was nothing open")
	}

	unknown := uuid.New()
	closed, err = pm.CloseGrant(nil, ws, services.CloseGrantInput{
		RoleBindingID: &unknown, Via: models.RevokedViaExpiry,
	})
	if err != nil {
		t.Fatalf("closing an unknown entitlement must not error: %v", err)
	}
	if closed {
		t.Error("closing an unknown entitlement reports closed=false")
	}
}

// After a grant is closed, the entitlement can be granted again — the closed history
// must not block it.
func TestClosedHistoryDoesNotBlockARegrant(t *testing.T) {
	raw, repo, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))

	if _, err := openGrant(t, pm, ws, binding, future(time.Hour), false, ""); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pm.CloseGrant(nil, ws, services.CloseGrantInput{
		RoleBindingID: &binding, Via: models.RevokedViaCertification, Reason: "revoked at review",
	}); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := openGrant(t, pm, ws, binding, future(time.Hour), false, ""); err != nil {
		t.Fatalf("re-granting after a close must be allowed: %v", err)
	}

	rows, total, err := repo.ListProvenance(ws, repositories.ProvenanceFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 rows (one closed, one open), got %d", total)
	}
	var open int
	for _, r := range rows {
		if r.IsOpen() {
			open++
		}
	}
	if open != 1 {
		t.Errorf("expected exactly 1 open row, got %d", open)
	}
}

// Lapsed is derived on read, so the expiry worker's backlog is visible rather than
// silent.
func TestLapsedIsDerivedOnRead(t *testing.T) {
	raw, repo, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))

	p, err := openGrant(t, pm, ws, binding, future(time.Hour), false, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Backdate the expiry directly: OpenGrant refuses a past expiry by design.
	exec(t, raw, "UPDATE entitlement_provenance SET expires_at = now() - interval '1 minute' WHERE id = $1", p.ID)

	stored, err := repo.GetProvenance(ws, p.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !stored.Lapsed {
		t.Error("an open grant past its expiry must read as lapsed")
	}
	if !stored.IsOpen() {
		t.Error("lapsed is not the same as closed — nothing has revoked it yet")
	}
}

// Standing grants sort first, because they are the ones that never lapse on their own
// and so always need a human.
func TestStandingGrantsSortFirst(t *testing.T) {
	raw, repo, pm, ws := govFixture(t)
	temp := bindRole(t, raw, future(time.Hour))
	perm := bindRole(t, raw, nil)

	if _, err := openGrant(t, pm, ws, temp, future(time.Hour), false, ""); err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := openGrant(t, pm, ws, perm, nil, true, "shared build agent"); err != nil {
		t.Fatalf("standing: %v", err)
	}

	rows, _, err := repo.ListProvenance(ws, repositories.ProvenanceFilter{OpenOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 || !rows[0].IsStanding {
		t.Errorf("standing grant should sort first, got %+v", rows)
	}

	standing, total, err := repo.ListProvenance(ws, repositories.ProvenanceFilter{StandingOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("list standing: %v", err)
	}
	if total != 1 || len(standing) != 1 {
		t.Errorf("standing-only should return exactly the permanent grant, got %d", total)
	}
}

/* ----------------------------- expiry worker ---------------------------- */

// seedLiveToken inserts an unexpired native token for the service account, standing in
// for one minted just before the grant lapsed.
func seedLiveToken(t *testing.T, raw *sql.DB, jti uuid.UUID) {
	t.Helper()
	rsID := uuid.New()
	exec(t, raw, `INSERT INTO resource_servers (id,workspace_id,name,resource_uri,public_base_url)
	              VALUES ($1,$2,'payments','authsec://rs/payments','https://payments.example')`, rsID, wsA)
	exec(t, raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','service_account',$3,'client-1',
	            $4,'authsec://rs/payments','read',now(),now() + interval '55 minutes')`,
		jti, wsA, govSA, rsID)
}

// THE gap this worker closes. Read-time filtering already stops a lapsed binding
// granting NEW scope, but a token minted a moment before it lapsed keeps working for
// its full remaining life — up to an hour. This proves the window is shut.
func TestExpirySweepRevokesLiveTokensAndRecordsTheLapse(t *testing.T) {
	raw, repo, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))
	jti := uuid.New()
	seedLiveToken(t, raw, jti)

	p, err := openGrant(t, pm, ws, binding, future(time.Hour), false, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Lapse both the grant and its provenance.
	exec(t, raw, "UPDATE entitlement_provenance SET expires_at = now() - interval '1 minute' WHERE id = $1", p.ID)
	exec(t, raw, "UPDATE role_bindings SET expires_at = now() - interval '1 minute' WHERE id = $1", binding)

	worker := services.NewExpiryWorker(gormFor(t, raw), time.Minute, 100)
	res := worker.RunOnce()

	if res.Errors != 0 {
		t.Fatalf("sweep reported %d errors", res.Errors)
	}
	if res.LapsedFound != 1 || res.BindingsRemoved != 1 || res.ProvenanceClosed != 1 {
		t.Errorf("unexpected sweep result: %+v", res)
	}
	if res.TokensRevoked != 1 {
		t.Errorf("tokens_revoked = %d, want 1 — the live token riding the lapsed grant "+
			"must be killed, or the grant keeps working for up to its full hour", res.TokensRevoked)
	}

	// The token is in the kill list introspection treats as authoritative.
	var revoked int
	if err := raw.QueryRow(`SELECT count(*) FROM revoked_tokens WHERE jti = $1::text AND kind = 'access_token'`,
		jti).Scan(&revoked); err != nil {
		t.Fatalf("count revoked: %v", err)
	}
	if revoked != 1 {
		t.Errorf("expected 1 revoked_tokens row, found %d", revoked)
	}

	// The binding is gone and the lapse is on the record.
	var bindings int
	if err := raw.QueryRow("SELECT count(*) FROM role_bindings WHERE id = $1", binding).Scan(&bindings); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if bindings != 0 {
		t.Error("the expired binding should have been removed")
	}
	stored, err := repo.GetProvenance(ws, p.ID)
	if err != nil {
		t.Fatalf("provenance must survive: %v", err)
	}
	if stored.RevokedVia != models.RevokedViaExpiry || stored.RevokedAt == nil {
		t.Errorf("the lapse was not recorded: %+v", stored)
	}
}

// A grant that has NOT lapsed must be left completely alone. A worker that only ever
// removes access is still wrong if it removes the wrong access.
func TestExpirySweepLeavesLiveGrantsAlone(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))
	if _, err := openGrant(t, pm, ws, binding, future(time.Hour), false, ""); err != nil {
		t.Fatalf("open: %v", err)
	}

	res := services.NewExpiryWorker(gormFor(t, raw), time.Minute, 100).RunOnce()
	if res.LapsedFound != 0 || res.BindingsRemoved != 0 || res.TokensRevoked != 0 {
		t.Errorf("a live grant must not be touched: %+v", res)
	}
	var n int
	if err := raw.QueryRow("SELECT count(*) FROM role_bindings WHERE id = $1", binding).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Error("the live binding was removed")
	}
}

// A standing grant has no expiry and must never be swept, however old it is.
func TestExpirySweepNeverTouchesStandingGrants(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, nil)
	if _, err := openGrant(t, pm, ws, binding, nil, true, "shared build agent"); err != nil {
		t.Fatalf("open: %v", err)
	}
	exec(t, raw, "UPDATE entitlement_provenance SET granted_at = now() - interval '400 days'")

	res := services.NewExpiryWorker(gormFor(t, raw), time.Minute, 100).RunOnce()
	if res.LapsedFound != 0 || res.BindingsRemoved != 0 {
		t.Errorf("a standing grant must never be swept: %+v", res)
	}
}

// Bindings that predate provenance still have to be swept, or the installed base
// stays un-cleaned forever.
func TestExpirySweepCleansBindingsWithNoProvenance(t *testing.T) {
	raw, _, _, _ := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))
	exec(t, raw, "UPDATE role_bindings SET expires_at = now() - interval '1 day' WHERE id = $1", binding)

	res := services.NewExpiryWorker(gormFor(t, raw), time.Minute, 100).RunOnce()
	if res.Errors != 0 {
		t.Fatalf("errors: %+v", res)
	}
	if res.OrphansRemoved != 1 {
		t.Errorf("orphans_removed = %d, want 1", res.OrphansRemoved)
	}
	if res.ProvenanceClosed != 0 {
		t.Errorf("there was no provenance to close, got %d", res.ProvenanceClosed)
	}
	var n int
	if err := raw.QueryRow("SELECT count(*) FROM role_bindings WHERE id = $1", binding).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Error("the orphaned expired binding should have been removed")
	}
}

// The sweep must be safe to run repeatedly — a crash mid-sweep or an overlapping
// tick must not double-revoke or error.
func TestExpirySweepIsIdempotent(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))
	jti := uuid.New()
	seedLiveToken(t, raw, jti)

	p, err := openGrant(t, pm, ws, binding, future(time.Hour), false, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	exec(t, raw, "UPDATE entitlement_provenance SET expires_at = now() - interval '1 minute' WHERE id = $1", p.ID)
	exec(t, raw, "UPDATE role_bindings SET expires_at = now() - interval '1 minute' WHERE id = $1", binding)

	w := services.NewExpiryWorker(gormFor(t, raw), time.Minute, 100)
	first := w.RunOnce()
	second := w.RunOnce()

	if first.Errors != 0 || second.Errors != 0 {
		t.Fatalf("errors: first=%+v second=%+v", first, second)
	}
	if second.LapsedFound != 0 || second.BindingsRemoved != 0 || second.OrphansRemoved != 0 {
		t.Errorf("the second sweep should find nothing left to do: %+v", second)
	}
	var revoked int
	if err := raw.QueryRow(`SELECT count(*) FROM revoked_tokens WHERE jti = $1::text`, jti).Scan(&revoked); err != nil {
		t.Fatalf("count: %v", err)
	}
	if revoked != 1 {
		t.Errorf("expected exactly 1 revocation row after two sweeps, found %d", revoked)
	}
}
