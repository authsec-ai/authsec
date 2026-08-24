// Phase 2 tests: the atomic provision and the single revocation path.
//
// Against real Postgres through the real service layer, because the properties that
// matter here are transactional and constraint-level:
//
//   - PG-2: everything commits together or nothing does. A rollback must leave NO
//     anchor, NO binding, and NO provenance — asserted by failing mid-transaction.
//   - PG-1: entitlements attach to a paired service account, because
//     role_bindings.check_principal cannot bind an oauth client.
//   - PG-6: de-provision removes bindings, kills live tokens, revokes registrations,
//     and asserts zero residual rather than assuming it.
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

type provFixture struct {
	raw    *sql.DB
	pm     services.ProvisioningManager
	prov   services.ProvenanceManager
	ws     uuid.UUID
	agent  uuid.UUID
	client uuid.UUID
	rs     uuid.UUID
	role   uuid.UUID
}

// newProvFixture builds a CLAIMED discovered agent — the only state provisioning
// accepts as input — plus the Application and role it will be granted.
func newProvFixture(t *testing.T) provFixture {
	t.Helper()
	raw := setupSchema(t)
	seedBaseline(t, raw)

	ws := uuid.MustParse(wsA)
	client := uuid.New()
	rs := uuid.New()
	role := uuid.New()
	agent := uuid.New()

	exec(t, raw, `INSERT INTO mcp_oauth_clients (id, client_id, hydra_client_id, client_name, home_workspace_id)
	              VALUES ($1,'agent-client-1','hydra-1','research-agent',$2)`, client, wsA)
	exec(t, raw, `INSERT INTO resource_servers (id,workspace_id,name,resource_uri,public_base_url)
	              VALUES ($1,$2,'payments','authsec://rs/payments','https://payments.example')`, rs, wsA)
	exec(t, raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,'agent-reader',$2)`, role, wsA)

	// A claimed sighting: status=registered with both an identity and an owner. The
	// metadata carries the workload identity discovery reported.
	exec(t, raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, metadata, deployment_origin,
	     status, matched_client_id, owner_user_id, runtime_status)
	    VALUES ($1,$2,'k8s_webhook','fp-prov-1','research-agent (Deployment) in ns/default',
	            '{"provisioning_hints":{"identity_anchor":"system:serviceaccount:default:research-agent-sa"}}',
	            'automated','registered',$3,$4,'running')`,
		agent, wsA, client, "aaaaaaaa-0000-0000-0000-000000000001")

	db := gormFor(t, raw)
	return provFixture{
		raw:  raw,
		pm:   services.NewProvisioningManager(db, services.NewOAuthASService(db)),
		prov: services.NewProvenanceManager(repositories.NewGovernanceRepository(db)),
		ws:   ws, agent: agent, client: client, rs: rs, role: role,
	}
}

func (f provFixture) provisionInput(expires *time.Time, standing bool, justification string) services.ProvisionInput {
	owner := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	return services.ProvisionInput{
		DiscoveredAgentID: f.agent,
		ResourceServerID:  f.rs,
		RoleID:            f.role,
		Justification:     justification,
		Purpose:           "nightly reconciliation",
		ExpiresAt:         expires,
		IsStanding:        standing,
		ActingUser:        &owner,
		ActingUserLabel:   "u@a.com",
	}
}

func (f provFixture) count(t *testing.T, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

/* -------------------------------- provision ------------------------------- */

// The end-to-end transition: claimed sighting -> governed principal.
func TestProvisionCreatesTheWholeGovernedPrincipal(t *testing.T) {
	f := newProvFixture(t)

	out, err := f.pm.Provision(f.ws, f.provisionInput(future(30*time.Minute), false, "on-call rotation"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// PG-1: the entitlement anchor, carrying the workload identity discovery found.
	if out.ServiceAccountID == uuid.Nil || !out.ServiceAccountNew {
		t.Errorf("expected a newly created service-account anchor, got %+v", out)
	}
	if out.SpiffeID != "system:serviceaccount:default:research-agent-sa" {
		t.Errorf("spiffe_id = %q; discovery's identity_anchor must land on the anchor", out.SpiffeID)
	}
	if f.count(t, `SELECT count(*) FROM service_accounts WHERE oauth_client_id = $1 AND status = 'active'`, f.client) != 1 {
		t.Error("the anchor should be active and paired to the oauth client")
	}

	// The binding exists, is RS-scoped, and EXPIRES.
	var expires *time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM role_bindings WHERE id = $1`, out.RoleBindingID).
		Scan(&expires); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if expires == nil {
		t.Error("the binding must carry the expiry — a permanent grant by default is the " +
			"behaviour governance exists to invert")
	}
	if f.count(t, `SELECT count(*) FROM role_bindings WHERE id = $1 AND service_account_id = $2
	               AND scope_type = 'resource_server' AND scope_id = $3`,
		out.RoleBindingID, out.ServiceAccountID, f.rs) != 1 {
		t.Error("the binding should be RS-scoped and held by the anchor")
	}

	// The registration is approved.
	if f.count(t, `SELECT count(*) FROM resource_server_client_registrations
	               WHERE id = $1 AND status = 'approved'`, out.RegistrationID) != 1 {
		t.Error("the registration should be approved")
	}

	// Provenance for both entitlements.
	if len(out.ProvenanceIDs) != 2 {
		t.Errorf("expected provenance for the binding AND the registration, got %d", len(out.ProvenanceIDs))
	}
	rows, _, err := f.prov.List(f.ws, repositories.ProvenanceFilter{OpenOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("list provenance: %v", err)
	}
	var binding, reg *models.EntitlementProvenance
	for i := range rows {
		switch rows[i].EntitlementType {
		case models.EntitlementRoleBinding:
			binding = &rows[i]
		case models.EntitlementClientRegistration:
			reg = &rows[i]
		}
	}
	if binding == nil || reg == nil {
		t.Fatalf("expected one of each provenance type, got %d rows", len(rows))
	}
	if binding.IsStanding || binding.ExpiresAt == nil {
		t.Error("the binding's provenance must be the expiring one")
	}
	if !reg.IsStanding {
		t.Error("the registration's provenance is standing: the agent stays connected " +
			"until deprovisioned, while its AUTHORITY is what expires")
	}
	if binding.Origin != models.GrantOriginDiscoveryClaim || binding.Purpose == "" {
		t.Errorf("origin/purpose not recorded on the binding: %+v", binding)
	}
	if binding.DiscoveredAgentID == nil || *binding.DiscoveredAgentID != f.agent {
		t.Error("provenance must tie the grant back to the sighting it came from")
	}

	// The identity is now governed and owned.
	var status string
	var owner *uuid.UUID
	if err := f.raw.QueryRow(`SELECT governance_status, owner_user_id FROM mcp_oauth_clients WHERE id = $1`,
		f.client).Scan(&status, &owner); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if status != models.GovernanceStatusActive {
		t.Errorf("governance_status = %q, want active", status)
	}
	if owner == nil {
		t.Error("the accountable owner from the claim must be stamped on the identity")
	}
}

// An unclaimed sighting must not be provisionable. A claim is the human decision that
// this agent should exist and names who answers for it.
func TestProvisionRequiresAClaim(t *testing.T) {
	f := newProvFixture(t)
	exec(t, f.raw, `UPDATE discovered_agents SET status = 'unregistered' WHERE id = $1`, f.agent)

	if _, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, "")); err == nil {
		t.Fatal("provisioning an unclaimed agent must be refused")
	}
	if f.count(t, `SELECT count(*) FROM service_accounts WHERE oauth_client_id = $1`, f.client) != 0 {
		t.Error("a refused provision must leave nothing behind")
	}
}

// An agent with no accountable human must not be provisionable — and it turns out the
// SCHEMA already guarantees that, which is worth pinning down.
//
// discovered_agents_registered_chk is `status <> 'registered' OR (matched_client_id IS
// NOT NULL AND owner_user_id IS NOT NULL)`, so "claimed but unowned" is not a
// representable state. The nil checks in Provision are therefore defence in depth
// rather than the primary control. This test asserts the real control, so that if the
// constraint is ever relaxed the service-level check has a reason to still be there.
func TestClaimedAgentCannotBeUnowned(t *testing.T) {
	f := newProvFixture(t)

	mustFail(t, f.raw, "a claimed agent with no owner",
		`UPDATE discovered_agents SET owner_user_id = NULL WHERE id = $1`, f.agent)
	mustFail(t, f.raw, "a claimed agent with no identity",
		`UPDATE discovered_agents SET matched_client_id = NULL WHERE id = $1`, f.agent)

	// Provisioning still works, i.e. the fixture was never corrupted by the attempts.
	if _, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, "")); err != nil {
		t.Fatalf("provision should still succeed: %v", err)
	}
}

// PG-4 at the provisioning boundary, not just in provenance.
func TestProvisionRefusesAnUnjustifiedPermanentGrant(t *testing.T) {
	f := newProvFixture(t)

	if _, err := f.pm.Provision(f.ws, f.provisionInput(nil, true, "")); err == nil {
		t.Fatal("a standing grant with no justification must be refused")
	}
	// And neither-expiry-nor-standing is refused too: silence is not a valid choice.
	if _, err := f.pm.Provision(f.ws, f.provisionInput(nil, false, "")); err == nil {
		t.Fatal("a grant with neither an expiry nor is_standing must be refused")
	}

	out, err := f.pm.Provision(f.ws, f.provisionInput(nil, true, "shared build agent, reviewed quarterly"))
	if err != nil {
		t.Fatalf("a justified standing grant should be allowed: %v", err)
	}
	var expires *time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM role_bindings WHERE id = $1`, out.RoleBindingID).
		Scan(&expires); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if expires != nil {
		t.Error("a standing grant's binding must have no expiry")
	}
}

// THE PG-2 test. A failure anywhere in the transaction must leave NOTHING behind —
// no anchor, no binding, no provenance, no approved registration. A half-provisioned
// agent is worse than an unprovisioned one because it looks governed.
func TestProvisionIsAllOrNothing(t *testing.T) {
	f := newProvFixture(t)

	// A role from ANOTHER workspace. The approve primitive validates role-workspace
	// membership, so this fails partway — after the anchor and registration have been
	// written inside the transaction.
	foreignRole := uuid.New()
	exec(t, f.raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,'foreign',$2)`, foreignRole, wsB)

	in := f.provisionInput(future(time.Hour), false, "")
	in.RoleID = foreignRole
	if _, err := f.pm.Provision(f.ws, in); err == nil {
		t.Fatal("a foreign-workspace role must be refused")
	}

	if n := f.count(t, `SELECT count(*) FROM service_accounts WHERE oauth_client_id = $1`, f.client); n != 0 {
		t.Errorf("rollback left %d anchor(s) behind", n)
	}
	if n := f.count(t, `SELECT count(*) FROM resource_server_client_registrations WHERE oauth_client_id = $1`,
		f.client); n != 0 {
		t.Errorf("rollback left %d registration(s) behind", n)
	}
	if n := f.count(t, `SELECT count(*) FROM entitlement_provenance`); n != 0 {
		t.Errorf("rollback left %d provenance row(s) behind", n)
	}
	var status string
	if err := f.raw.QueryRow(`SELECT governance_status FROM mcp_oauth_clients WHERE id = $1`, f.client).
		Scan(&status); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if status != models.GovernanceStatusUngoverned {
		t.Errorf("governance_status = %q after a rollback; it must stay ungoverned", status)
	}
}

// Provisioning the same agent into a SECOND Application must reuse the one anchor.
// Fragmenting entitlements across several principals would make "what does this agent
// have?" unanswerable.
func TestProvisioningTwiceReusesTheSameAnchor(t *testing.T) {
	f := newProvFixture(t)

	first, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, ""))
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}

	rs2 := uuid.New()
	role2 := uuid.New()
	exec(t, f.raw, `INSERT INTO resource_servers (id,workspace_id,name,resource_uri,public_base_url)
	                VALUES ($1,$2,'ledger','authsec://rs/ledger','https://ledger.example')`, rs2, wsA)
	exec(t, f.raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,'ledger-reader',$2)`, role2, wsA)

	in := f.provisionInput(future(time.Hour), false, "")
	in.ResourceServerID = rs2
	in.RoleID = role2
	second, err := f.pm.Provision(f.ws, in)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}

	if second.ServiceAccountID != first.ServiceAccountID {
		t.Errorf("expected the same anchor, got %s then %s", first.ServiceAccountID, second.ServiceAccountID)
	}
	if second.ServiceAccountNew {
		t.Error("the second provision must not create a second anchor")
	}
	if n := f.count(t, `SELECT count(*) FROM service_accounts WHERE oauth_client_id = $1`, f.client); n != 1 {
		t.Errorf("expected exactly 1 anchor, found %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE service_account_id = $1`,
		first.ServiceAccountID); n != 2 {
		t.Errorf("expected 2 bindings on the one anchor, found %d", n)
	}
}

/* ------------------------------- deprovision ------------------------------ */

func TestDeprovisionRemovesEverythingAndKillsTokens(t *testing.T) {
	f := newProvFixture(t)
	out, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, ""))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// A live token minted under the grant, as the running agent would hold.
	jti := uuid.New()
	exec(t, f.raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','service_account',$3,'agent-client-1',
	            $4,'authsec://rs/payments','read',now(),now() + interval '55 minutes')`,
		jti, wsA, out.ServiceAccountID, f.rs)

	res, err := f.pm.Deprovision(f.ws, services.DeprovisionInput{
		DiscoveredAgentID: &f.agent,
		Via:               models.RevokedViaAdmin,
		Reason:            "agent retired",
	})
	if err != nil {
		t.Fatalf("deprovision: %v", err)
	}

	if res.BindingsRemoved != 1 {
		t.Errorf("bindings_removed = %d, want 1", res.BindingsRemoved)
	}
	if res.TokensRevoked != 1 {
		t.Errorf("tokens_revoked = %d, want 1 — otherwise the agent keeps working for "+
			"up to an hour after being deprovisioned", res.TokensRevoked)
	}
	if res.RegistrationsRevoked != 1 {
		t.Errorf("registrations_revoked = %d, want 1", res.RegistrationsRevoked)
	}
	if res.ProvenanceClosed != 2 {
		t.Errorf("provenance_closed = %d, want 2 (binding + registration)", res.ProvenanceClosed)
	}
	if res.ResidualBindings != 0 {
		t.Errorf("residual_bindings = %d; a de-provision reporting success must leave none",
			res.ResidualBindings)
	}

	// The token is in the kill list introspection treats as authoritative.
	if f.count(t, `SELECT count(*) FROM revoked_tokens WHERE jti = $1::text AND kind='access_token'`, jti) != 1 {
		t.Error("the live token was not revoked")
	}
	// The anchor is kept but disabled — closed provenance references it.
	if f.count(t, `SELECT count(*) FROM service_accounts WHERE id = $1 AND status='disabled'`,
		out.ServiceAccountID) != 1 {
		t.Error("the anchor should be disabled, not deleted")
	}
	// The registration is revoked, not deleted: the history of having been connected
	// survives.
	if f.count(t, `SELECT count(*) FROM resource_server_client_registrations
	               WHERE id = $1 AND status='revoked'`, out.RegistrationID) != 1 {
		t.Error("the registration should be revoked and retained")
	}
	var status string
	if err := f.raw.QueryRow(`SELECT governance_status FROM mcp_oauth_clients WHERE id=$1`, f.client).
		Scan(&status); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if status != models.GovernanceStatusDeprovisioned {
		t.Errorf("governance_status = %q, want deprovisioned", status)
	}
}

// Provenance survives de-provisioning with the reason attached — that is the audit
// trail the whole design exists to preserve.
func TestDeprovisionKeepsProvenanceAsEvidence(t *testing.T) {
	f := newProvFixture(t)
	if _, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, "on-call")); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := f.pm.Deprovision(f.ws, services.DeprovisionInput{
		DiscoveredAgentID: &f.agent,
		Via:               models.RevokedViaCertification,
		Reason:            "revoked at quarterly review",
	}); err != nil {
		t.Fatalf("deprovision: %v", err)
	}

	rows, total, err := f.prov.List(f.ws, repositories.ProvenanceFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected both provenance rows to survive, got %d", total)
	}
	for _, r := range rows {
		if r.IsOpen() {
			t.Errorf("%s provenance should be closed", r.EntitlementType)
		}
		if r.RevokedVia != models.RevokedViaCertification {
			t.Errorf("revoked_via = %q, want certification", r.RevokedVia)
		}
		if r.RevokedReason == "" {
			t.Error("the reason must be recorded")
		}
		if r.Label == "" {
			t.Error("the label must survive so a reviewer can still read what this was")
		}
	}
}

// Every caller may retry, so de-provisioning twice must be safe and must not
// double-revoke.
func TestDeprovisionIsIdempotent(t *testing.T) {
	f := newProvFixture(t)
	out, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, ""))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	jti := uuid.New()
	exec(t, f.raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','service_account',$3,'agent-client-1',
	            $4,'authsec://rs/payments','read',now(),now() + interval '55 minutes')`,
		jti, wsA, out.ServiceAccountID, f.rs)

	in := services.DeprovisionInput{
		DiscoveredAgentID: &f.agent, Via: models.RevokedViaQuarantine, Reason: "quarantined",
	}
	first, err := f.pm.Deprovision(f.ws, in)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := f.pm.Deprovision(f.ws, in)
	if err != nil {
		t.Fatalf("second deprovision must not error: %v", err)
	}

	if first.BindingsRemoved != 1 || second.BindingsRemoved != 0 {
		t.Errorf("expected 1 then 0 bindings removed, got %d then %d",
			first.BindingsRemoved, second.BindingsRemoved)
	}
	if second.TokensRevoked != 0 {
		t.Errorf("the second pass should find no live tokens, got %d", second.TokensRevoked)
	}
	if f.count(t, `SELECT count(*) FROM revoked_tokens WHERE jti = $1::text`, jti) != 1 {
		t.Error("expected exactly one revocation row after two passes")
	}
}

// An agent that was never provisioned is reported as already clean, not an error:
// quarantine and leaver both fan out over agents that may or may not be provisioned.
func TestDeprovisionAnUnprovisionedAgentIsNotAnError(t *testing.T) {
	f := newProvFixture(t)
	// Drop back to unregistered in the same statement, because
	// discovered_agents_registered_chk forbids a claimed agent without an identity.
	exec(t, f.raw, `UPDATE discovered_agents
	                   SET status = 'unregistered', matched_client_id = NULL, owner_user_id = NULL
	                 WHERE id = $1`, f.agent)

	res, err := f.pm.Deprovision(f.ws, services.DeprovisionInput{
		DiscoveredAgentID: &f.agent, Via: models.RevokedViaLeaver, Reason: "owner deactivated",
	})
	if err != nil {
		t.Fatalf("should not error: %v", err)
	}
	if !res.AlreadyDeprovisioned {
		t.Error("expected already_deprovisioned=true for an agent with no identity")
	}
}

// A bogus revocation mechanism must be refused: revoked_via is the audit record of
// which of the five paths acted, and an arbitrary string makes it useless.
func TestDeprovisionRefusesAnUnknownMechanism(t *testing.T) {
	f := newProvFixture(t)
	if _, err := f.pm.Deprovision(f.ws, services.DeprovisionInput{
		DiscoveredAgentID: &f.agent, Via: "because-i-said-so", Reason: "x",
	}); err == nil {
		t.Fatal("an unknown revocation mechanism must be refused")
	}
}

// The provisioned grant must then be swept by the expiry worker like any other —
// proving phases 1 and 2 actually compose rather than merely coexisting.
func TestProvisionedGrantIsSweptByTheExpiryWorker(t *testing.T) {
	f := newProvFixture(t)
	out, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, ""))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Lapse both sides, as time passing would.
	exec(t, f.raw, `UPDATE role_bindings SET expires_at = now() - interval '1 minute' WHERE id = $1`,
		out.RoleBindingID)
	exec(t, f.raw, `UPDATE entitlement_provenance SET expires_at = now() - interval '1 minute'
	                WHERE role_binding_id = $1`, out.RoleBindingID)

	res := services.NewExpiryWorker(gormFor(t, f.raw), time.Minute, 100).RunOnce()
	if res.Errors != 0 {
		t.Fatalf("sweep errors: %+v", res)
	}
	if res.BindingsRemoved != 1 || res.ProvenanceClosed != 1 {
		t.Errorf("the provisioned grant should have been swept: %+v", res)
	}
	// The registration's standing provenance must be untouched — the agent is still
	// connected, it just has no authority right now.
	rows, _, err := f.prov.List(f.ws, repositories.ProvenanceFilter{OpenOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].EntitlementType != models.EntitlementClientRegistration {
		t.Errorf("expected only the standing registration to remain open, got %+v", rows)
	}
}

/* --------------------------- console approvals --------------------------- */

// grantFixture sets up a user-subject approval, as the console's
// "approve this access request" flow does.
func (f provFixture) grantFixture(t *testing.T) uuid.UUID {
	t.Helper()
	// A role named the way ApproveRequest requires (rs-<id>:...) is not needed here —
	// GrantEntitlement is called directly, below the controller's naming check.
	return uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
}

// THE fix for the half-done bug. The console approval path used to call the atomic
// approve primitive with no expiry and write no provenance, so every approval produced
// a permanent grant that nothing could explain later.
func TestConsoleApprovalHonoursDurationAndRecordsProvenance(t *testing.T) {
	f := newProvFixture(t)
	user := f.grantFixture(t)
	pm := f.pm.(interface {
		GrantEntitlement(uuid.UUID, services.GrantEntitlementInput) (*services.GrantResult, error)
	})

	expires := future(20 * time.Minute)
	out, err := pm.GrantEntitlement(f.ws, services.GrantEntitlementInput{
		ResourceServerID: f.rs,
		ClientID:         "agent-client-1",
		RoleID:           &f.role,
		SubjectType:      "user",
		SubjectID:        user,
		SubjectLabel:     "u@a.com",
		Origin:           models.GrantOriginSelfService,
		Justification:    "on-call rotation",
		Purpose:          "incident triage",
		ExpiresAt:        expires,
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if out.RoleBindingID == nil || out.ProvenanceID == nil {
		t.Fatalf("expected both a binding and provenance, got %+v", out)
	}
	if out.LegacyStandingDefault {
		t.Error("a grant with an explicit duration is not a legacy standing default")
	}

	// The binding actually expires.
	var got *time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM role_bindings WHERE id = $1`, *out.RoleBindingID).
		Scan(&got); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if got == nil {
		t.Fatal("the console approval must honour the requested duration, not create a permanent grant")
	}

	// And it is explained.
	p, err := f.prov.Get(f.ws, *out.ProvenanceID)
	if err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if p.Origin != models.GrantOriginSelfService || p.Justification == "" || p.Purpose == "" {
		t.Errorf("the approval's why was not recorded: %+v", p)
	}
	if p.IsStanding {
		t.Error("a time-boxed grant must not be recorded as standing")
	}
}

// Preserving the live endpoint's behaviour when no duration is supplied, WITHOUT
// hiding it: the grant is still permanent, but it is now recorded as an unjustified
// standing grant so certification can surface and drive it to zero.
func TestConsoleApprovalWithNoDurationIsRecordedAsLegacyStanding(t *testing.T) {
	f := newProvFixture(t)
	user := f.grantFixture(t)
	pm := f.pm.(interface {
		GrantEntitlement(uuid.UUID, services.GrantEntitlementInput) (*services.GrantResult, error)
	})

	out, err := pm.GrantEntitlement(f.ws, services.GrantEntitlementInput{
		ResourceServerID: f.rs,
		ClientID:         "agent-client-1",
		RoleID:           &f.role,
		SubjectType:      "user",
		SubjectID:        user,
		Origin:           models.GrantOriginConnectionApproval,
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !out.LegacyStandingDefault {
		t.Error("a grant with no duration must be flagged, so the console can warn and the " +
			"count can be driven to zero")
	}

	// Behaviour is unchanged — still a permanent binding — but it is now visible.
	var expires *time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM role_bindings WHERE id = $1`, *out.RoleBindingID).
		Scan(&expires); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if expires != nil {
		t.Error("with no duration the endpoint's historical behaviour is preserved: no expiry")
	}

	p, err := f.prov.Get(f.ws, *out.ProvenanceID)
	if err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if !p.IsStanding || p.Justification == "" {
		t.Errorf("it must be recorded as a standing grant WITH a justification, got %+v", p)
	}
	// Findable: "show me every permanent grant nobody justified".
	standing, total, err := f.prov.List(f.ws, repositories.ProvenanceFilter{StandingOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("list standing: %v", err)
	}
	if total != 1 || len(standing) != 1 {
		t.Errorf("the legacy standing grant should appear in the standing report, got %d", total)
	}
}

// A connection-only approval grants no authority, so it has no duration to reason
// about and must not be forced to invent one.
func TestConnectionOnlyApprovalNeedsNoDuration(t *testing.T) {
	f := newProvFixture(t)
	pm := f.pm.(interface {
		GrantEntitlement(uuid.UUID, services.GrantEntitlementInput) (*services.GrantResult, error)
	})

	out, err := pm.GrantEntitlement(f.ws, services.GrantEntitlementInput{
		ResourceServerID: f.rs,
		ClientID:         "agent-client-1",
		Origin:           models.GrantOriginConnectionApproval,
	})
	if err != nil {
		t.Fatalf("connection-only approval: %v", err)
	}
	if out.RoleBindingID != nil || out.ProvenanceID != nil {
		t.Error("no role was bound, so there is no entitlement to explain")
	}
	if out.LegacyStandingDefault {
		t.Error("a connection-only approval is not a standing grant")
	}
	if f.count(t, `SELECT count(*) FROM resource_server_client_registrations
	               WHERE id = $1 AND status='approved'`, out.RegistrationID) != 1 {
		t.Error("the registration should still be approved")
	}
}

// Re-approving is idempotent and must not invent a second "why".
func TestConsoleApprovalIsIdempotent(t *testing.T) {
	f := newProvFixture(t)
	user := f.grantFixture(t)
	pm := f.pm.(interface {
		GrantEntitlement(uuid.UUID, services.GrantEntitlementInput) (*services.GrantResult, error)
	})
	in := services.GrantEntitlementInput{
		ResourceServerID: f.rs,
		ClientID:         "agent-client-1",
		RoleID:           &f.role,
		SubjectType:      "user",
		SubjectID:        user,
		Origin:           models.GrantOriginSelfService,
		Justification:    "on-call",
		ExpiresAt:        future(time.Hour),
	}
	if _, err := pm.GrantEntitlement(f.ws, in); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := pm.GrantEntitlement(f.ws, in); err != nil {
		t.Fatalf("re-approval must not error: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM entitlement_provenance WHERE revoked_at IS NULL`); n != 1 {
		t.Errorf("expected exactly 1 open provenance row after two approvals, got %d", n)
	}
}
