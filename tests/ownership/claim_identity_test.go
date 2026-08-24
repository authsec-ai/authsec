// Claiming without hand-picking an OAuth client.
//
// Claim used to require an operator to select an existing agent-kind OAuth client.
// That was ceremony blocking the only judgement a human actually holds -- who is
// accountable -- because the overwhelming majority of agents discovered in a cluster
// are workloads that never authenticate to AuthSec at all: no SPIRE agent so no SVID,
// no mounted secret so no client_secret_basic. The operator was being asked to pick a
// credential-holder for a workload that holds no credential.
//
// The client is still required by the data model (service_accounts is keyed on
// oauth_client_id, so it is the only place an entitlement anchor can hang). What
// changed is who supplies it.
package ownership

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// unclaimedFixture gives a sighting that has NOT been claimed, with the provisioning
// hints the Kubernetes connector really sends.
// claimOwner is the baseline user every fixture in this package already seeds.
var claimOwner = uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")

func unclaimedFixture(t *testing.T) (provFixture, services.DiscoveryManager, uuid.UUID) {
	t.Helper()
	f := newProvFixture(t)
	dm := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(gormFor(t, f.raw)))

	id := uuid.New()
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status, metadata, runtime_status)
	  VALUES ($1,$2,'k8s_webhook',$3,'agent (Deployment/research-agent)','unregistered',
	    '{"provisioning_hints":{"identity_anchor":"system:serviceaccount:iga-demo:default",
	       "suggested_client_name":"research-agent/agent"}}','running')`,
		id, f.ws, "fp-unclaimed-"+id.String()[:8])
	return f, dm, id
}

func TestClaimWithoutAClientMintsOne(t *testing.T) {
	f, dm, agentID := unclaimedFixture(t)
	owner := claimOwner

	out, err := dm.ClaimAgent(f.ws, agentID, services.ClaimInput{OwnerUserID: owner})
	if err != nil {
		t.Fatalf("claim with no client must succeed: %v", err)
	}
	if out.Status != models.DiscoveredAgentRegistered {
		t.Fatalf("status = %q, want registered", out.Status)
	}
	if out.MatchedClientID == nil {
		t.Fatal("a governed identity must have been minted — the DB CHECK requires one " +
			"for a registered agent")
	}

	var kind, name string
	var methods string
	if err := f.raw.QueryRow(`SELECT client_kind, client_name,
	        array_to_string(allowed_token_endpoint_auth_methods, ',')
	      FROM mcp_oauth_clients WHERE id = $1`, *out.MatchedClientID).
		Scan(&kind, &name, &methods); err != nil {
		t.Fatalf("read minted client: %v", err)
	}

	// It must be visible to the claim dialog, which filters on 'agent'. Defaulting
	// to human_app is the bug that made the right identity type invisible.
	if kind != models.ClientKindAgent {
		t.Errorf("client_kind = %q, want %q", kind, models.ClientKindAgent)
	}
	// Named after the workload, using the hint the connector has always sent.
	if name != "research-agent/agent (agent)" {
		t.Errorf("client_name = %q; it should be derived from suggested_client_name", name)
	}
	// No secret. Minting a credential nobody holds and nobody rotates would be worse
	// than having none.
	if methods != "urn:authsec:params:oauth:client-assertion-type:spiffe-svid" {
		t.Errorf("auth methods = %q; a headless workload must not get a client secret", methods)
	}
}

// An owner is still mandatory: it is the judgement the system cannot make.
func TestClaimStillRequiresAnOwner(t *testing.T) {
	f, dm, agentID := unclaimedFixture(t)
	_ = f
	if _, err := dm.ClaimAgent(f.ws, agentID, services.ClaimInput{}); err == nil {
		t.Fatal("claim with no owner must be refused — a registered agent can never be ownerless")
	}
}

// Supplying a client explicitly still works: the minting is a default, not a policy.
func TestClaimWithAnExplicitClientIsUnchanged(t *testing.T) {
	f, dm, agentID := unclaimedFixture(t)
	owner := claimOwner

	explicit := uuid.New()
	exec(t, f.raw, `INSERT INTO mcp_oauth_clients (id, client_id, hydra_client_id,
	        client_name, home_workspace_id, client_kind)
	      VALUES ($1,$2,$2,'chosen-by-hand',$3,'agent')`,
		explicit, explicit.String(), f.ws)

	out, err := dm.ClaimAgent(f.ws, agentID, services.ClaimInput{
		MatchedClientID: explicit, OwnerUserID: owner,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if out.MatchedClientID == nil || *out.MatchedClientID != explicit {
		t.Errorf("an explicitly supplied client must be honoured, got %v", out.MatchedClientID)
	}
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM mcp_oauth_clients
	      WHERE home_workspace_id = $1 AND client_name LIKE '%(agent)'`, f.ws).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("nothing should have been minted when a client was supplied, found %d", n)
	}
}

// Each claim gets its own identity. A shared one would make several agents
// indistinguishable in the audit trail, defeating the point of the anchor.
func TestEachClaimGetsADistinctIdentity(t *testing.T) {
	f, dm, first := unclaimedFixture(t)
	owner := claimOwner

	second := uuid.New()
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status, metadata, runtime_status)
	  VALUES ($1,$2,'k8s_webhook',$3,'worker (Deployment/invoice-triage)','unregistered',
	    '{"provisioning_hints":{"identity_anchor":"system:serviceaccount:iga-demo:default",
	       "suggested_client_name":"invoice-triage/worker"}}','running')`,
		second, f.ws, "fp-second-"+second.String()[:8])

	a, err := dm.ClaimAgent(f.ws, first, services.ClaimInput{OwnerUserID: owner})
	if err != nil {
		t.Fatalf("claim first: %v", err)
	}
	b, err := dm.ClaimAgent(f.ws, second, services.ClaimInput{OwnerUserID: owner})
	if err != nil {
		t.Fatalf("claim second: %v", err)
	}
	if *a.MatchedClientID == *b.MatchedClientID {
		t.Error("two agents share one governed identity; every action must trace to " +
			"exactly one principal")
	}
}

/* ------------- the shared-ServiceAccount bug this exposed ---------------- */

// THE REGRESSION TEST THAT MATTERS.
//
// Both agents above run as system:serviceaccount:iga-demo:default -- the normal case,
// since a pod that names no ServiceAccount gets "default". ensureAnchor used to copy
// that string onto service_accounts.spiffe_id, which carries a UNIQUE index because a
// SPIFFE ID identifies exactly ONE workload.
//
// So provisioning the second agent in a namespace failed outright with
// duplicate key value violates unique constraint "uq_sa_spiffe" -- and there was no
// way for an operator to avoid it, because sharing an SA is the default behaviour of
// Kubernetes, not a misconfiguration.
func TestTwoAgentsSharingAServiceAccountCanBothBeProvisioned(t *testing.T) {
	f, dm, first := unclaimedFixture(t)
	owner := claimOwner
	pm := f.pm
	provisionExpiry := time.Now().Add(720 * time.Hour)

	second := uuid.New()
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status, metadata, runtime_status)
	  VALUES ($1,$2,'k8s_webhook',$3,'worker (Deployment/invoice-triage)','unregistered',
	    '{"provisioning_hints":{"identity_anchor":"system:serviceaccount:iga-demo:default",
	       "suggested_client_name":"invoice-triage/worker"}}','running')`,
		second, f.ws, "fp-shared-sa-"+second.String()[:8])

	for i, agentID := range []uuid.UUID{first, second} {
		if _, err := dm.ClaimAgent(f.ws, agentID, services.ClaimInput{OwnerUserID: owner}); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if _, err := pm.Provision(f.ws, services.ProvisionInput{
			DiscoveredAgentID: agentID,
			ResourceServerID:  f.rs,
			RoleID:            f.role,
			ExpiresAt:         &provisionExpiry,
			ActingUser:        &owner,
			ActingUserLabel:   "u@a.com",
			Purpose:           "shared-SA regression",
		}); err != nil {
			t.Fatalf("provision agent %d (both run as the SAME Kubernetes ServiceAccount, "+
				"which is the default and must not collide): %v", i, err)
		}
	}
}
