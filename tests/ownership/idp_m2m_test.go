package ownership

import (
	"testing"
)

const baselineUser = "aaaaaaaa-0000-0000-0000-000000000001"

// TestAppIDP_OnlyEnabledReturned proves the application↔IDP enablement model:
// ListForApplication's query returns only IDPs with an enabled policy row, and
// disabled policies are excluded.
func TestAppIDP_OnlyEnabledReturned(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	// An application (resource server) in workspace A.
	app := "dddddddd-0000-0000-0000-0000000000a1"
	exec(t, db,
		"INSERT INTO resource_servers (id, workspace_id, resource_uri, name, public_base_url) VALUES ($1,$2,'https://a.example/api','app-A','https://a.example')",
		app, wsA)

	// Two IDPs in workspace A.
	idpEnabled := "eeeeeeee-0000-0000-0000-0000000000e1"
	idpDisabled := "eeeeeeee-0000-0000-0000-0000000000e2"
	for _, id := range []string{idpEnabled, idpDisabled} {
		exec(t, db,
			`INSERT INTO identity_providers (id, workspace_id, provider_type, display_name, created_by_user_id)
			 VALUES ($1,$2,'ad','idp',$3)`,
			id, wsA, baselineUser)
	}

	// Policy: IDP1 enabled, IDP2 disabled.
	exec(t, db,
		"INSERT INTO application_identity_provider_policies (workspace_id, application_id, identity_provider_id, enabled) VALUES ($1,$2,$3,true)",
		wsA, app, idpEnabled)
	exec(t, db,
		"INSERT INTO application_identity_provider_policies (workspace_id, application_id, identity_provider_id, enabled) VALUES ($1,$2,$3,false)",
		wsA, app, idpDisabled)

	// Mirror ListForApplication.
	rows, err := db.Query(`
		SELECT ip.id
		  FROM identity_providers ip
		  JOIN application_identity_provider_policies p ON p.identity_provider_id = ip.id
		 WHERE p.application_id = $1 AND p.workspace_id = $2 AND p.enabled = true
		   AND ip.workspace_id = $2
		 ORDER BY ip.created_at ASC`, app, wsA)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, id)
	}
	if len(got) != 1 || got[0] != idpEnabled {
		t.Fatalf("expected only the enabled IDP %s, got %v", idpEnabled, got)
	}
}

// TestAppIDPPolicy_CrossWorkspaceRejected proves a policy cannot wire an
// application to an IDP across workspace boundaries (composite FKs on the
// policy table).
func TestAppIDPPolicy_CrossWorkspaceRejected(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	// App in A, IDP in B.
	app := "dddddddd-0000-0000-0000-0000000000a2"
	exec(t, db,
		"INSERT INTO resource_servers (id, workspace_id, resource_uri, name, public_base_url) VALUES ($1,$2,'https://a2.example/api','app-A2','https://a2.example')",
		app, wsA)
	// A user in B to satisfy created_by_user_id.
	exec(t, db, "INSERT INTO users (id, email, workspace_id) VALUES ($1,'u@b.com',$2)",
		"aaaaaaaa-0000-0000-0000-0000000000b1", wsB)
	idpB := "eeeeeeee-0000-0000-0000-0000000000b1"
	exec(t, db,
		`INSERT INTO identity_providers (id, workspace_id, provider_type, display_name, created_by_user_id)
		 VALUES ($1,$2,'ad','idp-B',$3)`,
		idpB, wsB, "aaaaaaaa-0000-0000-0000-0000000000b1")

	// Policy claiming workspace A, app A, but IDP from B: must violate the
	// idp composite FK (identity_provider_id, workspace_id).
	mustFail(t, db, "cross-workspace app-IDP policy",
		"INSERT INTO application_identity_provider_policies (workspace_id, application_id, identity_provider_id, enabled) VALUES ($1,$2,$3,true)",
		wsA, app, idpB)
}

// TestM2M_RevokedSpiffeIdentityGate proves the lifecycle gate query used by
// authenticateSPIFFESVID flags revoked/disabled identities and passes active
// ones — so a revoked workload can be blocked from minting tokens.
func TestM2M_RevokedSpiffeIdentityGate(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	app := "dddddddd-0000-0000-0000-0000000000a3"
	exec(t, db,
		"INSERT INTO resource_servers (id, workspace_id, resource_uri, name, public_base_url) VALUES ($1,$2,'https://a3.example/api','app-A3','https://a3.example')",
		app, wsA)

	activeSpiffe := "spiffe://td/wl/active"
	revokedSpiffe := "spiffe://td/wl/revoked"
	exec(t, db,
		`INSERT INTO application_spiffe_identities (workspace_id, application_id, spiffe_id, trust_domain, status)
		 VALUES ($1,$2,$3,'td','active')`,
		wsA, app, activeSpiffe)
	exec(t, db,
		`INSERT INTO application_spiffe_identities (workspace_id, application_id, spiffe_id, trust_domain, status, revoked_at)
		 VALUES ($1,$2,$3,'td','revoked', now())`,
		wsA, app, revokedSpiffe)

	gate := func(spiffe string) int {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM application_spiffe_identities
			  WHERE spiffe_id = $1 AND (revoked_at IS NOT NULL OR status IN ('revoked','disabled'))`,
			spiffe,
		).Scan(&n); err != nil {
			t.Fatalf("gate query: %v", err)
		}
		return n
	}

	if got := gate(activeSpiffe); got != 0 {
		t.Fatalf("active SPIFFE identity should pass the gate (count 0), got %d", got)
	}
	if got := gate(revokedSpiffe); got == 0 {
		t.Fatal("revoked SPIFFE identity should be flagged by the gate (count > 0), got 0")
	}
}
