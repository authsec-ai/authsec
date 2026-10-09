package integration

// D-61 (P2-DECISIONS; SPEC-iga-phase2-graph.md §1.4 l.261, §4.7 l.4411-4412):
// ONE definition of "connected" -- a connector exists and is not revoked --
// applied where the PROJECTOR freezes it into the graph: a resource
// reference's provider_attrs.account_connected, and the choice between an
// identity and an external principal as a trust principal's source. Through
// the REAL scan worker and projector.

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// Account A's role trusts B's PartnerRole by exact ARN and A's policy names a
// table in each account. B has been scanned, so PartnerRole is a live
// identity of the workspace. Then:
//
//	B connected  the trust principal IS PartnerRole (an identity, basis
//	             declared) and the table in B is account_connected: true;
//	B revoked    the same document names an account that is not read any
//	             more: the principal is an unresolved aws_principal external
//	             principal -- never B's frozen identity -- and the table in B is
//	             account_connected: false. The table in A is connected either way.
//
// The connected half is the non-vacuity control: the same fixture, one
// connector status apart.
//
// Safeguard (mutation-checked): Load's ConnectedAccounts excludes revoked
// connectors (load.go, D-61).
func TestP2BdbRevokedAccountIsNotConnected(t *testing.T) {
	inA := "arn:aws:dynamodb:us-east-1:" + accountA + ":table/orders"
	inB := "arn:aws:dynamodb:us-east-1:" + accountB + ":table/partner"
	for _, revoked := range []bool{false, true} {
		name := map[bool]string{false: "connected", true: "revoked"}[revoked]
		t.Run(name, func(t *testing.T) {
			l := newP2Lab(t, "p2-bdb-d61-"+name, true)
			a := l.account(accountA)
			b := l.account(accountB)
			partner := b.role("PartnerRole", "AROAPARTNERROLEPART1")
			l.scanAndProject(b)
			partnerID := bdbIdentity(t, l, "PartnerRole")
			if revoked {
				if err := l.db.Exec(`UPDATE cloud_connector SET status = ? WHERE workspace_id = ? AND id = ?`,
					models.CloudConnectorRevoked, l.ws, b.conn).Error; err != nil {
					t.Fatalf("revoke B: %v", err)
				}
			}
			trustRole(a, "OrdersRole", "AROAORDERSROLEORDER1", trustDoc(trustAllow(`{"AWS":"`+partner+`"}`, "sts:AssumeRole")))
			a.attach("OrdersRole", a.managed("Tables", `{"Version":"2012-10-17","Statement":[{"Sid":"Tables",`+
				`"Effect":"Allow","Action":"dynamodb:GetItem","Resource":["`+inA+`","`+inB+`"]}]}`))
			l.scanAndProject(a)

			// The resource references: account_connected frozen per revision (D-3).
			for text, want := range map[string]bool{inA: true, inB: !revoked} {
				var raw string
				l.db.Raw(`SELECT provider_attrs::text FROM iga_resources WHERE workspace_id = ? AND provider = 'aws'
				           AND display_name = ? AND lifecycle = 'active'`, l.ws, text).Scan(&raw)
				var attrs map[string]any
				if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
					t.Fatalf("%s provider_attrs %q: %v", text, raw, err)
				}
				if attrs["account_connected"] != want {
					t.Errorf("%s account_connected = %v, want %v (provider_attrs %s)", text, attrs["account_connected"], want, raw)
				}
			}

			// The trust principal.
			var edges []struct {
				SourceIdentity *uuid.UUID
				Mechanism      *string
				Subject        *string
				State          string
			}
			l.db.Raw(`SELECT r.source_identity_account_id AS source_identity, ep.mechanism, ep.subject_claim AS subject, r.state
			            FROM iga_relationship r
			            JOIN iga_identity_accounts d ON d.workspace_id = r.workspace_id AND d.id = r.target_identity_account_id
			            LEFT JOIN iga_external_principal ep ON ep.workspace_id = r.workspace_id AND ep.id = r.source_external_principal_id
			           WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume' AND d.display_name = 'OrdersRole'`,
				l.ws).Scan(&edges)
			if len(edges) != 1 || edges[0].State != models.RelCurrent {
				t.Fatalf("can_assume into OrdersRole = %+v, want one current edge", edges)
			}
			e := edges[0]
			switch {
			case !revoked && (e.SourceIdentity == nil || *e.SourceIdentity != partnerID):
				t.Errorf("B connected: the principal = %+v, want the identity PartnerRole %s", e, partnerID)
			case revoked && (e.SourceIdentity != nil || e.Mechanism == nil || *e.Mechanism != models.ExternalPrincipalAWSPrincipal ||
				e.Subject == nil || *e.Subject != partner):
				t.Errorf("B revoked: the principal = %+v, want an unresolved aws_principal for %s, never B's identity", e, partner)
			}
		})
	}
}
