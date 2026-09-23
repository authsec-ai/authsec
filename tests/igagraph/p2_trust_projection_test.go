package igagraph_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// Pod-identity projection against real Postgres, through the real Load
// (SPEC-iga-phase2-graph.md §4.7, §1.4; P2-DECISIONS D-42).

const trustPodSubject = "system:serviceaccount:payments:ledger-agent"

// trustPodRow inserts one eks_pod_identity cloud_assume_edge row.
func trustPodRow(f *fixture, identityID uuid.UUID, issuer any, attrs string, gen int) {
	f.t.Helper()
	f.exec(`INSERT INTO cloud_assume_edge (workspace_id, connector_id, identity_id, subject_kind, subject,
	          issuer, mechanism, k8s_ref, attrs, last_seen_generation)
	        VALUES ($1, $2, $3, 'k8s_service_account', $4, $5, 'eks_pod_identity', $4, $6::jsonb, $7)`,
		f.workspace, f.connector, identityID, trustPodSubject, issuer, attrs, gen)
}

func trustPodCoverage() map[string]models.SurfaceCoverage {
	cov := cleanCoverage(region)
	cov[models.SurfaceEKSPodIdentity] = reached(1)
	return cov
}

// §4.7's pod-identity loop passes the association's role without looking; a
// role outside this run's snapshot would be written as a uuid.Nil target. The
// projector skips it -- and projects the association whose role IS here.
func TestTrustPodIdentityRoleOutsideTheSnapshotIsSkipped(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	orphan := uuid.New()
	f.exec(`INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	        VALUES ($1, $2, $3, 'iam_role', 'arn:aws:iam::111111111111:role/gone', 'gone', '{"unique_id":"AROAGONEGONEGONEGONE"}', 0)`,
		orphan, f.workspace, f.connector)
	trustPodRow(f, est.roleID, "oidc.eks.eu-central-1.amazonaws.com/id/ABC", `{}`, 1)
	trustPodRow(f, orphan, "oidc.eks.eu-central-1.amazonaws.com/id/ABC", `{}`, 1)
	run := f.publishedRun(f.connector, 1, trustPodCoverage())
	f.mustProject(est.load(run))

	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE relationship_type = 'can_assume'
	                    AND mechanism = 'eks_pod_identity' AND state = 'current'`); n != 1 {
		t.Errorf("pod-identity edges = %d, want 1 (the role in the snapshot)", n)
	}
}

// D-42: a cluster without an OIDC issuer is named by its ARN, when the
// collector recorded one -- so the service account is still one principal of
// one cluster, never an issuer-less node shared by every cluster.
func TestTrustPodIdentityFallsBackToTheClusterARN(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	cluster := "arn:aws:eks:eu-central-1:111111111111:cluster/pods-only"
	trustPodRow(f, est.roleID, nil, `{"cluster_arn":"`+cluster+`"}`, 1)
	run := f.publishedRun(f.connector, 1, trustPodCoverage())
	f.mustProject(est.load(run))

	var issuer, subject, kind string
	if err := f.db.QueryRow(`SELECT ep.issuer, ep.subject_claim, ep.mechanism
	                           FROM iga_relationship r JOIN iga_external_principal ep ON ep.id = r.source_external_principal_id
	                          WHERE r.mechanism = 'eks_pod_identity'`).Scan(&issuer, &subject, &kind); err != nil {
		t.Fatalf("pod-identity edge: %v", err)
	}
	if issuer != cluster || subject != trustPodSubject || kind != models.ExternalPrincipalK8sServiceAccount {
		t.Errorf("principal = (%q, %q, %q), want the cluster ARN as issuer for %s", issuer, subject, kind, trustPodSubject)
	}
}
