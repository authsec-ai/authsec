package igagraph_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Pod-identity projection against real Postgres, through the real Load
// (SPEC-iga-phase2-graph.md §4.7, §1.4; P2-DECISIONS D-42).

const (
	trustPodSubject = "system:serviceaccount:payments:ledger-agent"
	trustPodIssuer  = "oidc.eks.eu-central-1.amazonaws.com/id/ABC"
)

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

// trustPodEdge reads the one pod-identity can_assume and its source node.
func trustPodEdge(t *testing.T, f *fixture) (id uuid.UUID, state, issuer, subject, kind string) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT r.id, r.state, ep.issuer, ep.subject_claim, ep.mechanism
	                           FROM iga_relationship r JOIN iga_external_principal ep ON ep.id = r.source_external_principal_id
	                          WHERE r.workspace_id = $1 AND r.mechanism = 'eks_pod_identity'`, f.workspace).
		Scan(&id, &state, &issuer, &subject, &kind); err != nil {
		t.Fatalf("pod-identity edge: %v", err)
	}
	return id, state, issuer, subject, kind
}

// §4.7's pod-identity loop passes the association's role without looking; a
// role outside this run's snapshot would be written as a uuid.Nil target. The
// projector skips it -- and projects the association whose role IS here, from
// a k8s_service_account node whose subject carries D-42's pod: prefix.
func TestTrustPodIdentityRoleOutsideTheSnapshotIsSkipped(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	orphan := uuid.New()
	f.exec(`INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	        VALUES ($1, $2, $3, 'iam_role', 'arn:aws:iam::111111111111:role/gone', 'gone', '{"unique_id":"AROAGONEGONEGONEGONE"}', 0)`,
		orphan, f.workspace, f.connector)
	trustPodRow(f, est.roleID, trustPodIssuer, `{}`, 1)
	trustPodRow(f, orphan, trustPodIssuer, `{}`, 1)
	run := f.publishedRun(f.connector, 1, trustPodCoverage())
	f.mustProject(est.load(run))

	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE relationship_type = 'can_assume'
	                    AND mechanism = 'eks_pod_identity' AND state = 'current'`); n != 1 {
		t.Fatalf("pod-identity edges = %d, want 1 (the role in the snapshot)", n)
	}
	_, _, issuer, subject, kind := trustPodEdge(t, f)
	if issuer != trustPodIssuer || subject != igagraph.PodIdentitySubject(trustPodSubject) ||
		kind != models.ExternalPrincipalK8sServiceAccount {
		t.Errorf("principal = (%q, %q, %q), want k8s_service_account %q under the cluster issuer",
			issuer, subject, kind, igagraph.PodIdentitySubject(trustPodSubject))
	}
}

// D-42: no cluster-ARN fallback. An association whose cluster issuer could not
// be read (a failed DescribeCluster) is left unresolved -- no edge, no
// issuer-less node, no node named by the cluster ARN, whose key would change
// the moment the issuer is read again -- and the role's pod-identity edge from
// the last good read goes STALE: eks_pod_identity was reached, so only the
// projector's protection keeps it from ending on a read it could not
// attribute.
func TestTrustPodIdentityWithoutAnIssuerIsUnresolved(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	cluster := "arn:aws:eks:eu-central-1:111111111111:cluster/prod"
	trustPodRow(f, est.roleID, trustPodIssuer, `{"cluster_arn":"`+cluster+`"}`, 1)
	f.mustProject(est.load(f.publishedRun(f.connector, 1, trustPodCoverage())))
	edge, state, _, _, _ := trustPodEdge(t, f)
	if state != models.RelCurrent {
		t.Fatalf("setup: pod-identity edge is %s, want current", state)
	}

	est.seed(2)
	f.exec(`UPDATE cloud_assume_edge SET issuer = NULL, last_seen_generation = 2 WHERE workspace_id = $1`, f.workspace)
	f.mustProject(est.load(f.publishedRun(f.connector, 2, trustPodCoverage())))

	var st, reason string
	if err := f.db.QueryRow(`SELECT state, ended_reason FROM iga_relationship WHERE id = $1`, edge).
		Scan(&st, &reason); err != nil {
		t.Fatal(err)
	}
	if st != models.RelStale || reason != "" {
		t.Errorf("pod-identity edge after an unattributable read = %s/%q, want stale: its cluster could not be named", st, reason)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND mechanism = 'eks_pod_identity'`,
		f.workspace); n != 1 {
		t.Errorf("pod-identity edges = %d, want the one from the last good read and no other", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = $1 AND (issuer = '' OR issuer = $2)`,
		f.workspace, cluster); n != 0 {
		t.Errorf("%d external principals with no issuer or the cluster ARN as issuer; want none (D-42)", n)
	}
}

// trustSetDocument stores a role's trust document as the collector does
// (035): verbatim, hashed, readable.
func trustSetDocument(f *fixture, roleID uuid.UUID, doc string) {
	f.t.Helper()
	f.exec(`UPDATE cloud_identity SET trust_document = $2::jsonb, trust_document_hash = md5($2::text), trust_parse_error = ''
	         WHERE id = $1`, roleID, doc)
}

// THE RETIREMENT CASCADE for an edge whose source is an external principal.
// External principals never retire (D-47), so nothing on the SOURCE side can
// ever end lambda.amazonaws.com -> role; only the TARGET's retirement can.
// Here the partition that would otherwise close the edge cannot: the
// permission scanner failed, which vetoes the trust partition (§4.10) but not
// the roles partition. The role, absent from a complete roles listing,
// retires -- and its can_assume from the external principal must end with it,
// subject_retired, rather than linger stale on a role that is gone. The node
// itself stays.
func TestTrustRetiredRoleEndsItsExternalEdges(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	trustSetDocument(f, est.roleID,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	f.mustProject(est.load(f.publishedRun(f.connector, 1, cleanCoverage(region))))

	var edge uuid.UUID
	if err := f.db.QueryRow(`SELECT r.id FROM iga_relationship r
	                           JOIN iga_external_principal ep ON ep.id = r.source_external_principal_id
	                          WHERE r.workspace_id = $1 AND r.relationship_type = 'can_assume' AND r.state = 'current'
	                            AND ep.mechanism = 'aws_service' AND ep.subject_claim = 'lambda.amazonaws.com'`,
		f.workspace).Scan(&edge); err != nil {
		t.Fatalf("setup: the role's aws_service can_assume: %v", err)
	}

	// Generation 2 lists no role at all (iam_roles reached), and the
	// permission scanner failed.
	cov := cleanCoverage(region)
	cov[models.SurfacePermissionScan] = denied()
	f.mustProject(est.load(f.publishedRun(f.connector, 2, cov)))

	var lifecycle string
	if err := f.db.QueryRow(`SELECT lifecycle FROM iga_identity_accounts WHERE workspace_id = $1 AND display_name = 'role'`,
		f.workspace).Scan(&lifecycle); err != nil || lifecycle != models.IGALifecycleRetired {
		t.Fatalf("setup: role lifecycle = %q (%v), want retired", lifecycle, err)
	}
	var st, reason string
	if err := f.db.QueryRow(`SELECT state, ended_reason FROM iga_relationship WHERE id = $1`, edge).Scan(&st, &reason); err != nil {
		t.Fatal(err)
	}
	if st != models.RelEnded || reason != models.EndedSubjectRetired {
		t.Errorf("external-sourced can_assume into the retired role = %s/%q, want ended subject_retired", st, reason)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = $1 AND subject_claim = 'lambda.amazonaws.com'`,
		f.workspace); n != 1 {
		t.Errorf("aws_service nodes = %d, want the node kept: external principals never retire", n)
	}
}

// A same-account principal is NOT given up merely because this run's snapshot
// lacks it: only a COMPLETE listing proves an identity gone. Here the role
// trusts a user of its own account; the next scan's user listing is denied,
// so the user is absent from the snapshot but still live in the graph (its
// support goes stale, it does not retire). The edge must stay the SAME row,
// current, sourced from that user -- not be re-sourced to an unresolved
// external principal on the strength of a read that did not happen.
func TestTrustUnlistedPrincipalOfADeniedListingStaysTheSource(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	const userARN = "arn:aws:iam::111111111111:user/priya"
	f.exec(`INSERT INTO cloud_identity (workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	        VALUES ($1, $2, 'iam_user', $3, 'priya', '{"unique_id":"AIDAPRIYAPRIYAPRIYA1"}', 1)`,
		f.workspace, f.connector, userARN)
	trustSetDocument(f, est.roleID, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"AWS":"`+userARN+`"},"Action":"sts:AssumeRole"}]}`)
	f.mustProject(est.load(f.publishedRun(f.connector, 1, cleanCoverage(region))))

	edgeOf := func() (id uuid.UUID, state, source string) {
		t.Helper()
		if err := f.db.QueryRow(`SELECT r.id, r.state, COALESCE(si.display_name, 'external')
		                           FROM iga_relationship r
		                           LEFT JOIN iga_identity_accounts si ON si.id = r.source_identity_account_id
		                          WHERE r.workspace_id = $1 AND r.relationship_type = 'can_assume' AND r.state <> 'ended'`,
			f.workspace).Scan(&id, &state, &source); err != nil {
			t.Fatalf("the one live can_assume: %v", err)
		}
		return id, state, source
	}
	first, state, source := edgeOf()
	if state != models.RelCurrent || source != "priya" {
		t.Fatalf("setup: can_assume = %s from %s, want current from priya", state, source)
	}

	est.seed(2) // the role (and its trust document) again; priya is not listed
	cov := cleanCoverage(region)
	cov[models.SurfaceIAMUsers] = denied()
	f.mustProject(est.load(f.publishedRun(f.connector, 2, cov)))

	id, state, source := edgeOf()
	if id != first || state != models.RelCurrent || source != "priya" {
		t.Errorf("after a denied user listing: edge %s %s from %s, want the same row %s, current, from priya",
			id, state, source, first)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = $1`, f.workspace); n != 0 {
		t.Errorf("%d external principals: a user we could not list is not an unknown principal", n)
	}
}

// §4.7: "parsed at collection, failed now" is a hard error. A trust document
// the collector recorded READABLE (an empty trust_parse_error) that the projector
// cannot fully read is an inconsistency between the two, and the pass fails
// loudly -- it never projects the readable neighbours and ends what the
// unreadable statement declared.
func TestTrustReadableAtCollectionUnreadableNowFailsThePass(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::111111111111:role/ledger-role", "AROALEDGERROLELEDGER")
	est.seed(1)
	trustSetDocument(f, est.roleID, `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},`+
		`{"Effect":"Allow","Principal":{"AWS":12},"Action":"sts:AssumeRole"}]}`)
	err := f.project(est.load(f.publishedRun(f.connector, 1, cleanCoverage(region))))
	if err == nil || !strings.Contains(err.Error(), "parsed at collection") {
		t.Fatalf("project = %v, want the pass to fail: collection said readable, projection cannot read it", err)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND relationship_type = 'can_assume'`,
		f.workspace); n != 0 {
		t.Errorf("%d can_assume rows written by a failed pass", n)
	}
}
