package integration

// T3.4 + T4.7 through the REAL pipeline (SPEC-iga-phase2-graph.md §4.7 Trust,
// §2.12, §2.3; P2-DECISIONS D-41..D-47, D-88): the IAM scanner writes each
// role's trust document (cloud_identity.trust_document, trust_parse_error), the
// projector turns it into can_assume edges and external principals, and
// reconciliation keeps what could not be read.
//
// Every scenario below runs AWSScanWorker and ProjectionService under
// different owner names, with every AWS call answered by the P2-0 lab's fakes.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

const (
	trustAccountC = "300000000003" // partner: NEVER connected

	trustGitHubProvider = "arn:aws:iam::" + accountA + ":oidc-provider/token.actions.githubusercontent.com"
	trustSAMLProvider   = "arn:aws:iam::" + accountA + ":saml-provider/Okta"
	trustEKSProvider    = "arn:aws:iam::" + accountA + ":oidc-provider/" + eksIssuerNoSch
)

// trustDoc wraps statements in a trust document.
func trustDoc(statements ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
}

// trustAllow is one Allow statement for a principal block and action.
func trustAllow(principal, action string) string {
	return `{"Effect":"Allow","Principal":` + principal + `,"Action":"` + action + `"}`
}

// trustSetDoc replaces a role's AssumeRolePolicyDocument, URL-encoded as IAM
// returns it. The current IAM scanner writes it to cloud_identity itself.
func trustSetDoc(a *p2Account, roleName, doc string) {
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) == roleName {
			a.iam.roles[i].AssumeRolePolicyDocument = aws.String(url.QueryEscape(doc))
			return
		}
	}
	panic("trustSetDoc: no role " + roleName)
}

// trustRole adds a role whose trust document is doc.
func trustRole(a *p2Account, name, roleID, doc string) string {
	arn := a.role(name, roleID)
	trustSetDoc(a, name, doc)
	return arn
}

// trustRemoveRole deletes a role from the account's IAM.
func trustRemoveRole(a *p2Account, name string) {
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) == name {
			a.iam.roles = append(a.iam.roles[:i], a.iam.roles[i+1:]...)
			return
		}
	}
}

// trustScan is l.scan with an EKS fake of the test's choosing (the lab's own
// hook answers EKS with an empty fake).
func trustScan(l *p2Lab, a *p2Account, eks *fakeEKS, owner string) models.CloudScanRun {
	l.t.Helper()
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	base := a.hook()
	hook := func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		base(iamS, perm, wl)
		if eks != nil {
			perm.WithEKSAPI(eks)
		}
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).
		WithGraphProjection(l.gate).WithScannerHook(hook)
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker %s: worked=%v err=%v", owner, worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		l.t.Fatalf("read run: %v", err)
	}
	if run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %s is %s (%s), want published", run.ID, run.Status, run.LastError)
	}
	return run
}

var trustSeq int

// trustCycle is one scan (with an optional EKS fake) and one projection.
func trustCycle(l *p2Lab, a *p2Account, eks *fakeEKS) models.CloudScanRun {
	l.t.Helper()
	trustSeq++
	run := trustScan(l, a, eks, fmt.Sprintf("trust-scan-%d", trustSeq))
	l.project(fmt.Sprintf("trust-projector-%d", trustSeq))
	return run
}

// trustEdge is one can_assume row with both endpoints described.
type trustEdge struct {
	ID             uuid.UUID
	SourceKey      string
	Target         string
	State          string
	EndedReason    string
	Mechanism      string
	StatementKey   string
	Conditions     *string
	ValidFrom      time.Time
	LastConfirmed  time.Time
	SourceIdentity *uuid.UUID
	SourceName     string // the source identity's display name, when an identity
	ExtID          *uuid.UUID
	ExtKind        string
	ExtIssuer      string
	ExtSubject     string
	ExtResolved    *uuid.UUID
	ExtBasis       string
	Evidence       int
}

func trustEdges(l *p2Lab) []trustEdge {
	l.t.Helper()
	var out []trustEdge
	if err := l.db.Raw(`
		SELECT r.id, r.source_key, t.display_name AS target, r.state, r.ended_reason, r.mechanism, r.statement_key,
		       r.conditions::text AS conditions, r.valid_from, r.last_confirmed_at AS last_confirmed,
		       r.source_identity_account_id AS source_identity, COALESCE(si.display_name, '') AS source_name,
		       r.source_external_principal_id AS ext_id, COALESCE(ep.mechanism, '') AS ext_kind,
		       COALESCE(ep.issuer, '') AS ext_issuer, COALESCE(ep.subject_claim, '') AS ext_subject,
		       ep.resolved_identity_account_id AS ext_resolved, COALESCE(ep.resolution_basis, '') AS ext_basis,
		       (SELECT count(*) FROM iga_relationship_evidence e WHERE e.relationship_id = r.id) AS evidence
		  FROM iga_relationship r
		  JOIN iga_identity_accounts t ON t.id = r.target_identity_account_id
		  LEFT JOIN iga_identity_accounts si ON si.id = r.source_identity_account_id
		  LEFT JOIN iga_external_principal ep ON ep.id = r.source_external_principal_id
		 WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume'
		 ORDER BY t.display_name, r.created_at, r.id`, l.ws).Scan(&out).Error; err != nil {
		l.t.Fatalf("read can_assume: %v", err)
	}
	return out
}

// trustEdgesTo filters edges by the target role's display name. A recreated
// role and its predecessor share a name, so both incarnations' edges appear.
func trustEdgesTo(edges []trustEdge, target string) []trustEdge {
	var out []trustEdge
	for _, e := range edges {
		if e.Target == target {
			out = append(out, e)
		}
	}
	return out
}

// trustNode reads the external principal a (issuer, subject) names.
func trustNode(l *p2Lab, issuer, subject string) (models.IGAExternalPrincipal, bool) {
	l.t.Helper()
	var ep models.IGAExternalPrincipal
	err := l.db.Where("workspace_id = ? AND source_key = ?", l.ws, igagraph.ExternalPrincipalKey(issuer, subject)).
		Limit(1).Find(&ep).Error
	if err != nil {
		l.t.Fatalf("read external principal %s/%s: %v", issuer, subject, err)
	}
	return ep, ep.ID != uuid.Nil
}

// trustProviderAttrs reads a role's provider_attrs trust flags.
func trustProviderAttrs(l *p2Lab, role string) (deny, notPrincipal *bool) {
	var row struct {
		Deny *bool
		NP   *bool
	}
	l.db.Raw(`SELECT (provider_attrs->>'trust_has_deny')::boolean AS deny,
	                 (provider_attrs->>'trust_has_not_principal')::boolean AS np
	            FROM iga_identity_accounts WHERE workspace_id = ? AND display_name = ? AND lifecycle = 'active'`,
		l.ws, role).Scan(&row)
	return row.Deny, row.NP
}

func trustIdentityID(l *p2Lab, role string) uuid.UUID {
	l.t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND display_name = ? AND lifecycle = 'active'`,
		l.ws, role).Row().Scan(&id); err != nil {
		l.t.Fatalf("identity %s: %v", role, err)
	}
	return id
}

func trustBool(b *bool) string {
	if b == nil {
		return "<absent>"
	}
	return fmt.Sprint(*b)
}

/* ================================ scenarios ============================== */

// T4.7's gate and E11's first half: same-account, cross-account, service,
// OIDC, SAML and "*" principals all appear, each as the node §4.7's table and
// D-42 say; Deny and NotPrincipal produce no edge and set the role's flags; a
// condition with non-string values no longer fails the document. Then an
// unchanged rescan keeps every can_assume and external-principal id and
// first_seen_at.
func TestP2TrustPrincipalsAppear(t *testing.T) {
	l := newP2Lab(t, "p2-trust-principals", true)
	a := l.account(accountA)
	helper := a.role("helper", "AROAHELPERHELPERHELP")
	trustRole(a, "self-trust", "AROASELFTRUSTSELFTRU", trustDoc(trustAllow(`{"AWS":"`+helper+`"}`, "sts:AssumeRole")))
	trustRole(a, "partner-access", "AROAPARTNERACCESS001", trustDoc(
		trustAllow(`{"AWS":["arn:aws:iam::`+trustAccountC+`:role/partner-role","arn:aws:iam::`+trustAccountC+`:root"]}`, "sts:AssumeRole")))
	trustRole(a, "gha-deploy", "AROAGHADEPLOYGHADEPL", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},`+
			`"StringLike":{"token.actions.githubusercontent.com:sub":"repo:authsec-ai/authsec:*"}}}`))
	trustRole(a, "gha-envs", "AROAGHAENVSGHAENVSGH", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":`+
			`["repo:authsec-ai/authsec:environment:prod","repo:authsec-ai/authsec:ref:refs/heads/main"]}}}`))
	trustRole(a, "gha-unscoped", "AROAGHAUNSCOPED00001", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity"}`))
	trustRole(a, "saml-admin", "AROASAMLADMINSAMLADM", trustDoc(
		trustAllow(`{"Federated":"`+trustSAMLProvider+`"}`, "sts:AssumeRoleWithSAML")))
	trustRole(a, "open-role", "AROAOPENROLEOPENROLE", trustDoc(trustAllow(`"*"`, "sts:AssumeRole")))
	trustRole(a, "open-aws-role", "AROAOPENAWSROLEOPENA", trustDoc(trustAllow(`{"AWS":"*"}`, "sts:AssumeRole")))
	trustRole(a, "deny-role", "AROADENYROLEDENYROLE", trustDoc(
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		`{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},"Action":"sts:AssumeRole"}`))
	trustRole(a, "notprincipal-role", "AROANOTPRINCIPAL0001", trustDoc(
		`{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},"Action":"sts:AssumeRole"}`))
	trustRole(a, "mfa-role", "AROAMFAROLEMFAROLEMF", trustDoc(
		`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},"Action":"sts:AssumeRole",`+
			`"Condition":{"Bool":{"aws:MultiFactorAuthPresent":true},"NumericLessThan":{"aws:MultiFactorAuthAge":3600}}}`))
	trustCycle(l, a, nil)

	// Collection: every role's document is stored and readable, including the
	// one whose condition values are a boolean and a number (T3.4's gate).
	var unreadable []string
	l.db.Raw(`SELECT name FROM cloud_identity WHERE workspace_id = ? AND kind = 'iam_role'
	            AND (trust_document IS NULL OR trust_document_hash = '' OR trust_parse_error <> '')`, l.ws).
		Scan(&unreadable)
	if len(unreadable) != 0 {
		t.Fatalf("roles with no readable trust document after the scan: %v", unreadable)
	}

	edges := trustEdges(l)
	one := func(target string) trustEdge {
		t.Helper()
		got := trustEdgesTo(edges, target)
		if len(got) != 1 {
			t.Fatalf("%s: %d can_assume edges %+v, want 1", target, len(got), got)
		}
		return got[0]
	}
	// Same account: the identity itself, basis declared.
	if e := one("self-trust"); e.SourceIdentity == nil || e.SourceName != "helper" || e.ExtID != nil ||
		e.Mechanism != models.MechanismSTSAssumeRole {
		t.Errorf("self-trust = %+v, want identity-sourced from helper, sts_assume_role", e)
	}
	// An unconnected account: its role is an unresolved aws_principal named by
	// its ARN, its root an aws_account whose subject is the account id parsed
	// out of the ARN.
	partner := trustEdgesTo(edges, "partner-access")
	kinds := map[string]trustEdge{}
	for _, e := range partner {
		kinds[e.ExtKind] = e
	}
	if len(partner) != 2 || kinds[models.ExternalPrincipalAWSPrincipal].ExtSubject != "arn:aws:iam::"+trustAccountC+":role/partner-role" ||
		kinds[models.ExternalPrincipalAWSPrincipal].ExtResolved != nil ||
		kinds[models.ExternalPrincipalAWSAccount].ExtSubject != trustAccountC {
		t.Errorf("partner-access = %+v, want an unresolved aws_principal (the role) and an aws_account %s", partner, trustAccountC)
	}
	for _, e := range partner {
		if e.SourceIdentity != nil || e.ExtIssuer != "aws" {
			t.Errorf("partner edge %+v: an unconnected account's principal must be external, issuer aws", e)
		}
	}
	if e := one("gha-deploy"); e.ExtKind != models.ExternalPrincipalOIDC || e.ExtIssuer != "token.actions.githubusercontent.com" ||
		e.ExtSubject != "repo:authsec-ai/authsec:*" || e.ExtResolved != nil || e.Mechanism != models.MechanismOIDCFederation ||
		e.Conditions == nil || !strings.Contains(*e.Conditions, "repo:authsec-ai/authsec:*") {
		t.Errorf("gha-deploy = %+v, want an unresolved oidc principal with the wildcard subject and its condition", e)
	}
	// Every positive sub value is its own principal and its own edge.
	envs := map[string]bool{}
	for _, e := range trustEdgesTo(edges, "gha-envs") {
		envs[e.ExtSubject] = e.ExtKind == models.ExternalPrincipalOIDC && e.Mechanism == models.MechanismOIDCFederation
	}
	if len(envs) != 2 || !envs["repo:authsec-ai/authsec:environment:prod"] || !envs["repo:authsec-ai/authsec:ref:refs/heads/main"] {
		t.Errorf("gha-envs subjects = %v, want one oidc edge per sub value", envs)
	}
	if e := one("gha-unscoped"); e.ExtKind != models.ExternalPrincipalOIDC || e.ExtSubject != "*" || e.Conditions != nil {
		t.Errorf("gha-unscoped = %+v, want oidc subject * and NULL conditions", e)
	}
	if e := one("saml-admin"); e.ExtKind != models.ExternalPrincipalSAML || e.ExtIssuer != trustSAMLProvider ||
		e.ExtSubject != "*" || e.Mechanism != models.MechanismSAMLFederation {
		t.Errorf("saml-admin = %+v, want saml issuer %s subject *, saml_federation", e, trustSAMLProvider)
	}
	// "*" either way it is spelled: ONE aws_account node, subject "*" (D-42).
	open, openAWS := one("open-role"), one("open-aws-role")
	if open.ExtKind != models.ExternalPrincipalAWSAccount || open.ExtSubject != "*" || open.ExtID == nil ||
		openAWS.ExtID == nil || *openAWS.ExtID != *open.ExtID || open.Mechanism != models.MechanismSTSAssumeRole {
		t.Errorf("open-role = %+v, open-aws-role = %+v; want both from the one aws_account \"*\" node", open, openAWS)
	}
	// The lab's Lambda trust: aws_service lambda.amazonaws.com (§4.12).
	if e := one("helper"); e.ExtKind != models.ExternalPrincipalAWSService || e.ExtSubject != "lambda.amazonaws.com" ||
		e.Mechanism != models.MechanismSTSAssumeRole {
		t.Errorf("helper = %+v, want aws_service lambda.amazonaws.com via sts_assume_role", e)
	}
	// Deny: the Allow's edge only, and the flag.
	if e := one("deny-role"); e.ExtSubject != "lambda.amazonaws.com" {
		t.Errorf("deny-role's only edge = %+v, want the Allow principal; a Deny is never an edge", e)
	}
	if deny, np := trustProviderAttrs(l, "deny-role"); deny == nil || !*deny || np == nil || *np {
		t.Errorf("deny-role flags = deny %s not_principal %s, want true/false", trustBool(deny), trustBool(np))
	}
	// NotPrincipal: no edge at all, and the flag.
	if got := trustEdgesTo(edges, "notprincipal-role"); len(got) != 0 {
		t.Errorf("notprincipal-role edges = %+v, want none: NotPrincipal is never resolved", got)
	}
	if deny, np := trustProviderAttrs(l, "notprincipal-role"); np == nil || !*np || deny == nil || *deny {
		t.Errorf("notprincipal-role flags = deny %s not_principal %s, want false/true", trustBool(deny), trustBool(np))
	}
	// The non-string condition, verbatim on the edge.
	if e := one("mfa-role"); e.Conditions == nil || !strings.Contains(*e.Conditions, `"aws:MultiFactorAuthPresent": true`) ||
		!strings.Contains(*e.Conditions, `"aws:MultiFactorAuthAge": 3600`) {
		t.Errorf("mfa-role = %+v, want the Bool and Numeric condition recorded verbatim", e)
	}
	// One external principal per far endpoint, shared: account C's root is
	// named by deny-role (a Deny, no node), partner-access and mfa-role.
	if n := l.count(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = ? AND source_key = ?`,
		l.ws, igagraph.ExternalPrincipalKey("aws", trustAccountC)); n != 1 {
		t.Errorf("%d nodes for account %s, want one shared node", n, trustAccountC)
	}
	// T4.9, per edge: every can_assume has evidence (the role's observation).
	for _, e := range edges {
		if e.Evidence == 0 || e.State != models.RelCurrent {
			t.Errorf("edge to %s = %+v, want current with evidence", e.Target, e)
		}
	}

	// Unchanged rescan: same ids, same first_seen_at, same counts.
	var eps1 []models.IGAExternalPrincipal
	l.db.Where("workspace_id = ?", l.ws).Order("source_key").Find(&eps1)
	time.Sleep(10 * time.Millisecond)
	trustCycle(l, a, nil)
	after := trustEdges(l)
	if len(after) != len(edges) {
		t.Fatalf("can_assume rows %d -> %d on an unchanged rescan", len(edges), len(after))
	}
	for i := range edges {
		if after[i].ID != edges[i].ID || !after[i].ValidFrom.Equal(edges[i].ValidFrom) || after[i].State != models.RelCurrent {
			t.Errorf("edge %s -> %+v changed on an unchanged rescan", edges[i].ID, after[i])
		}
	}
	var eps2 []models.IGAExternalPrincipal
	l.db.Where("workspace_id = ?", l.ws).Order("source_key").Find(&eps2)
	if len(eps2) != len(eps1) {
		t.Fatalf("external principals %d -> %d on an unchanged rescan", len(eps1), len(eps2))
	}
	for i := range eps1 {
		if eps2[i].ID != eps1[i].ID || !eps2[i].FirstSeenAt.Equal(eps1[i].FirstSeenAt) || !eps2[i].LastSeenAt.After(eps1[i].LastSeenAt) {
			t.Errorf("external principal %s: id/first_seen %s/%s -> %s/%s, last_seen %s -> %s",
				eps1[i].SourceKey, eps1[i].ID, eps1[i].FirstSeenAt, eps2[i].ID, eps2[i].FirstSeenAt,
				eps1[i].LastSeenAt, eps2[i].LastSeenAt)
		}
	}
}

// B12's trust analogue, in ONE run: a role whose trust document gained one
// malformed statement is unreadable (trust_parse_error), so its existing
// can_assume edges go STALE -- never ended, last confirmation kept -- even the
// one whose principal the new document dropped; while other roles' removed
// principals, in the same run, END not_seen.
func TestP2TrustUnreadableDocumentKeepsItsEdges(t *testing.T) {
	l := newP2Lab(t, "p2-trust-unreadable", true)
	a := l.account(accountA)
	two := trustDoc(trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		trustAllow(`{"AWS":"arn:aws:iam::`+trustAccountC+`:root"}`, "sts:AssumeRole"),
		`{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::`+trustAccountC+`:role/blocked"},"Action":"sts:AssumeRole"}`)
	trustRole(a, "broken-later", "AROABROKENLATER00001", two)
	// Two clean roles whose documents drop ecs-tasks next run: one keyed by a
	// Sid (the statement, and its lambda edge, keep their identity), one
	// without (its content changed, so its lambda edge is replaced -- §2.6).
	both := `{"Service":["lambda.amazonaws.com","ecs-tasks.amazonaws.com"]}`
	trustRole(a, "edited-sid", "AROAEDITEDSIDEDITEDS",
		trustDoc(`{"Sid":"Services","Effect":"Allow","Principal":`+both+`,"Action":"sts:AssumeRole"}`))
	trustRole(a, "edited-nosid", "AROAEDITEDNOSIDEDITE", trustDoc(trustAllow(both, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	before := trustEdges(l)
	if n := len(trustEdgesTo(before, "broken-later")); n != 2 {
		t.Fatalf("setup: broken-later has %d edges, want 2", n)
	}

	// Rescan: broken-later drops account C AND gains a malformed statement;
	// edited drops ecs-tasks (a clean document).
	trustSetDoc(a, "broken-later", trustDoc(trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		`{"Effect":"Allow","Principal":{"AWS":12},"Action":"sts:AssumeRole"}`))
	trustSetDoc(a, "edited-sid", trustDoc(
		`{"Sid":"Services","Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}`))
	trustSetDoc(a, "edited-nosid", trustDoc(trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole")))
	time.Sleep(10 * time.Millisecond)
	trustCycle(l, a, nil)

	var parseErr string
	l.db.Raw(`SELECT trust_parse_error FROM cloud_identity WHERE workspace_id = ? AND name = 'broken-later'`, l.ws).
		Scan(&parseErr)
	if !strings.HasPrefix(parseErr, "parse: 1 statement(s) unusable") {
		t.Fatalf("trust_parse_error = %q, want the unusable statement named", parseErr)
	}
	// Its trust flags are not re-derived from a document we could not read:
	// what the same incarnation carried stands.
	if deny, np := trustProviderAttrs(l, "broken-later"); deny == nil || !*deny || np == nil || *np {
		t.Errorf("unreadable role's flags = deny %s not_principal %s, want the last read's true/false",
			trustBool(deny), trustBool(np))
	}
	after := trustEdges(l)
	prev := map[uuid.UUID]trustEdge{}
	for _, e := range before {
		prev[e.ID] = e
	}
	broken := trustEdgesTo(after, "broken-later")
	if len(broken) != 2 {
		t.Errorf("unreadable role has %d edges %+v, want its 2 and no new one", len(broken), broken)
	}
	for _, e := range broken {
		if e.State != models.RelStale || !e.LastConfirmed.Equal(prev[e.ID].LastConfirmed) {
			t.Errorf("unreadable role's edge %s (%s) = %s, confirmed %s -> %s; want STALE with its last confirmation kept",
				e.ExtSubject, e.ID, e.State, prev[e.ID].LastConfirmed, e.LastConfirmed)
		}
	}
	// The same run's clean documents reconcile normally: the partition could
	// end, and did, for exactly what the documents stopped saying.
	for role, sidKeyed := range map[string]bool{"edited-sid": true, "edited-nosid": false} {
		var oldLambda uuid.UUID
		for _, e := range trustEdgesTo(before, role) {
			if e.ExtSubject == "lambda.amazonaws.com" {
				oldLambda = e.ID
			}
		}
		var currentLambda []uuid.UUID
		for _, e := range trustEdgesTo(after, role) {
			switch {
			case e.ExtSubject == "ecs-tasks.amazonaws.com":
				if e.State != models.RelEnded || e.EndedReason != models.EndedNotSeen {
					t.Errorf("%s's removed principal = %s/%s, want ended not_seen", role, e.State, e.EndedReason)
				}
			case e.State == models.RelCurrent:
				currentLambda = append(currentLambda, e.ID)
			case e.ID == oldLambda && (e.State != models.RelEnded || e.EndedReason != models.EndedNotSeen):
				t.Errorf("%s's replaced lambda edge = %s/%s, want ended not_seen", role, e.State, e.EndedReason)
			}
		}
		if len(currentLambda) != 1 || (currentLambda[0] == oldLambda) != sidKeyed {
			t.Errorf("%s: current lambda edges %v (was %s); want one, the SAME row only when the statement has a Sid",
				role, currentLambda, oldLambda)
		}
	}
}

// D-41 rule 1 and §2.12: A's role trusts B's data-reader before B is
// connected -- an unresolved aws_principal. B connects: B's own pass gives the
// NODE a derived resolution to data-reader, and A's next pass keeps THE SAME
// EDGE (same id, same valid_from), still sourced from that node -- continuity
// is the node's, the edge is never re-pointed. B's data-reader is then
// deleted: the resolution is re-derived away (unresolved), and A's edge --
// A's declaration -- is untouched.
func TestP2TrustFarAccountConnectsLater(t *testing.T) {
	l := newP2Lab(t, "p2-trust-far", true)
	a := l.account(accountA)
	reader := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "reader-access", "AROAREADERACCESS0001", trustDoc(trustAllow(`{"AWS":"`+reader+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	first := trustEdgesTo(trustEdges(l), "reader-access")
	if len(first) != 1 || first[0].ExtKind != models.ExternalPrincipalAWSPrincipal || first[0].ExtSubject != reader ||
		first[0].ExtResolved != nil {
		t.Fatalf("before B connects = %+v, want one edge from an unresolved aws_principal %s", first, reader)
	}
	edgeID, validFrom, extID := first[0].ID, first[0].ValidFrom, *first[0].ExtID

	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERDATARE")
	trustCycle(l, b, nil)
	readerID := trustIdentityID(l, "data-reader")
	if ep, _ := trustNode(l, "aws", reader); ep.ID != extID || ep.ResolutionBasis != models.BasisDerived ||
		ep.ResolutionRule != models.ResolutionRuleExactARN || ep.ResolvedIdentityAccountID == nil ||
		*ep.ResolvedIdentityAccountID != readerID {
		t.Errorf("after B's pass the node = %+v, want a derived exact_arn_match resolution to data-reader %s", ep, readerID)
	}
	time.Sleep(10 * time.Millisecond)
	trustCycle(l, a, nil)

	now := trustEdgesTo(trustEdges(l), "reader-access")
	if len(now) != 1 {
		t.Fatalf("after B connects: %d edges %+v, want the one row", len(now), now)
	}
	if e := now[0]; e.ID != edgeID || !e.ValidFrom.Equal(validFrom) || e.State != models.RelCurrent ||
		e.ExtID == nil || *e.ExtID != extID || e.SourceIdentity != nil || !e.LastConfirmed.After(first[0].LastConfirmed) {
		t.Errorf("after B connects = %+v, want edge %s (valid_from %s) current, confirmed again, still from node %s",
			e, edgeID, validFrom, extID)
	}

	// data-reader is recreated under the same ARN: an exact ARN match now
	// names the NEW object, which is right for a mechanical fact (§2.12's
	// "recreated" row) -- re-derived in B's own pass, A's edge untouched.
	b.role("data-reader", "AROADATAREADERSECOND")
	trustCycle(l, b, nil)
	secondID := trustIdentityID(l, "data-reader")
	if ep, _ := trustNode(l, "aws", reader); secondID == readerID || ep.ResolutionBasis != models.BasisDerived ||
		ep.ResolvedIdentityAccountID == nil || *ep.ResolvedIdentityAccountID != secondID {
		t.Errorf("after data-reader is recreated the node = %+v, want it re-derived to the new data-reader %s (was %s)",
			ep, secondID, readerID)
	}

	// B's data-reader is deleted; B's rescan retires it.
	trustRemoveRole(b, "data-reader")
	trustCycle(l, b, nil)
	if ep, _ := trustNode(l, "aws", reader); ep.ResolvedIdentityAccountID != nil || ep.ResolutionBasis != "" {
		t.Errorf("after data-reader retires the node = %+v, want the derived resolution re-derived away", ep)
	}
	gone := trustEdgesTo(trustEdges(l), "reader-access")
	if len(gone) != 1 || gone[0].ID != edgeID || gone[0].State != models.RelCurrent {
		t.Errorf("after data-reader retires = %+v, want edge %s untouched: it is A's declaration", gone, edgeID)
	}
}

// D-41 rule 2 and "no edge is re-pointed": B is connected first, so A's trust
// of B's data-reader is an identity-sourced edge crossing accounts, and no
// external principal exists for it. data-reader is then deleted: B's pass
// ENDS the edge subject_retired (the ordinary cascade -- its source is gone),
// and A's next pass, whose document still names the ARN, re-sources the
// principal as a NEW edge from an unresolved aws_principal.
func TestP2TrustConnectedIdentityIsTheSource(t *testing.T) {
	l := newP2Lab(t, "p2-trust-connected", true)
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERCONNEC")
	trustCycle(l, b, nil)
	readerID := trustIdentityID(l, "data-reader")

	a := l.account(accountA)
	reader := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "reader-access", "AROAREADERACCESSCONN", trustDoc(trustAllow(`{"AWS":"`+reader+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	first := trustEdgesTo(trustEdges(l), "reader-access")
	if len(first) != 1 || first[0].SourceIdentity == nil || *first[0].SourceIdentity != readerID || first[0].ExtID != nil {
		t.Fatalf("A's trust of connected B = %+v, want identity-sourced from data-reader %s", first, readerID)
	}
	if _, ok := trustNode(l, "aws", reader); ok {
		t.Error("an external principal exists for a principal that is a live identity in a connected account")
	}

	trustRemoveRole(b, "data-reader")
	trustCycle(l, b, nil)
	ended := trustEdgesTo(trustEdges(l), "reader-access")
	if len(ended) != 1 || ended[0].ID != first[0].ID || ended[0].State != models.RelEnded ||
		ended[0].EndedReason != models.EndedSubjectRetired || ended[0].SourceIdentity == nil {
		t.Fatalf("after data-reader retires = %+v, want edge %s ended subject_retired, its source unchanged", ended, first[0].ID)
	}
	// The retired role's OWN trust edges end with it: its lab Lambda trust is
	// sourced from an external principal (aws_service), which never retires.
	// B's trust partition was fully read and no longer names it, so partition
	// reconciliation ends it not_seen before retireUnsupported runs (D-67); the
	// retirement cascade alone is proven in tests/igagraph
	// (TestTrustRetiredRoleEndsItsExternalEdges), where the partition cannot end.
	own := trustEdgesTo(trustEdges(l), "data-reader")
	if len(own) != 1 || own[0].ExtKind != models.ExternalPrincipalAWSService || own[0].State != models.RelEnded ||
		own[0].EndedReason != models.EndedNotSeen {
		t.Errorf("retired data-reader's own trust edges = %+v, want its aws_service edge ended not_seen (D-67)", own)
	}
	if _, ok := trustNode(l, "aws", "lambda.amazonaws.com"); !ok {
		t.Error("the aws_service node was removed with the role; external principals never retire (D-47)")
	}

	trustCycle(l, a, nil)
	edges := trustEdgesTo(trustEdges(l), "reader-access")
	var fresh []trustEdge
	for _, e := range edges {
		if e.ID != first[0].ID {
			fresh = append(fresh, e)
		}
	}
	if len(edges) != 2 || len(fresh) != 1 || fresh[0].State != models.RelCurrent || fresh[0].ExtID == nil ||
		fresh[0].ExtKind != models.ExternalPrincipalAWSPrincipal || fresh[0].ExtSubject != reader || fresh[0].ExtResolved != nil {
		t.Errorf("A's next pass = %+v, want the ended edge plus a NEW edge from an unresolved aws_principal %s", edges, reader)
	}
}

// E11: loop-a and loop-b in B trust each other -- a cycle -- and both edges
// are projected, identity to identity.
func TestP2TrustLoopProjectsBothEdges(t *testing.T) {
	l := newP2Lab(t, "p2-trust-loop", true)
	b := l.account(accountB)
	loopA, loopB := "arn:aws:iam::"+accountB+":role/loop-a", "arn:aws:iam::"+accountB+":role/loop-b"
	trustRole(b, "loop-a", "AROALOOPALOOPALOOPA1", trustDoc(trustAllow(`{"AWS":"`+loopB+`"}`, "sts:AssumeRole")))
	trustRole(b, "loop-b", "AROALOOPBLOOPBLOOPB1", trustDoc(trustAllow(`{"AWS":"`+loopA+`"}`, "sts:AssumeRole")))
	trustCycle(l, b, nil)
	edges := trustEdges(l)
	for target, source := range map[string]string{"loop-a": "loop-b", "loop-b": "loop-a"} {
		got := trustEdgesTo(edges, target)
		if len(got) != 1 || got[0].SourceName != source || got[0].State != models.RelCurrent || got[0].Evidence == 0 {
			t.Errorf("%s <- %+v, want one current, evidenced edge from %s", target, got, source)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Errorf("%d external principals for a same-account cycle, want 0", n)
	}
}

// A trusted role deleted and recreated (B7 for trust). AWS rewrites a trust
// policy naming a deleted principal to that principal's unique id, which
// never resolves: consumer's identity edge ENDS and an edge from an unresolved
// aws_principal "AROA…" begins. follower's document still names the ARN: its
// old edge ends subject_recreated and a NEW edge -- a new key, naming the new
// incarnation's endpoint -- comes from the new producer.
func TestP2TrustRecreatedTrustedRole(t *testing.T) {
	l := newP2Lab(t, "p2-trust-recreated", true)
	a := l.account(accountA)
	producer := a.role("producer", "AROAPRODUCEROLD00001")
	trustRole(a, "consumer", "AROACONSUMERCONSUMER", trustDoc(trustAllow(`{"AWS":"`+producer+`"}`, "sts:AssumeRole")))
	trustRole(a, "follower", "AROAFOLLOWERFOLLOWER", trustDoc(trustAllow(`{"AWS":"`+producer+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	oldProducer := trustIdentityID(l, "producer")
	before := trustEdges(l)
	follower := trustEdgesTo(before, "follower")
	if len(follower) != 1 || follower[0].SourceIdentity == nil || *follower[0].SourceIdentity != oldProducer {
		t.Fatalf("setup: follower = %+v, want sourced from producer", follower)
	}

	a.role("producer", "AROAPRODUCERNEW00001") // same name, new RoleId
	trustSetDoc(a, "consumer", trustDoc(trustAllow(`{"AWS":"AROAPRODUCEROLD00001"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	newProducer := trustIdentityID(l, "producer")
	if newProducer == oldProducer {
		t.Fatal("setup: the recreated producer kept its identity")
	}
	edges := trustEdges(l)
	consumer := trustEdgesTo(edges, "consumer")
	var ended, live []trustEdge
	for _, e := range consumer {
		if e.State == models.RelEnded {
			ended = append(ended, e)
		} else {
			live = append(live, e)
		}
	}
	if len(ended) != 1 || ended[0].SourceIdentity == nil || *ended[0].SourceIdentity != oldProducer ||
		ended[0].EndedReason != models.EndedSubjectRecreate {
		t.Errorf("consumer's identity edge = %+v, want ended subject_recreated", ended)
	}
	if len(live) != 1 || live[0].ExtKind != models.ExternalPrincipalAWSPrincipal || live[0].ExtSubject != "AROAPRODUCEROLD00001" ||
		live[0].ExtResolved != nil || live[0].SourceIdentity != nil {
		t.Errorf("consumer's live edge = %+v, want an unresolved aws_principal AROAPRODUCEROLD00001", live)
	}
	f := trustEdgesTo(edges, "follower")
	var old, fresh *trustEdge
	for i := range f {
		if f[i].ID == follower[0].ID {
			old = &f[i]
		} else {
			fresh = &f[i]
		}
	}
	if len(f) != 2 || old == nil || fresh == nil {
		t.Fatalf("follower = %+v, want its old edge and one new edge", f)
	}
	if old.State != models.RelEnded || old.EndedReason != models.EndedSubjectRecreate || old.SourceIdentity == nil ||
		*old.SourceIdentity != oldProducer {
		t.Errorf("follower's old edge = %+v, want ended subject_recreated, still from the OLD producer: never re-pointed", *old)
	}
	if fresh.State != models.RelCurrent || fresh.SourceIdentity == nil || *fresh.SourceIdentity != newProducer ||
		fresh.SourceKey == old.SourceKey {
		t.Errorf("follower's new edge = %+v, want current from the new producer under a NEW key (old key %q)", *fresh, old.SourceKey)
	}
	// The recreated role's OWN trust edges (it is their target) end, and the
	// new role's are new rows.
	oldOwn := trustEdgesTo(before, "producer")
	for _, e := range trustEdgesTo(edges, "producer") {
		switch {
		case e.ID == oldOwn[0].ID && (e.State != models.RelEnded || e.EndedReason != models.EndedSubjectRecreate):
			t.Errorf("old producer's trust edge = %s/%s, want ended subject_recreated", e.State, e.EndedReason)
		case e.ID != oldOwn[0].ID && e.State != models.RelCurrent:
			t.Errorf("new producer's trust edge = %s, want current", e.State)
		}
	}
	if n := len(trustEdgesTo(edges, "producer")); n != 2 {
		t.Errorf("producer edges = %d, want the old (ended) and the new (current)", n)
	}
}

// IRSA and EKS Pod Identity for the SAME service account (D-42): the trust
// document's IRSA statement is an `oidc` node (issuer = the cluster's OIDC
// host and path), the association a `k8s_service_account` node whose subject
// carries the pod: prefix -- two nodes, one edge each, oidc_federation and
// eks_pod_identity, each with its evidence and its own partition. Then the
// cluster's issuer cannot be read: the association cannot be attributed, and
// its edge goes stale instead of ending.
func TestP2TrustIRSAAndPodIdentity(t *testing.T) {
	l := newP2Lab(t, "p2-trust-pods", true)
	a := l.account(accountA)
	sa := "system:serviceaccount:payments:ledger-agent"
	roleARN := trustRole(a, "ledger-role", "AROALEDGERROLELEDGER", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustEKSProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"`+eksIssuerNoSch+`:sub":"`+sa+`"}}}`,
		trustAllow(`{"Service":"pods.eks.amazonaws.com"}`, "sts:AssumeRole")))
	eks := podIdentityEKS(roleARN)

	run := trustScan(l, a, eks, "trust-pod-scan-1")
	// The association's observation, as T3.5's writer is to record it: the
	// role as subject, PodIdentitySubjectKey as subject_native_id.
	var roleCloudID uuid.UUID
	if err := l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`, l.ws, roleARN).
		Row().Scan(&roleCloudID); err != nil {
		t.Fatalf("role's cloud_identity: %v", err)
	}
	w := services.NewObservationWriter(l.db, l.ws, a.conn, run.ID, run.Generation)
	if err := w.Record(services.IdentitySubject(roleCloudID), "eks:DescribePodIdentityAssociation",
		models.SurfaceEKSPodIdentity, models.CloudCoverageReached, time.Now(),
		igagraph.PodIdentitySubjectKey(roleARN, eksIssuerNoSch, sa),
		map[string]any{"cluster_name": "prod-cluster", "namespace": "payments", "service_account": "ledger-agent"}); err != nil {
		t.Fatalf("record association observation: %v", err)
	}
	l.project("trust-pod-projector-1")

	edges := trustEdgesTo(trustEdges(l), "ledger-role")
	byMech := map[string]trustEdge{}
	for _, e := range edges {
		byMech[e.Mechanism] = e
	}
	irsa, pod := byMech[models.MechanismOIDCFederation], byMech[models.MechanismEKSPodIdentity]
	if len(edges) != 3 || irsa.ExtID == nil || pod.ExtID == nil {
		t.Fatalf("ledger-role edges = %+v, want IRSA, pod identity and the pods.eks service", edges)
	}
	if irsa.ExtKind != models.ExternalPrincipalOIDC || irsa.ExtIssuer != eksIssuerNoSch || irsa.ExtSubject != sa {
		t.Errorf("IRSA source = (%s, %s, %s), want oidc %s / %s", irsa.ExtKind, irsa.ExtIssuer, irsa.ExtSubject, eksIssuerNoSch, sa)
	}
	if pod.ExtKind != models.ExternalPrincipalK8sServiceAccount || pod.ExtIssuer != eksIssuerNoSch ||
		pod.ExtSubject != igagraph.PodIdentitySubject(sa) || *pod.ExtID == *irsa.ExtID {
		t.Errorf("pod source = (%s, %s, %s), want its own k8s_service_account node %s / %s",
			pod.ExtKind, pod.ExtIssuer, pod.ExtSubject, eksIssuerNoSch, igagraph.PodIdentitySubject(sa))
	}
	if pod.Conditions != nil || irsa.Conditions == nil {
		t.Errorf("conditions: pod %v irsa %v; want NULL for the association, the sub condition for IRSA", pod.Conditions, irsa.Conditions)
	}
	var podObs, roleObs int64
	l.db.Raw(`SELECT count(*) FROM iga_relationship_evidence e JOIN cloud_observation o ON o.id = e.observation_id
	           WHERE e.relationship_id = ? AND o.source_api = 'eks:DescribePodIdentityAssociation'`, pod.ID).Scan(&podObs)
	l.db.Raw(`SELECT count(*) FROM iga_relationship_evidence e JOIN cloud_observation o ON o.id = e.observation_id
	           WHERE e.relationship_id = ? AND o.subject_native_id = ?`, irsa.ID, roleARN).Scan(&roleObs)
	if podObs != 1 || roleObs != 1 {
		t.Errorf("evidence: pod edge %d association observations, IRSA edge %d role observations; want 1 and 1", podObs, roleObs)
	}
	var parts int64
	l.db.Raw(`SELECT count(DISTINCT partition_key) FROM iga_relationship WHERE id IN (?, ?)`, pod.ID, irsa.ID).Scan(&parts)
	if parts != 2 {
		t.Errorf("IRSA and pod edges share a partition; they reconcile on different surfaces (§4.10)")
	}

	// The cluster's issuer is gone (a failed DescribeCluster): the association
	// cannot be attributed to a cluster. eks_pod_identity is still "reached",
	// so only the projector's protection keeps the edge from ending.
	eks.clusters["prod-cluster"] = ""
	trustCycle(l, a, eks)
	for _, e := range trustEdgesTo(trustEdges(l), "ledger-role") {
		if e.ID == pod.ID && (e.State != models.RelStale || e.EndedReason != "") {
			t.Errorf("unattributable association's edge = %s/%s, want stale: we could not name its cluster", e.State, e.EndedReason)
		}
		if e.ID == irsa.ID && e.State != models.RelCurrent {
			t.Errorf("IRSA edge = %s, want current: the trust document was read", e.State)
		}
	}
	var issuerless int64
	l.db.Raw(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = ? AND issuer = ''`, l.ws).Scan(&issuerless)
	if issuerless != 0 {
		t.Errorf("%d issuer-less external principals: one would merge the same service account across clusters", issuerless)
	}
}

// Human-owned columns are never overwritten (Rules the DDL cannot express, 5):
// a person's asserted resolution of an external principal survives every
// re-sighting, and the derived-resolution pass never touches it.
func TestP2TrustAssertedResolutionUntouched(t *testing.T) {
	l := newP2Lab(t, "p2-trust-asserted", true)
	a := l.account(accountA)
	reader := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "gha-deploy", "AROAGHADEPLOYASSERTE", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:authsec-ai/authsec:ref:refs/heads/main"}}}`))
	trustRole(a, "reader-access", "AROAREADERACCESSASSE", trustDoc(trustAllow(`{"AWS":"`+reader+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	someone := trustIdentityID(l, "gha-deploy")
	// A person asserts both nodes resolve to gha-deploy's identity (any live
	// identity will do; what matters is that the projector leaves it alone).
	if err := l.db.Exec(`UPDATE iga_external_principal
	                        SET resolved_identity_account_id = ?, resolution_basis = 'asserted',
	                            resolution_rule = 'reviewed', resolved_by = 'user-42'
	                      WHERE workspace_id = ?`, someone, l.ws).Error; err != nil {
		t.Fatal(err)
	}
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERASSERT")
	trustCycle(l, b, nil)
	trustCycle(l, a, nil)
	// B's data-reader has the lab's Lambda trust, so lambda.amazonaws.com is a
	// third, unasserted node; the two a person decided about are checked.
	var eps []models.IGAExternalPrincipal
	l.db.Where("workspace_id = ? AND mechanism <> ?", l.ws, models.ExternalPrincipalAWSService).Find(&eps)
	if len(eps) != 2 {
		t.Fatalf("external principals = %d, want the 2 asserted ones", len(eps))
	}
	check := func(when string) {
		t.Helper()
		for _, ep := range eps {
			var now models.IGAExternalPrincipal
			l.db.First(&now, "id = ?", ep.ID)
			if now.ResolutionBasis != models.BasisAsserted || now.ResolvedBy != "user-42" || now.ResolutionRule != "reviewed" ||
				now.ResolvedIdentityAccountID == nil || *now.ResolvedIdentityAccountID != someone {
				t.Errorf("%s: %s = %+v, want the person's assertion exactly as they left it", when, now.SubjectClaim, now)
			}
		}
	}
	check("after two projections")
	// The write's own guard, alone: whatever a caller believes, an asserted
	// row is never given a derived resolution.
	repo := repositories.NewIGAGraphRepository()
	for _, ep := range eps {
		if err := repo.SetDerivedResolution(l.db, l.ws, ep.ID, trustIdentityID(l, "data-reader"),
			models.ResolutionRuleExactARN); err != nil {
			t.Fatalf("SetDerivedResolution: %v", err)
		}
	}
	check("after SetDerivedResolution on asserted rows")
}

// D-61: "connected" means a connector exists and is not revoked. A principal
// in a revoked connector's account names an account we no longer read, so it
// stays an unresolved external principal even though that account's identity
// is still in the graph.
func TestP2TrustRevokedAccountIsNotConnected(t *testing.T) {
	l := newP2Lab(t, "p2-trust-revoked", true)
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERREVOKE")
	trustCycle(l, b, nil)
	if err := l.db.Exec(`UPDATE cloud_connector SET status = ? WHERE id = ?`,
		models.CloudConnectorRevoked, b.conn).Error; err != nil {
		t.Fatal(err)
	}
	a := l.account(accountA)
	reader := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "reader-access", "AROAREADERACCESSREVO", trustDoc(trustAllow(`{"AWS":"`+reader+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	got := trustEdgesTo(trustEdges(l), "reader-access")
	if len(got) != 1 || got[0].SourceIdentity != nil || got[0].ExtSubject != reader || got[0].ExtResolved != nil {
		t.Errorf("reader-access = %+v, want an unresolved aws_principal: account %s is revoked", got, accountB)
	}
}

// trustNegatedKeys reads a role's provider_attrs.trust_negated_statements.
func trustNegatedKeys(l *p2Lab, role string) []string {
	l.t.Helper()
	var keys []string
	if err := l.db.Raw(`SELECT jsonb_array_elements_text(provider_attrs->'trust_negated_statements')
	                      FROM iga_identity_accounts
	                     WHERE workspace_id = ? AND display_name = ? AND lifecycle = 'active'
	                       AND jsonb_typeof(provider_attrs->'trust_negated_statements') = 'array'`,
		l.ws, role).Scan(&keys).Error; err != nil {
		l.t.Fatalf("read trust_negated_statements of %s: %v", role, err)
	}
	return keys
}

// D-88: an Allow written with NotAction yields its edge when it does not
// exclude the assume action, and that edge must carry `negated_statement`. No
// can_assume column can say so (031), so the role records the statement keys
// of its NotAction statements -- exactly the edges' statement_key, and only
// theirs -- and an unreadable document keeps what the same incarnation said.
func TestP2TrustNotActionMarksItsStatement(t *testing.T) {
	l := newP2Lab(t, "p2-trust-notaction", true)
	a := l.account(accountA)
	trustRole(a, "notaction-role", "AROANOTACTIONROLE001", trustDoc(
		`{"Sid":"AllButTagging","Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"NotAction":"sts:TagSession"}`,
		trustAllow(`{"Service":"ecs-tasks.amazonaws.com"}`, "sts:*")))
	a.role("plain-role", "AROAPLAINROLEPLAINRO") // the lab's Lambda trust: Action, no NotAction
	trustCycle(l, a, nil)

	edges := trustEdgesTo(trustEdges(l), "notaction-role")
	bySubject := map[string]trustEdge{}
	for _, e := range edges {
		bySubject[e.ExtSubject] = e
	}
	negated, plain := bySubject["lambda.amazonaws.com"], bySubject["ecs-tasks.amazonaws.com"]
	if len(edges) != 2 || negated.ID == uuid.Nil || plain.ID == uuid.Nil {
		t.Fatalf("notaction-role edges = %+v, want the NotAction lambda edge and the sts:* ecs-tasks edge", edges)
	}
	keys := trustNegatedKeys(l, "notaction-role")
	if len(keys) != 1 || keys[0] != negated.StatementKey {
		t.Errorf("trust_negated_statements = %v, want exactly the NotAction edge's statement_key %q (not %q)",
			keys, negated.StatementKey, plain.StatementKey)
	}
	if n := len(trustEdgesTo(trustEdges(l), "plain-role")); n != 1 {
		t.Fatalf("setup: plain-role has %d edges, want its Lambda trust", n)
	}
	if other := trustNegatedKeys(l, "plain-role"); len(other) != 0 {
		t.Errorf("a role with no NotAction statement lists %v", other)
	}

	// Unreadable next scan: the edges are protected, and so is the marker
	// their limitation is drawn from.
	trustSetDoc(a, "notaction-role", trustDoc(
		`{"Sid":"AllButTagging","Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"NotAction":"sts:TagSession"}`,
		`{"Effect":"Allow","Principal":{"Service":7},"Action":"sts:AssumeRole"}`))
	trustCycle(l, a, nil)
	if got := trustNegatedKeys(l, "notaction-role"); len(got) != 1 || got[0] != negated.StatementKey {
		t.Errorf("after an unreadable scan trust_negated_statements = %v, want %q kept", got, negated.StatementKey)
	}
	for _, e := range trustEdgesTo(trustEdges(l), "notaction-role") {
		if e.State != models.RelStale {
			t.Errorf("unreadable role's edge %s = %s, want stale", e.ExtSubject, e.State)
		}
	}
}

// A same-account principal that this run's COMPLETE role listing no longer
// names (deleted between the listing and the trust read; AWS has not yet
// rewritten the ARN to its unique id). The prefetched graph still holds it as
// live -- reconciliation retires it later in the same pass -- so sourcing the
// edge from it would re-confirm a principal the run proved gone and end the
// edge in the same breath. It is an unresolved aws_principal instead, and the
// old identity edge ends with its last confirmation untouched.
func TestP2TrustUnlistedOwnPrincipalIsNotTheSource(t *testing.T) {
	l := newP2Lab(t, "p2-trust-unlisted", true)
	a := l.account(accountA)
	producer := a.role("producer", "AROAPRODUCERUNLISTED")
	trustRole(a, "consumer", "AROACONSUMERUNLISTED", trustDoc(trustAllow(`{"AWS":"`+producer+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	before := trustEdgesTo(trustEdges(l), "consumer")
	if len(before) != 1 || before[0].SourceName != "producer" {
		t.Fatalf("setup: consumer = %+v, want identity-sourced from producer", before)
	}

	trustRemoveRole(a, "producer")
	time.Sleep(10 * time.Millisecond)
	trustCycle(l, a, nil)

	var live, ended []trustEdge
	for _, e := range trustEdgesTo(trustEdges(l), "consumer") {
		if e.State == models.RelEnded {
			ended = append(ended, e)
		} else {
			live = append(live, e)
		}
	}
	if len(live) != 1 || live[0].State != models.RelCurrent || live[0].ExtKind != models.ExternalPrincipalAWSPrincipal ||
		live[0].ExtSubject != producer || live[0].ExtResolved != nil || live[0].SourceIdentity != nil {
		t.Errorf("consumer's live edges = %+v, want one current edge from an unresolved aws_principal %s", live, producer)
	}
	if len(ended) != 1 || ended[0].ID != before[0].ID || !ended[0].LastConfirmed.Equal(before[0].LastConfirmed) {
		t.Errorf("consumer's ended edges = %+v, want the old identity edge, last confirmed %s and never again",
			ended, before[0].LastConfirmed)
	}
}
