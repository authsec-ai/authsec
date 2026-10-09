package integration

// /evidence describes what the revision holds AS OF the claim's run
// (P2-DECISIONS D-24, D-25; §2.6 statement revisions): no observation of a run
// that is not projected, no statement content that run did not confirm, no
// policy version but the one each fact's own observation read. Everything is
// collected by the real scan worker and projected by the real projector; the
// one state the projector never writes -- a junction link to a later read --
// is inserted directly and says so.

import (
	"reflect"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// evidenceObservationRefs lists the observations behind a response's facts
// (include=raw), sorted.
func evidenceObservationRefs(body map[string]any) []string {
	var out []string
	for _, r := range digl(body, "data", "raw") {
		if ref := digs(r, "observation"); ref != "" {
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out
}

// evidencePolicyFacts are a response's policy-version facts, with their raw
// entries (include=raw) at the same index.
func evidencePolicyFacts(body map[string]any) (facts, raws []any) {
	raw := digl(body, "data", "raw")
	for i, f := range digl(body, "data", "facts") {
		if dig(f, "policy") == nil {
			continue
		}
		facts = append(facts, f)
		if i < len(raw) {
			raws = append(raws, raw[i])
		} else {
			raws = append(raws, nil)
		}
	}
	return facts, raws
}

// D-25 / D-24: a run that has collected but is not projected changes nothing
// the revision says. Its NEW observations -- a new policy version, a role
// entry and a Lambda read that changed -- are no object's facts until it
// publishes; the observations it merely RE-CONFIRMED (an unchanged role's
// entry) still are, because they existed at the claim's run. Presence,
// target, statement, policy, workload and resource claims all read that way.
func TestP2EvidenceFactsIgnoreAnUnprojectedRun(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-unprojected-facts", true)
	a := l.account(accountA)
	anchor := a.role("AnchorRole", "AROAANCHORROLEANCHO1")
	steady := a.role("SteadyRole", "AROASTEADYROLESTEAD1")
	a.lambda("us-east-1", "anchor-fn", anchor)
	pol := a.managed("AnchorRead", s3aDoc("AnchorGet", "s3:GetObject", "arn:aws:s3:::anchor-bucket/*"))
	a.attach("AnchorRole", pol)
	a.attach("SteadyRole", a.managed("SteadyRead", s3aDoc("SteadyGet", "s3:GetObject", "arn:aws:s3:::steady/*")))
	run1 := l.scanAndProject(a)
	api := l.api()

	resID, _ := l.resourceID("arn:aws:s3:::anchor-bucket/*")
	claims := map[string]string{
		"grant":     evidenceGrant(t, l, "AnchorRole", "AnchorRead", "AnchorGet"),
		"statement": evidenceStatementRef(t, l, "AnchorRead", "AnchorGet"),
		"target":    evidenceTarget(t, l, "AnchorRead", "AnchorGet", "arn:aws:s3:::anchor-bucket/*"),
		"identity":  evidenceNode(t, l, "identity", "iga_identity_accounts", "AnchorRole"),
		"policy":    evidenceNode(t, l, "policy", "iga_policy", "AnchorRead"),
		"workload":  evidenceNode(t, l, "workload", "iga_workload", "anchor-fn"),
		"resource":  refOf("resource", resID),
		"steady":    evidenceNode(t, l, "identity", "iga_identity_accounts", "SteadyRole"),
	}
	before := map[string][]string{}
	for name, c := range claims {
		before[name] = evidenceObservationRefs(evidenceGet(t, api, c, "include", "raw"))
		if len(before[name]) == 0 {
			t.Fatalf("fixture: %s (%s) has no facts to compare", name, c)
		}
	}
	rev := num(evidenceGet(t, api, claims["grant"]), "meta", "rev")

	// Everything the anchor claims rest on changes -- and nothing is projected.
	a.iam.managedPolicies[pol] = evidenceDoc(`{"Sid":"AnchorGet","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],` +
		`"Resource":"arn:aws:s3:::anchor-bucket/*"}`)
	a.iam.policyVersions[pol] = "v9"
	s3aEditRole(t, a, "AnchorRole", func(r *iamtypes.Role) { r.Path = aws.String("/changed/") })
	a.lambda("us-east-1", "anchor-fn", steady)
	run2 := l.scan(a, "evidence-unprojected-scan")
	for what, q := range map[string]string{
		"a new policy version": `surface = 'iam_policies' AND subject_native_id = '` + pol + `'`,
		"a new role entry":     `surface = 'iam_roles' AND subject_native_id = '` + anchor + `'`,
		"a new Lambda read":    `surface LIKE 'lambda%'`,
	} {
		if n := l.count(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND scan_run_id = ? AND `+q, l.ws, run2.ID); n == 0 {
			t.Fatalf("fixture: the unprojected run recorded no %s", what)
		}
	}
	if n := l.count(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND subject_native_id = ?
	                  AND last_confirmed_run_id = ? AND scan_run_id = ?`, l.ws, steady, run2.ID, run1.ID); n == 0 {
		t.Fatal("fixture: the unprojected run did not re-confirm SteadyRole's unchanged entry; the in-flight case is untested")
	}

	for name, c := range claims {
		body := evidenceGet(t, api, c, "include", "raw")
		if got := num(body, "meta", "rev"); got != rev {
			t.Fatalf("fixture: rev moved from %d to %d without a projection", rev, got)
		}
		if got := evidenceObservationRefs(body); !reflect.DeepEqual(got, before[name]) {
			t.Errorf("%s: facts' observations = %v, want the revision's %v (never the unprojected run's)", name, got, before[name])
		}
		for _, f := range digl(body, "data", "facts") {
			if digs(f, "observed_in_run") == refOf("cloud_scan_run", run2.ID) {
				t.Errorf("%s: fact %q is dated by the unprojected run", name, digs(f, "fact"))
			}
		}
	}
	facts, raws := evidencePolicyFacts(evidenceGet(t, api, claims["statement"], "include", "raw"))
	if len(facts) != 1 || digs(facts[0], "policy_version") != "v3" || digs(raws[0], "sanitized_facts", "version_id") != "v3" ||
		digs(facts[0], "statement_excerpt", "Action") != "s3:GetObject" {
		t.Errorf("statement facts = %s, want only the v3 read, labelled v3", evidenceJSON(facts))
	}
	body := evidenceGet(t, api, claims["identity"], "include", "raw")
	if got := digs(body, "data", "raw", 0, "sanitized_facts", "path"); got != "/" {
		t.Errorf("AnchorRole's entry path = %q, want the projected entry's /", got)
	}
	body = evidenceGet(t, api, claims["workload"], "include", "raw")
	if got := digs(body, "data", "raw", 0, "sanitized_facts", "identity_native_id"); got != anchor {
		t.Errorf("anchor-fn's read names %q, want the projected read's %s", got, anchor)
	}

	// Projected, the new reads are the facts -- and the ones they replaced are
	// not (last confirmed before the claims' run).
	l.project("evidence-unprojected-late")
	for _, name := range []string{"statement", "target", "identity", "policy", "workload", "resource"} {
		body := evidenceGet(t, api, claims[name], "include", "raw")
		refs := evidenceObservationRefs(body)
		if len(refs) != 1 || reflect.DeepEqual(refs, before[name]) {
			t.Errorf("%s after projection: facts' observations = %v, want the one new read (was %v)", name, refs, before[name])
		}
	}
	facts, _ = evidencePolicyFacts(evidenceGet(t, api, claims["policy"]))
	if len(facts) != 1 || digs(facts[0], "policy_version") != "v9" || digs(facts[0], "fact") != "Policy AnchorRead version v9 was read" {
		t.Errorf("policy facts after projection = %s, want the v9 read", evidenceJSON(facts))
	}
}

// §2.6 / D-24: an ENDED grant is described by what its last confirming run
// confirmed -- not by the statement's revised content. The Sid-keyed
// statement keeps its row when revised, so its current actions, targets and
// Condition are not the ended grant's; the policy-version fact is labelled
// with the version its own observation read. The grant still current on the
// same statement is described by the revision.
func TestP2EvidenceEndedGrantKeepsItsContent(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-ended-content", true)
	a := l.account(accountA)
	a.role("LeftRole", "AROALEFTROLELEFTROL1")
	a.role("StayRole", "AROASTAYROLESTAYROL1")
	shared := a.managed("SharedRead", s3aDoc("SharedGet", "s3:GetObject", "arn:aws:s3:::shared/*"))
	a.attach("LeftRole", shared)
	a.attach("StayRole", shared)
	run1 := l.scanAndProject(a)
	left := evidenceGrant(t, l, "LeftRole", "SharedRead", "SharedGet")
	leftAssignment := evidenceAssignment(t, l, "SharedRead", "LeftRole")
	stay := evidenceGrant(t, l, "StayRole", "SharedRead", "SharedGet")

	a.detach("LeftRole", shared)
	l.scanAndProject(a)
	// Revised in place: another action, an exact reference, a Condition.
	a.iam.managedPolicies[shared] = evidenceDoc(`{"Sid":"SharedGet","Effect":"Allow","Action":["s3:GetObject","s3:DeleteObject"],` +
		`"Resource":["arn:aws:s3:::shared/*","arn:aws:s3:::archive/report.csv"],"Condition":{"Bool":{"aws:SecureTransport":"true"}}}`)
	a.iam.policyVersions[shared] = "v7"
	l.scanAndProject(a)
	if again := evidenceGrant(t, l, "StayRole", "SharedRead", "SharedGet"); again != stay {
		t.Fatalf("fixture: StayRole's grant was re-keyed (%s -> %s); a Sid-keyed statement keeps its row", stay, again)
	}
	if n := l.count(`SELECT count(*) FROM iga_statement_revision sr JOIN iga_access_edges g ON g.entitlement_id = sr.entitlement_id
	                  WHERE g.id = ?`, refUUID(t, left)); n != 2 {
		t.Fatalf("fixture: %d revisions of SharedGet, want the original and the revision", n)
	}
	api := l.api()
	shared1, _ := l.resourceID("arn:aws:s3:::shared/*")
	archive, _ := l.resourceID("arn:aws:s3:::archive/report.csv")

	body := evidenceGet(t, api, left, "include", "raw")
	d := dig(body, "data")
	if digs(d, "status", "lifecycle") != "ended" {
		t.Fatalf("fixture: LeftRole's grant = %s, want ended", evidenceJSON(dig(d, "status")))
	}
	if got, want := digs(d, "claim", "sentence"),
		"LeftRole was granted s3:GetObject on shared/* by SharedRead (statement SharedGet); the grant ended."; got != want {
		t.Errorf("ended sentence = %q, want %q", got, want)
	}
	facts, raws := evidencePolicyFacts(body)
	if len(facts) != 1 {
		t.Fatalf("ended grant policy facts = %s, want the one version it was confirmed with", evidenceJSON(facts))
	}
	p := facts[0]
	if digs(p, "fact") != "Statement SharedGet allows s3:GetObject on arn:aws:s3:::shared/*" ||
		digs(p, "policy_version") != "v3" || digs(raws[0], "sanitized_facts", "version_id") != "v3" ||
		digs(p, "statement_excerpt", "Action") != "s3:GetObject" || dig(p, "statement_excerpt", "Condition") != nil ||
		digs(p, "observed_in_run") != refOf("cloud_scan_run", run1.ID) {
		t.Errorf("ended grant policy fact = %s (raw %s), want the v3 content, labelled v3, dated run 1",
			evidenceJSON(p), evidenceJSON(raws[0]))
	}
	if dig(p, "statement", "index") != nil || digs(p, "statement", "sid") != "SharedGet" {
		t.Errorf("statement = %s, want Sid SharedGet and no claimed position (the revision records none)", evidenceJSON(dig(p, "statement")))
	}
	if evidenceLim(body, "conditions_not_evaluated") != nil || evidenceLim(body, "resource_existence_not_verified") != nil {
		t.Errorf("ended grant limitations = %v: the Condition and the exact reference came after it ended", evidenceCodes(body))
	}
	if lim := evidenceLim(body, "selector_may_match_nothing"); lim == nil ||
		!reflect.DeepEqual(evidenceStrings(lim["resources"]), []string{refOf("resource", shared1)}) {
		t.Errorf("selector_may_match_nothing = %v, want [shared/*]", lim)
	}

	// The current grant on the same statement: the revision, labelled v7.
	body = evidenceGet(t, api, stay)
	if got, want := digs(body, "data", "claim", "sentence"),
		"StayRole is granted s3:GetObject, s3:DeleteObject on shared/*, archive/report.csv by SharedRead (statement SharedGet)."; got != want {
		t.Errorf("current sentence = %q, want %q", got, want)
	}
	facts, _ = evidencePolicyFacts(body)
	if len(facts) != 1 || digs(facts[0], "policy_version") != "v7" || num(facts[0], "statement", "index") != 1 {
		t.Errorf("current grant policy facts = %s, want v7 at index 1", evidenceJSON(facts))
	}
	if lim := evidenceLim(body, "conditions_not_evaluated"); lim == nil ||
		!reflect.DeepEqual(evidenceStrings(lim["keys"]), []string{"aws:SecureTransport"}) {
		t.Errorf("current grant conditions = %v, want aws:SecureTransport", lim)
	}
	if lim := evidenceLim(body, "resource_existence_not_verified"); lim == nil ||
		!reflect.DeepEqual(evidenceStrings(lim["resources"]), []string{refOf("resource", archive)}) {
		t.Errorf("current grant exact references = %v, want [archive/report.csv]", lim)
	}

	// The ended assignment: past tense, and the version it was read at.
	body = evidenceGet(t, api, leftAssignment)
	if got, want := digs(body, "data", "claim", "sentence"), "SharedRead was attached to LeftRole; the assignment ended."; got != want {
		t.Errorf("ended assignment sentence = %q, want %q", got, want)
	}
	facts, _ = evidencePolicyFacts(body)
	if len(facts) != 1 || digs(facts[0], "policy_version") != "v3" || digs(facts[0], "fact") != "Policy SharedRead version v3 was read" {
		t.Errorf("ended assignment policy facts = %s, want the v3 read", evidenceJSON(facts))
	}
}

// One AWS-managed policy in two accounts: AWS revised it and only B has read
// it since. A's grant is still current (A's partition confirmed it) and is
// the content A read; every per-account fact quotes its own account's read;
// and a fact whose account's read did not name the target is no fact of it.
func TestP2EvidenceSharedPolicyFactsAsOfEachAccount(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-shared-asof", true)
	v1 := evidenceDoc(`{"Sid":"Guide","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::guide/*"}`)
	a := l.account(accountA)
	a.role("GuideA", "AROAGUIDEAGUIDEAGUI1")
	b := l.account(accountB)
	b.role("GuideB", "AROAGUIDEBGUIDEBGUI1")
	arn := s3aAWSManaged(a, "GuideAccess", v1)
	s3aAWSManaged(b, "GuideAccess", v1)
	a.attach("GuideA", arn)
	b.attach("GuideB", arn)
	// A names guide-extra/* too, through its own policy: the reference has a
	// support row in A that GuideAccess never gave it there.
	a.attach("GuideA", a.managed("OwnExtra", s3aDoc("Extra", "s3:ListBucket", "arn:aws:s3:::guide-extra/*")))
	l.scanAndProject(a)
	l.scanAndProject(b)
	b.iam.managedPolicies[arn] = evidenceDoc(`{"Sid":"Guide","Effect":"Allow","Action":"s3:GetObject",` +
		`"Resource":["arn:aws:s3:::guide/*","arn:aws:s3:::guide-extra/*"]}`)
	b.iam.policyVersions[arn] = "v5"
	l.scanAndProject(b)
	api := l.api()
	guide, _ := l.resourceID("arn:aws:s3:::guide/*")
	extra, _ := l.resourceID("arn:aws:s3:::guide-extra/*")

	type perAccount struct{ version, fact string }
	byAccount := func(body map[string]any) map[string]perAccount {
		out := map[string]perAccount{}
		facts, _ := evidencePolicyFacts(body)
		for _, f := range facts {
			acct := digs(f, "account_id")
			if _, dup := out[acct]; dup {
				t.Errorf("two policy facts from %s: %s", acct, evidenceJSON(facts))
			}
			out[acct] = perAccount{digs(f, "policy_version"), digs(f, "fact")}
			res := dig(f, "statement_excerpt", "Resource")
			if _, one := res.(string); (acct == accountA) != one {
				t.Errorf("%s's excerpt Resource = %v: A read one resource, B two", acct, res)
			}
		}
		return out
	}

	body := evidenceGet(t, api, evidenceGrant(t, l, "GuideA", "GuideAccess", "Guide"))
	if digs(body, "data", "status", "lifecycle") != "current" {
		t.Fatalf("fixture: GuideA's grant = %v, want current", dig(body, "data", "status"))
	}
	if got, want := digs(body, "data", "claim", "sentence"), "GuideA is granted s3:GetObject on guide/* by GuideAccess (statement Guide)."; got != want {
		t.Errorf("A's grant sentence = %q, want %q (what A read)", got, want)
	}
	if lim := evidenceLim(body, "selector_may_match_nothing"); lim == nil ||
		!reflect.DeepEqual(evidenceStrings(lim["resources"]), []string{refOf("resource", guide)}) {
		t.Errorf("A's grant selectors = %v, want [guide/*] only", lim)
	}
	if got := byAccount(body); !reflect.DeepEqual(got, map[string]perAccount{accountA: {"v3",
		"Statement Guide allows s3:GetObject on arn:aws:s3:::guide/*"}}) {
		t.Errorf("A's grant policy facts = %v", got)
	}
	body = evidenceGet(t, api, evidenceGrant(t, l, "GuideB", "GuideAccess", "Guide"))
	if got, want := digs(body, "data", "claim", "sentence"),
		"GuideB is granted s3:GetObject on guide/*, guide-extra/* by GuideAccess (statement Guide)."; got != want {
		t.Errorf("B's grant sentence = %q, want %q", got, want)
	}

	cases := map[string]struct {
		claim string
		want  map[string]perAccount
	}{
		"the statement's presence": {evidenceStatementRef(t, l, "GuideAccess", "Guide"), map[string]perAccount{
			accountA: {"v3", "Statement Guide is in policy GuideAccess"}, accountB: {"v5", "Statement Guide is in policy GuideAccess"}}},
		"a target both reads named": {evidenceTarget(t, l, "GuideAccess", "Guide", "arn:aws:s3:::guide/*"), map[string]perAccount{
			accountA: {"v3", "Statement Guide of GuideAccess names arn:aws:s3:::guide/*"},
			accountB: {"v5", "Statement Guide of GuideAccess names arn:aws:s3:::guide/*"}}},
		"a target only B's read named": {evidenceTarget(t, l, "GuideAccess", "Guide", "arn:aws:s3:::guide-extra/*"), map[string]perAccount{
			accountB: {"v5", "Statement Guide of GuideAccess names arn:aws:s3:::guide-extra/*"}}},
		"a reference GuideAccess named only in B's read": {refOf("resource", extra), map[string]perAccount{
			accountA: {"v3", "Statement Extra of OwnExtra names this reference"},
			accountB: {"v5", "Statement Guide of GuideAccess names this reference"}}},
	}
	for name, tc := range cases {
		body := evidenceGet(t, api, tc.claim)
		got := map[string]perAccount{}
		facts, _ := evidencePolicyFacts(body)
		for _, f := range facts {
			got[digs(f, "account_id")+"|"+digs(f, "fact")] = perAccount{digs(f, "policy_version"), digs(f, "fact")}
		}
		want := map[string]perAccount{}
		for acct, pa := range tc.want {
			want[acct+"|"+pa.fact] = pa
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: policy facts = %s, want %v", name, evidenceJSON(facts), tc.want)
		}
		byAccount(body) // each account's excerpt is its own read
	}
}

// A junction link to an observation first recorded AFTER the claim's last
// confirming run is no support of it (D-24: the observation must have existed
// at that run). The projector links only what the edge's own run confirmed,
// so the link is inserted directly -- a projector defect or a replay must
// still not let a later read vouch for an earlier claim.
func TestP2EvidenceJunctionNeverLinksALaterRead(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-later-link", true)
	a := l.account(accountA)
	a.role("PlainRole", "AROAPLAINROLEPLAIN01")
	arn := a.managed("PlainRead", s3aDoc("PlainGet", "s3:GetObject", "arn:aws:s3:::plain-bucket/report.csv"))
	a.attach("PlainRole", arn)
	l.scanAndProject(a)
	claim := evidenceGrant(t, l, "PlainRole", "PlainRead", "PlainGet")
	a.iam.managedPolicies[arn] = evidenceDoc(`{"Sid":"PlainGet","Effect":"Allow","Action":"s3:*","Resource":"*"}`)
	a.iam.policyVersions[arn] = "v8"
	run2 := l.scan(a, "evidence-later-link-scan")
	var later uuid.UUID
	if err := l.db.Raw(`SELECT id FROM cloud_observation WHERE workspace_id = ? AND scan_run_id = ? AND surface = ?
	                      AND subject_native_id = ?`, l.ws, run2.ID, models.SurfaceIAMPolicies, arn).Row().Scan(&later); err != nil {
		t.Fatalf("fixture: the later run's policy version: %v", err)
	}
	if err := l.db.Exec(`INSERT INTO iga_access_edge_evidence (workspace_id, access_edge_id, observation_id, relation)
	                      VALUES (?, ?, ?, 'supports')`, l.ws, refUUID(t, claim), later).Error; err != nil {
		t.Fatalf("insert link: %v", err)
	}
	facts, _ := evidencePolicyFacts(evidenceGet(t, l.api(), claim))
	if len(facts) != 1 || digs(facts[0], "policy_version") != "v3" {
		t.Errorf("policy facts = %s, want only the v3 read the grant was confirmed with", evidenceJSON(facts))
	}
}
