package igaread

// Pure pieces of /evidence (evidence.go, evidence_facts.go, limitations.go).
// Everything that reads the database is proven end to end in
// tests/integration/p2_evidence_*.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

func TestP2EvidenceStatementText(t *testing.T) {
	// AWS's own statement: a string or a list per element.
	st := parseStatementText(json.RawMessage(`{"Sid":"A","Effect":"Allow","Action":"s3:GetObject",
		"NotResource":["arn:aws:s3:::finance/*","arn:aws:s3:::hr/*"],"Condition":{"Bool":{"aws:SecureTransport":"true"}}}`))
	if !reflect.DeepEqual(st.Actions, []string{"s3:GetObject"}) || len(st.NotActions) != 0 ||
		!reflect.DeepEqual(st.NotResources, []string{"arn:aws:s3:::finance/*", "arn:aws:s3:::hr/*"}) || !hasCondition(st.Condition) {
		t.Fatalf("verbatim statement = %+v", st)
	}
	// The collector's fallback shape (models.NativeRights).
	st = parseStatementText(json.RawMessage(`{"effect":"allow","not_actions":["iam:*"],"resources":["*"],"condition":{"StringEquals":{"k":"v"}}}`))
	if !reflect.DeepEqual(st.NotActions, []string{"iam:*"}) || !reflect.DeepEqual(st.Resources, []string{"*"}) ||
		!reflect.DeepEqual(ConditionKeys(st.Condition), []string{"k"}) {
		t.Fatalf("fallback statement = %+v", st)
	}
	if st := parseStatementText(json.RawMessage(`{"Condition":null}`)); hasCondition(st.Condition) {
		t.Errorf("a null Condition is no condition")
	}
	if hasCondition(json.RawMessage(`{}`)) || hasCondition(nil) {
		t.Errorf("an empty Condition block is no condition")
	}
}

func TestP2EvidenceConditionKeys(t *testing.T) {
	got := ConditionKeys(json.RawMessage(`{"StringEquals":{"sts:ExternalId":"x","aws:PrincipalTag/team":"ops"},
		"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]},"StringLike":{"sts:ExternalId":"y*"}}`))
	want := []string{"aws:PrincipalTag/team", "aws:SourceIp", "sts:ExternalId"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v (sorted, distinct across operators)", got, want)
	}
	if got := ConditionKeys(json.RawMessage(`"not a block"`)); got == nil || len(got) != 0 {
		t.Errorf("malformed block keys = %#v, want an empty list", got)
	}
}

func TestP2EvidencePhrases(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:s3:::support-tickets/*": "support-tickets/*",
		"arn:aws:s3:::support-tickets":   "support-tickets",
		"*":                              "all resources",
		"arn:aws:kms:us-east-1:300000000003:key/ab": "arn:aws:kms:us-east-1:300000000003:key/ab",
		"arn:aws:dynamodb:us-east-1:1:table/T":      "arn:aws:dynamodb:us-east-1:1:table/T",
	} {
		if got := resourcePhrase(in); got != want {
			t.Errorf("resourcePhrase(%q) = %q, want %q", in, got, want)
		}
	}
	if got := actionsPhrase(statementText{NotActions: []string{"iam:*", "organizations:*"}}); got != "all actions except iam:*, organizations:*" {
		t.Errorf("NotAction phrase = %q", got)
	}
	pos := []evTarget{{Text: "*"}}
	excl := []evTarget{{Text: "arn:aws:s3:::finance/*"}}
	if got := targetsPhrase(pos, excl, true); got != "all resources except finance/*" {
		t.Errorf("NotResource phrase = %q", got)
	}
	if got := targetsPhrase([]evTarget{{Text: "arn:aws:s3:::a/*"}, {Text: "arn:aws:s3:::b"}}, nil, false); got != "arn:aws:s3:::a/*, arn:aws:s3:::b" {
		t.Errorf("full targets phrase = %q", got)
	}
	if got := joinWords([]string{"a", "b", "c"}); got != "a, b and c" {
		t.Errorf("joinWords = %q", got)
	}
}

func TestP2EvidenceExternalPrincipalLabels(t *testing.T) {
	cases := []struct{ kind, issuer, subject, label, account string }{
		{models.ExternalPrincipalAWSAccount, "aws", "300000000003", "300000000003", "300000000003"},
		{models.ExternalPrincipalAWSAccount, "aws", "*", "any AWS principal", ""},
		{models.ExternalPrincipalAWSPrincipal, "aws", "arn:aws:iam::905418271234:role/X", "arn:aws:iam::905418271234:role/X", "905418271234"},
		{models.ExternalPrincipalAWSService, "aws", "lambda.amazonaws.com", "lambda.amazonaws.com", ""},
		{models.ExternalPrincipalOIDC, "token.actions.githubusercontent.com", "repo:o/r:ref:refs/heads/main",
			"token.actions.githubusercontent.com repo:o/r:ref:refs/heads/main", ""},
		{models.ExternalPrincipalK8sServiceAccount, "oidc.eks/id/X", "pod:system:serviceaccount:tools:runner", "tools/runner", ""},
	}
	for _, c := range cases {
		if got := ExternalPrincipalLabel(c.kind, c.issuer, c.subject); got != c.label {
			t.Errorf("label(%s, %s) = %q, want %q", c.kind, c.subject, got, c.label)
		}
		if got := ExternalPrincipalAccountID(c.kind, c.subject); got != c.account {
			t.Errorf("account(%s, %s) = %q, want %q (D-87: only aws_account and aws_principal state one)", c.kind, c.subject, got, c.account)
		}
	}
}

func TestP2EvidenceGroupKey(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	base := statementText{Actions: []string{"s3:PutObject", "s3:GetObject"}}
	k := StatementGroupKey(base, []uuid.UUID{b, a}, nil)
	if k != StatementGroupKey(statementText{Actions: []string{"s3:GetObject", "s3:PutObject"}}, []uuid.UUID{a, b}, nil) {
		t.Errorf("order of actions or targets changed the group key")
	}
	if !strings.HasPrefix(k, "s3:GetObject,s3:PutObject→") {
		t.Errorf("key = %q, want sorted actions then the arrow", k)
	}
	cond := base
	cond.Condition = json.RawMessage(`{"Bool":{"aws:SecureTransport":"true"}}`)
	if StatementGroupKey(cond, []uuid.UUID{a, b}, nil) == k {
		t.Errorf("a Condition must change the group key (D-37)")
	}
	if StatementGroupKey(base, []uuid.UUID{a, b}, []uuid.UUID{uuid.New()}) == k {
		t.Errorf("an exclusion must change the group key (D-37)")
	}
	if got := StatementGroupKey(statementText{NotActions: []string{"iam:*"}}, nil, nil); !strings.HasPrefix(got, "!iam:*→") {
		t.Errorf("NotAction key = %q, want the ! prefix", got)
	}
}

func TestP2EvidenceClassifyObservation(t *testing.T) {
	for _, c := range []struct{ api, surface, want string }{
		{"iam:GetAccountAuthorizationDetails", models.SurfaceIAMRoles, factRoleEntry},
		{"iam:GetAccountAuthorizationDetails", models.SurfaceIAMUsers, factUserEntry},
		{"iam:GetAccountAuthorizationDetails", models.SurfaceIAMGroups, factGroupEntry},
		{"iam:GetPolicyVersion", models.SurfaceIAMPolicies, factPolicyVersion},
		{"iam:GetAccountAuthorizationDetails", models.SurfaceIAMPolicies, factPolicyVersion},
		{"eks:DescribePodIdentityAssociation", models.SurfaceEKSPodIdentity, factPodAssociation},
		{"lambda:ListFunctions", "lambda:eu-west-1", factWorkload},
		{"bedrock-agentcore:GetGateway", "agentcore-gateways:us-east-1", factWorkload},
		// Never configuration evidence:
		{"iam:GetCredentialReport", "iam_credential_report", ""},
		{"iam:ListAccessKeys", models.SurfaceIAMAccessKeys, ""},
		{"cloudtrail:LookupEvents", "cloudtrail-events:us-east-1", ""},
		{"iam:GetCredentialReport", models.SurfaceIAMUsers, ""},
	} {
		if got := classifyObservation(c.api, c.surface); got != c.want {
			t.Errorf("classify(%s, %s) = %q, want %q", c.api, c.surface, got, c.want)
		}
	}
}

func TestP2EvidencePolicyNativeID(t *testing.T) {
	if got := policyNativeID("customer_managed", "arn:aws:iam::1:policy/P", "aws\x1farn:aws:iam::1:policy/P"); got != "arn:aws:iam::1:policy/P" {
		t.Errorf("managed = %q", got)
	}
	if got := policyNativeID("inline", "", "aws\x1finline\x1farn:aws:iam::1:user/priya\x1fPriyaOwn"); got != "inline:arn:aws:iam::1:user/priya:PriyaOwn" {
		t.Errorf("inline = %q, want the collector's native id", got)
	}
	if got := policyNativeID("inline", "", "garbage"); got != "" {
		t.Errorf("an unreadable inline key = %q, want none (never a guess)", got)
	}
}

func TestP2EvidenceSurfaceCodes(t *testing.T) {
	for _, c := range []struct{ surface, state, want string }{
		{"iam_users", models.CloudCoverageDenied, LimSurfaceDenied},
		{"iam_users", models.CloudCoveragePartial, LimSurfacePartial},
		{"iam_users", models.CloudCoverageThrottled, LimSurfaceStale},
		{"lambda:us-east-1", models.CloudCoverageNotSelected, LimSurfaceStale},
		{"iam_users", models.CloudCoverageUnknown, LimSurfaceStale},
		{"iam_users", models.CloudCoverageReached, ""},
		{SurfaceOrganizations, models.CloudCoverageUnsupported, ""},
		{"bedrock-agentcore:ap-east-1", models.CloudCoverageUnsupported, ""},
	} {
		if got := surfaceCode(c.surface, c.state); got != c.want {
			t.Errorf("surfaceCode(%s, %s) = %q, want %q", c.surface, c.state, got, c.want)
		}
	}
}

func TestP2EvidenceD1OverSupports(t *testing.T) {
	t1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	a, b := uuid.New(), uuid.New()
	state, last, anchor := d1([]evSupport{
		{ID: a, State: StateStale, LastConfirmedAt: &t2},
		{ID: b, State: StateCurrent, LastConfirmedAt: &t1},
	})
	if state != StateCurrent || !last.Equal(t2) || anchor.ID != a {
		t.Errorf("d1 = %s %v %v, want current, the latest time and its row", state, last, anchor.ID)
	}
	if state, _, _ := d1([]evSupport{{State: StateEnded}, {State: StateStale}}); state != StateStale {
		t.Errorf("stale and ended = %s, want stale", state)
	}
	if state, _, _ := d1([]evSupport{{State: StateEnded}}); state != StateEnded {
		t.Errorf("all ended = %s, want ended", state)
	}
}

func TestP2EvidenceCollection(t *testing.T) {
	c := &claimCoverage{
		gaps: map[int][]claimGap{
			1: {{state: models.CloudCoverageDenied}, {state: models.CloudCoveragePartial}},
			2: {{state: models.CloudCoverageThrottled}},
		},
		unrecorded: map[int]bool{3: true},
		direct:     map[int]string{4: CollectionPartial},
	}
	for i, want := range []string{CollectionComplete, CollectionPartial, CollectionStale, CollectionStale, CollectionPartial} {
		if got := c.collection(i); got != want {
			t.Errorf("collection(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestP2EvidenceLimitationOrder(t *testing.T) {
	ls := []Limitation{
		{"code": LimSurfaceDenied, "account_id": "2", "surface": "iam_users"},
		{"code": LimOrganizationsNotCollected},
		{"code": LimSurfaceStale, "account_id": "1", "surface": "iam_roles"},
		{"code": LimEffectiveAccessNotEvaluated},
		{"code": LimActivityAttemptsNotOutcomes},
		{"code": LimSelectorMayMatchNothing},
		{"code": LimResourceExistenceNotVerified},
	}
	sortLimitations(ls)
	var got []string
	for _, l := range ls {
		got = append(got, l.Code())
	}
	want := []string{LimEffectiveAccessNotEvaluated, LimOrganizationsNotCollected, LimResourceExistenceNotVerified,
		LimSelectorMayMatchNothing, LimSurfaceStale, LimSurfaceDenied, LimActivityAttemptsNotOutcomes}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want the §5.3 table's %v", got, want)
	}
}

// An ended claim is stated in the past tense and says it ended -- never
// "removed", never a present-tense configuration (§2.14.8).
func TestP2EvidenceEndedSentences(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{relationshipSentence(models.RelTypeExecutesAs, "", "fn", "R", true), "fn was configured to run as R; the relationship ended"},
		{relationshipSentence(models.RelTypeMemberOf, "", "priya", "ops", true), "priya was a member of ops; the membership ended"},
		{relationshipSentence(models.RelTypeCanAssume, "", "lambda.amazonaws.com", "R", true),
			"The trust policy of R named lambda.amazonaws.com; the relationship ended"},
		{relationshipSentence(models.RelTypeCanAssume, "", "lambda.amazonaws.com", "R", false), "lambda.amazonaws.com may assume R"},
		{assignmentSentence(models.CloudAttachmentAttached, "P", "R", true), "P was attached to R; the assignment ended"},
		{assignmentSentence(models.CloudAttachmentBoundary, "P", "R", true), "P was the permissions boundary of R; the assignment ended"},
		{assignmentSentence(models.CloudAttachmentInline, "P", "R", false), "P is an inline policy of R"},
	} {
		if c.got != c.want {
			t.Errorf("sentence = %q, want %q", c.got, c.want)
		}
		for _, banned := range []string{"removed", "can access", "allowed"} {
			if strings.Contains(strings.ToLower(c.got), banned) {
				t.Errorf("%q uses %q", c.got, banned)
			}
		}
	}
}

// contentTargets derives an earlier content's targets the way the projector
// writes them: Resource targets, NotResource exclusions, and the implicit "*"
// of a NotResource statement without Resource.
func TestP2EvidenceContentTargets(t *testing.T) {
	got := contentTargets(parseStatementText(json.RawMessage(`{"Effect":"Allow","Action":"s3:*","NotResource":["a","b"]}`)))
	want := []contentTarget{{"a", models.TargetNotResource, 0}, {"b", models.TargetNotResource, 1}, {"*", models.TargetResource, 0}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NotResource targets = %v, want %v", got, want)
	}
	got = contentTargets(parseStatementText(json.RawMessage(`{"Effect":"Allow","Action":"s3:*","Resource":["x"],"NotResource":"y"}`)))
	want = []contentTarget{{"x", models.TargetResource, 0}, {"y", models.TargetNotResource, 0}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mixed targets = %v, want %v (no implicit * when Resource is stated)", got, want)
	}
}

// applyTo describes the earlier content -- flags re-derived from its text, no
// claimed position -- and names matches a target by reference and mode.
func TestP2EvidenceContentApply(t *testing.T) {
	idx := 2
	live := &evStatement{ID: uuid.New(), Sid: "S", Index: &idx, Effect: models.EffectAllow, Negated: false, Conditional: true,
		NativeRights: json.RawMessage(`{"Sid":"S","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"k":"v"}}}`)}
	raw := json.RawMessage(`{"Sid":"S","Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:s3:::a/*"}`)
	res := uuid.New()
	h := &stmtContent{raw: raw, text: parseStatementText(raw), effect: models.EffectAllow,
		targets: []evTarget{{ResourceID: res, Mode: models.TargetResource, Text: "arn:aws:s3:::a/*"}}}
	st := h.applyTo(live)
	if st.Index != nil || !st.Negated || st.Conditional || string(st.NativeRights) != string(raw) || st.Sid != "S" {
		t.Errorf("applyTo = %+v, want the earlier content, negated, unconditional, no index", st)
	}
	if live.Index == nil || !live.Conditional {
		t.Errorf("applyTo changed the live statement")
	}
	if !h.names(evTarget{ResourceID: res, Mode: models.TargetResource}) {
		t.Errorf("names: the content's own target is not named")
	}
	if h.names(evTarget{ResourceID: res, Mode: models.TargetNotResource}) || h.names(evTarget{ResourceID: uuid.New(), Mode: models.TargetResource}) {
		t.Errorf("names: another mode or reference is named")
	}
}
