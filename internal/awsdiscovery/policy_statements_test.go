package awsdiscovery

import (
	"errors"
	"testing"
)

// Each case here is a statement whose narrowing half used to be discarded.
// Discarding it makes a permission read as broader than it is, which is the
// dangerous direction: a reviewer is shown access the principal does not have.

func TestDenyWrittenWithNotActionSurvives(t *testing.T) {
	// The whole statement used to vanish: the parser required a non-empty
	// Action, and a NotAction statement has none. A vanished Deny is the worst
	// possible parse failure -- the console shows no restriction at all.
	doc := `{"Statement":[{"Effect":"Deny","NotAction":["s3:GetObject"],"Resource":"*"}]}`

	got, skipped, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0: the statement is usable", skipped)
	}
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1 -- a Deny with NotAction was dropped", len(got))
	}
	if got[0].Effect != "deny" {
		t.Errorf("effect = %q, want deny", got[0].Effect)
	}
	if len(got[0].NotActions) != 1 || got[0].NotActions[0] != "s3:GetObject" {
		t.Errorf("NotActions = %v, want [s3:GetObject]", got[0].NotActions)
	}
	if len(got[0].Actions) != 0 {
		t.Errorf("Actions = %v, want empty: the statement named none", got[0].Actions)
	}
}

func TestConditionIsPreservedVerbatim(t *testing.T) {
	// A tag-gated grant rendered as unconditional over-reports access.
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",
	         "Resource":"arn:aws:s3:::reports/*",
	         "Condition":{"StringEquals":{"aws:PrincipalTag/Team":"operations"}}}]}`

	got, _, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1", len(got))
	}
	if got[0].Condition == "" {
		t.Fatal("Condition is empty: a conditional grant would render as unconditional")
	}
	const want = `{"StringEquals":{"aws:PrincipalTag/Team":"operations"}}`
	if got[0].Condition != want {
		t.Errorf("Condition = %s, want %s", got[0].Condition, want)
	}
}

func TestNotResourceIsPreservedAndNotWidened(t *testing.T) {
	// NotResource used to set Resources to nil, and the writer turned nil into
	// "*" -- converting a bounded exclusion into an unbounded grant.
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",
	         "NotResource":["arn:aws:s3:::secrets/*"]}]}`

	got, _, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1", len(got))
	}
	if len(got[0].NotResources) != 1 || got[0].NotResources[0] != "arn:aws:s3:::secrets/*" {
		t.Errorf("NotResources = %v, want [arn:aws:s3:::secrets/*]", got[0].NotResources)
	}
	if len(got[0].Resources) != 0 {
		t.Errorf("Resources = %v, want empty", got[0].Resources)
	}
	if got[0].Unbounded() {
		t.Error("Unbounded() = true: a NotResource statement excludes something and is not account-wide")
	}
}

func TestStatementNamingNoResourceAtAllIsUnbounded(t *testing.T) {
	// The genuine account-wide case, kept distinct from the NotResource one.
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:*"}]}`

	got, _, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || !got[0].Unbounded() {
		t.Fatalf("want one unbounded statement, got %+v", got)
	}
}

func TestMalformedDocumentIsAnErrorNotAnEmptyPolicy(t *testing.T) {
	// Returning zero statements made a broken policy look like one that grants
	// nothing. The caller must be able to tell those apart and record coverage.
	got, _, err := ParsePolicyDocument(`{"Statement":[{"Effect":`)
	if !errors.Is(err, ErrMalformedPolicy) {
		t.Fatalf("err = %v, want ErrMalformedPolicy", err)
	}
	if got != nil {
		t.Errorf("statements = %v, want nil on a parse failure", got)
	}
}

func TestUnusableStatementsAreCountedNotSilentlyDropped(t *testing.T) {
	// A statement with no Effect cannot be used, but the drop must be visible.
	doc := `{"Statement":[
	  {"Action":"s3:GetObject","Resource":"*"},
	  {"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`

	got, skipped, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d usable statements, want 1", len(got))
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestSidAndMultipleActionsRoundTrip(t *testing.T) {
	doc := `{"Statement":[{"Sid":"AllowInvoiceRead","Effect":"Allow",
	         "Action":["s3:GetObject","s3:ListBucket"],
	         "Resource":["arn:aws:s3:::acme-invoices/*"]}]}`

	got, _, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1", len(got))
	}
	if got[0].Sid != "AllowInvoiceRead" {
		t.Errorf("Sid = %q", got[0].Sid)
	}
	if len(got[0].Actions) != 2 {
		t.Errorf("Actions = %v, want 2", got[0].Actions)
	}
	if got[0].Condition != "" {
		t.Errorf("Condition = %q, want empty", got[0].Condition)
	}
}

// --- trust policy: a negative condition must never read as a positive one ---

func TestNegativeSubConditionDoesNotNamePrincipal(t *testing.T) {
	// "anyone EXCEPT repo:acme/deploy" used to be recorded as
	// "repo:acme/deploy" -- naming the one principal the policy forbids.
	cond := conditionBlock{
		"StringNotEquals": {
			"token.actions.githubusercontent.com:sub": stringOrSlice{"repo:acme/deploy:*"},
		},
	}
	sub, negated := cond.subClaim()
	if sub != "" {
		t.Errorf("sub = %q, want empty: a StringNotEquals names who may NOT assume the role", sub)
	}
	if !negated {
		t.Error("negated = false, want true")
	}
}

func TestPositiveSubConditionStillResolves(t *testing.T) {
	cond := conditionBlock{
		"StringEquals": {
			"token.actions.githubusercontent.com:sub": stringOrSlice{"repo:acme/deploy:*"},
		},
	}
	sub, negated := cond.subClaim()
	if sub != "repo:acme/deploy:*" {
		t.Errorf("sub = %q, want repo:acme/deploy:*", sub)
	}
	if negated {
		t.Error("negated = true, want false")
	}
}

func TestPositiveWinsWhenBothOperatorsPresent(t *testing.T) {
	// A policy may allow one subject and exclude another. The positive is what
	// the trust edge is about; the negative must not overwrite it.
	cond := conditionBlock{
		"StringEquals":    {"oidc.eks.us-east-1.amazonaws.com/id/ABC:sub": stringOrSlice{"system:serviceaccount:operations:reconcile-sa"}},
		"StringNotEquals": {"oidc.eks.us-east-1.amazonaws.com/id/ABC:sub": stringOrSlice{"system:serviceaccount:default:default"}},
	}
	sub, negated := cond.subClaim()
	if sub != "system:serviceaccount:operations:reconcile-sa" {
		t.Errorf("sub = %q, want the StringEquals value", sub)
	}
	if !negated {
		t.Error("negated = false: the exclusion was present and should be reported")
	}
}

func TestNegatedOperatorRecognisesQualifiedForms(t *testing.T) {
	for _, op := range []string{
		"StringNotEquals", "StringNotLike", "StringNotEqualsIfExists",
		"ForAllValues:StringNotEquals", "ArnNotLike",
	} {
		if !negatedOperator(op) {
			t.Errorf("negatedOperator(%q) = false, want true", op)
		}
	}
	for _, op := range []string{
		"StringEquals", "StringLike", "StringEqualsIfExists",
		"ForAnyValue:StringEquals", "ArnLike",
	} {
		if negatedOperator(op) {
			t.Errorf("negatedOperator(%q) = true, want false", op)
		}
	}
}
