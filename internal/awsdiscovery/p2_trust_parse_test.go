package awsdiscovery

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// T3.4 (SPEC-iga-phase2-graph.md §6.2): the trust parser reads Allow AND Deny,
// every principal form, conditions verbatim, records NotPrincipal, and isolates
// a statement that fails -- while still reporting it (P2-DECISIONS D-42..D-46).

func trustParse(t *testing.T, doc string) *TrustDocument {
	t.Helper()
	d, err := ParseTrustDocument(json.RawMessage(doc))
	if err != nil {
		t.Fatalf("parse %s: %v", doc, err)
	}
	return d
}

// trustOnly parses a one-statement document and returns its statement.
func trustOnly(t *testing.T, stmt string) TrustStatement {
	t.Helper()
	d := trustParse(t, `{"Version":"2012-10-17","Statement":[`+stmt+`]}`)
	if len(d.Skipped) != 0 || len(d.Statements) != 1 {
		t.Fatalf("statement %s: skipped %v, parsed %d", stmt, d.Skipped, len(d.Statements))
	}
	return d.Statements[0]
}

// THE T3.4 GATE: a trust statement with a non-string condition value no longer
// fails the document, and the condition round-trips verbatim.
func TestTrustNonStringConditionValueParses(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
	  "Principal":{"AWS":"arn:aws:iam::905418271234:root"},"Action":"sts:AssumeRole",
	  "Condition":{"Bool":{"aws:MultiFactorAuthPresent":true},
	               "NumericLessThan":{"aws:MultiFactorAuthAge":3600}}}]}`
	if reason := ValidateTrustDocument(json.RawMessage(doc)); reason != "" {
		t.Fatalf("ValidateTrustDocument = %q, want readable: a boolean or number is a legal condition value", reason)
	}
	st := trustParse(t, doc).Statements[0]
	want := `{"Bool":{"aws:MultiFactorAuthPresent":true},"NumericLessThan":{"aws:MultiFactorAuthAge":3600}}`
	if string(st.Condition) != want {
		t.Errorf("Condition = %s, want verbatim %s", st.Condition, want)
	}
	if subs := st.Subjects(); len(subs) != 1 || subs[0].Kind != ExternalAWSAccount || subs[0].Subject != "905418271234" {
		t.Errorf("subjects = %+v, want the account", subs)
	}
	// The legacy writer reads it too, instead of counting a parse failure.
	if _, err := ParseTrustPolicy(doc); err != nil {
		t.Errorf("legacy ParseTrustPolicy: %v", err)
	}
}

func TestTrustDenyStatementIsReturned(t *testing.T) {
	d := trustParse(t, `{"Statement":[
	  {"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},
	  {"Sid":"NoPartner","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`)
	if len(d.Statements) != 2 {
		t.Fatalf("statements = %d, want both Allow and Deny", len(d.Statements))
	}
	if d.Statements[1].Effect != "deny" || d.Statements[1].Sid != "NoPartner" {
		t.Errorf("deny statement = %+v", d.Statements[1])
	}
	if !d.HasDeny() || d.HasNotPrincipal() {
		t.Errorf("HasDeny=%v HasNotPrincipal=%v, want true/false", d.HasDeny(), d.HasNotPrincipal())
	}
	// The legacy table records Allow principals only.
	legacy, err := ParseTrustPolicy(`{"Statement":[{"Effect":"Deny","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`)
	if err != nil || len(legacy) != 0 {
		t.Errorf("legacy principals for a Deny = %+v, %v; want none", legacy, err)
	}
}

func TestTrustNotPrincipalRecordedNeverEmitted(t *testing.T) {
	st := trustOnly(t, `{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::905418271234:role/blocked"},"Action":"sts:AssumeRole"}`)
	if !st.HasNotPrincipal() || string(st.NotPrincipal) != `{"AWS":"arn:aws:iam::905418271234:role/blocked"}` {
		t.Errorf("NotPrincipal = %s, want recorded verbatim", st.NotPrincipal)
	}
	if len(st.Principals) != 0 || len(st.Subjects()) != 0 {
		t.Errorf("principals %v / subjects %v: a NotPrincipal entry must never become a principal", st.Principals, st.Subjects())
	}
	d := trustParse(t, `{"Statement":{"Effect":"Deny","NotPrincipal":"*","Action":"sts:AssumeRole"}}`)
	if !d.HasNotPrincipal() {
		t.Error("single-object Statement with NotPrincipal not recorded")
	}
}

// One malformed statement is skipped with its index and reason, its neighbours
// survive -- and the document is UNREADABLE (D-45), so the projector protects
// what it declared before instead of ending it.
func TestTrustMalformedStatementIsolated(t *testing.T) {
	doc := `{"Statement":[
	  {"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},
	  {"Effect":"Allow","Principal":{"AWS":12},"Action":"sts:AssumeRole"},
	  {"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	d := trustParse(t, doc)
	if len(d.Statements) != 2 || d.Statements[0].Index != 0 || d.Statements[1].Index != 2 {
		t.Fatalf("parsed %+v, want statements 0 and 2 with their original indexes", d.Statements)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Index != 1 || !strings.Contains(d.Skipped[0].Reason, "Principal") {
		t.Fatalf("skipped = %+v, want statement 1 named with its reason", d.Skipped)
	}
	reason := ValidateTrustDocument(json.RawMessage(doc))
	if !strings.HasPrefix(reason, "parse: 1 statement(s) unusable: statement index 1: Principal") {
		t.Errorf("ValidateTrustDocument = %q, want the skipped statement to make the document unreadable", reason)
	}
	if _, err := ParseTrustPolicy(doc); err == nil {
		t.Error("legacy ParseTrustPolicy accepted a document with an unusable statement")
	}
}

func TestTrustStatementShapesThatCannotBeRead(t *testing.T) {
	for name, stmt := range map[string]string{
		"canonical user":        `{"Effect":"Allow","Principal":{"CanonicalUser":"79a59df900b949e5"},"Action":"sts:AssumeRole"}`,
		"no principal":          `{"Effect":"Allow","Action":"sts:AssumeRole"}`,
		"both principals":       `{"Effect":"Allow","Principal":"*","NotPrincipal":"*","Action":"sts:AssumeRole"}`,
		"empty principal":       `{"Effect":"Allow","Principal":{},"Action":"sts:AssumeRole"}`,
		"principal string":      `{"Effect":"Allow","Principal":"lambda.amazonaws.com","Action":"sts:AssumeRole"}`,
		"no effect":             `{"Principal":"*","Action":"sts:AssumeRole"}`,
		"odd effect":            `{"Effect":"Maybe","Principal":"*","Action":"sts:AssumeRole"}`,
		"no action":             `{"Effect":"Allow","Principal":"*"}`,
		"action and notaction":  `{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","NotAction":"sts:TagSession"}`,
		"numeric action":        `{"Effect":"Allow","Principal":"*","Action":7}`,
		"condition not object":  `{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":"x"}`,
		"operator not object":   `{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"Bool":true}}`,
		"statement not object":  `"Allow"`,
		"sid not string":        `{"Sid":5,"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}`,
		"principal list number": `{"Effect":"Allow","Principal":{"Service":["a.amazonaws.com",3]},"Action":"sts:AssumeRole"}`,
	} {
		d := trustParse(t, `{"Statement":[`+stmt+`]}`)
		if len(d.Skipped) != 1 || len(d.Statements) != 0 {
			t.Errorf("%s: parsed %d, skipped %v; want the statement skipped, never read as naming nobody",
				name, len(d.Statements), d.Skipped)
		}
	}
	for name, doc := range map[string]string{
		"empty": ``, "not json": `{`, "array": `[]`, "no statement": `{"Version":"2012-10-17"}`,
		"null statement": `{"Statement":null}`, "string statement": `{"Statement":"x"}`,
	} {
		if _, err := ParseTrustDocument(json.RawMessage(doc)); err == nil {
			t.Errorf("%s: document accepted", name)
		}
		if ValidateTrustDocument(json.RawMessage(doc)) == "" {
			t.Errorf("%s: ValidateTrustDocument said readable", name)
		}
	}
}

// Every principal form §4.7's table and T3.4 name, normalised per D-42 with the
// mechanism per D-43.
func TestTrustPrincipalForms(t *testing.T) {
	type want struct {
		kind, issuer, subject, account, identityARN, mech string
		wildcard                                          bool
	}
	const role = `"Action":"sts:AssumeRole"`
	const web = `"Action":"sts:AssumeRoleWithWebIdentity"`
	for name, tc := range map[string]struct {
		stmt string
		want []want
	}{
		"bare account": {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},` + role + `}`,
			[]want{{kind: ExternalAWSAccount, issuer: "aws", subject: "905418271234", account: "905418271234", mech: MechanismSTSAssumeRole}}},
		"root arn is the same account node": {`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::905418271234:root"},` + role + `}`,
			[]want{{kind: ExternalAWSAccount, issuer: "aws", subject: "905418271234", account: "905418271234", mech: MechanismSTSAssumeRole}}},
		"role arn": {`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::905418271234:role/data-reader"},` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "arn:aws:iam::905418271234:role/data-reader",
				account: "905418271234", identityARN: "arn:aws:iam::905418271234:role/data-reader", mech: MechanismSTSAssumeRole}}},
		"user arn with path": {`{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::905418271234:user/ops/priya"]},` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "arn:aws:iam::905418271234:user/ops/priya",
				account: "905418271234", identityARN: "arn:aws:iam::905418271234:user/ops/priya", mech: MechanismSTSAssumeRole}}},
		"session arn never resolves": {`{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::905418271234:assumed-role/ci/run-7"},` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "arn:aws:sts::905418271234:assumed-role/ci/run-7",
				account: "905418271234", mech: MechanismSTSAssumeRole}}},
		"federated user arn": {`{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::905418271234:federated-user/bob"},` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "arn:aws:sts::905418271234:federated-user/bob",
				account: "905418271234", mech: MechanismSTSAssumeRole}}},
		"unique id of a deleted principal": {`{"Effect":"Allow","Principal":{"AWS":"AROA3XFRBF535PLBIFPI4"},` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "AROA3XFRBF535PLBIFPI4", mech: MechanismSTSAssumeRole}}},
		"anyone": {`{"Effect":"Allow","Principal":"*",` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "*", mech: MechanismSTSAssumeRole, wildcard: true}}},
		"any aws principal is the same node": {`{"Effect":"Allow","Principal":{"AWS":"*"},` + role + `}`,
			[]want{{kind: ExternalAWSPrincipal, issuer: "aws", subject: "*", mech: MechanismSTSAssumeRole, wildcard: true}}},
		"service": {`{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","ecs-tasks.amazonaws.com"]},` + role + `}`,
			[]want{{kind: ExternalAWSService, issuer: "aws", subject: "lambda.amazonaws.com", mech: MechanismSTSAssumeRole},
				{kind: ExternalAWSService, issuer: "aws", subject: "ecs-tasks.amazonaws.com", mech: MechanismSTSAssumeRole}}},
		"github oidc wildcard sub": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:oidc-provider/token.actions.githubusercontent.com"},` + web +
			`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:authsec-ai/authsec:*"}}}`,
			[]want{{kind: ExternalOIDC, issuer: "token.actions.githubusercontent.com", subject: "repo:authsec-ai/authsec:*",
				account: "429418377036", mech: MechanismOIDCFederation, wildcard: true}}},
		"oidc with no sub is unscoped": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:oidc-provider/token.actions.githubusercontent.com"},` + web +
			`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}`,
			[]want{{kind: ExternalOIDC, issuer: "token.actions.githubusercontent.com", subject: "*", account: "429418377036",
				mech: MechanismOIDCFederation, wildcard: true}}},
		"a negated sub names nobody": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:oidc-provider/token.actions.githubusercontent.com"},` + web +
			`,"Condition":{"StringNotEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/deploy:ref:refs/heads/main"}}}`,
			[]want{{kind: ExternalOIDC, issuer: "token.actions.githubusercontent.com", subject: "*", account: "429418377036",
				mech: MechanismOIDCFederation, wildcard: true}}},
		"a Null operator is not a subject": {`{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},` + web +
			`,"Condition":{"Null":{"accounts.google.com:sub":"false"}}}`,
			[]want{{kind: ExternalOIDC, issuer: "accounts.google.com", subject: "*", mech: MechanismOIDCFederation, wildcard: true}}},
		"every sub value, one subject each": {`{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},` + web +
			`,"Condition":{"ForAnyValue:StringEquals":{"cognito-identity.amazonaws.com:sub":["us-east-1:bbb","us-east-1:aaa"]}}}`,
			[]want{{kind: ExternalOIDC, issuer: "cognito-identity.amazonaws.com", subject: "us-east-1:bbb", mech: MechanismOIDCFederation},
				{kind: ExternalOIDC, issuer: "cognito-identity.amazonaws.com", subject: "us-east-1:aaa", mech: MechanismOIDCFederation}}},
		"irsa is a kubernetes service account": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"},` + web +
			`,"Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/ABC:sub":"system:serviceaccount:payments:ledger-agent"}}}`,
			[]want{{kind: ExternalK8sSA, issuer: "oidc.eks.us-east-1.amazonaws.com/id/ABC", subject: "system:serviceaccount:payments:ledger-agent",
				account: "429418377036", mech: MechanismOIDCFederation}}},
		"an irsa wildcard is not one service account": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"},` + web +
			`,"Condition":{"StringLike":{"oidc.eks.us-east-1.amazonaws.com/id/ABC:sub":"system:serviceaccount:payments:*"}}}`,
			[]want{{kind: ExternalOIDC, issuer: "oidc.eks.us-east-1.amazonaws.com/id/ABC", subject: "system:serviceaccount:payments:*",
				account: "429418377036", mech: MechanismOIDCFederation, wildcard: true}}},
		"saml without a sub": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML",` +
			`"Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}`,
			[]want{{kind: ExternalSAML, issuer: "arn:aws:iam::429418377036:saml-provider/Okta", subject: "*", account: "429418377036",
				mech: MechanismSAMLFederation, wildcard: true}}},
		"saml with a sub": {`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::429418377036:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML",` +
			`"Condition":{"StringEquals":{"SAML:sub":"priya@example.com"}}}`,
			[]want{{kind: ExternalSAML, issuer: "arn:aws:iam::429418377036:saml-provider/Okta", subject: "priya@example.com",
				account: "429418377036", mech: MechanismSAMLFederation}}},
	} {
		st := trustOnly(t, tc.stmt)
		var got []want
		for _, s := range st.Subjects() {
			got = append(got, want{s.Kind, s.Issuer, s.Subject, s.Account, s.IdentityARN, s.Mechanism, s.Wildcard})
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", name, got, tc.want)
		}
	}
}

// D-43: the mechanism follows the action, and a principal the actions cannot
// serve assumes nothing.
func TestTrustActionDecidesMechanism(t *testing.T) {
	gh := `"Federated":"arn:aws:iam::429418377036:oidc-provider/token.actions.githubusercontent.com"`
	for name, tc := range map[string]struct {
		stmt  string
		mechs []string
	}{
		"tag session alone assumes nothing": {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},"Action":"sts:TagSession"}`, nil},
		"sts wildcard":                      {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},"Action":"sts:*"}`, []string{MechanismSTSAssumeRole}},
		"case and glob":                     {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},"Action":"STS:Assume?ole"}`, []string{MechanismSTSAssumeRole}},
		"not action excluding tag session":  {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},"NotAction":"sts:TagSession"}`, []string{MechanismSTSAssumeRole}},
		"not action excluding assume":       {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},"NotAction":"sts:AssumeRole*"}`, nil},
		"federated under AssumeRole only":   {`{"Effect":"Allow","Principal":{` + gh + `},"Action":"sts:AssumeRole"}`, nil},
		"aws principal under web identity":  {`{"Effect":"Allow","Principal":{"AWS":"905418271234"},"Action":"sts:AssumeRoleWithWebIdentity"}`, nil},
		"mixed statement": {`{"Effect":"Allow","Principal":{"AWS":"905418271234",` + gh + `},` +
			`"Action":["sts:AssumeRole","sts:AssumeRoleWithWebIdentity"]}`, []string{MechanismSTSAssumeRole, MechanismOIDCFederation}},
		"anyone by web identity": {`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}`, []string{MechanismOIDCFederation}},
	} {
		var got []string
		for _, s := range trustOnly(t, tc.stmt).Subjects() {
			got = append(got, s.Mechanism)
		}
		if !reflect.DeepEqual(got, tc.mechs) {
			t.Errorf("%s: mechanisms %v, want %v", name, got, tc.mechs)
		}
	}
}

// Keys are built from these values, so the order must not depend on Go map
// iteration: the same document yields the same subjects, in the same order,
// every time.
func TestTrustSubjectsAreDeterministic(t *testing.T) {
	stmt := `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},` +
		`"Action":"sts:AssumeRoleWithWebIdentity","Condition":{` +
		`"StringLike":{"token.actions.githubusercontent.com:sub":["repo:a/z:*","repo:a/y:*"]},` +
		`"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:a/x:ref:refs/heads/main"},` +
		`"ForAnyValue:StringLike":{"token.actions.githubusercontent.com:sub":"repo:a/w:*"}}}`
	first := trustOnly(t, stmt).Subjects()
	for i := 0; i < 50; i++ {
		if again := trustOnly(t, stmt).Subjects(); !reflect.DeepEqual(again, first) {
			t.Fatalf("run %d: subjects %+v != %+v", i, again, first)
		}
	}
	if len(first) != 4 {
		t.Fatalf("subjects = %+v, want every positive sub value", first)
	}
	// Legacy subClaim picks one, deterministically: the first sorted operator.
	c := trustOnly(t, stmt).cond
	for i := 0; i < 50; i++ {
		if sub, _ := c.subClaim(); sub != "repo:a/w:*" {
			t.Fatalf("subClaim = %q, want the ForAnyValue:StringLike value every time", sub)
		}
	}
}

// D-46: the Sid-less statement hash covers Principal and NotPrincipal, and is
// blind to order, formatting and Sid.
func TestTrustContentHash(t *testing.T) {
	a := trustOnly(t, `{"Sid":"A","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:role/x","arn:aws:iam::1:role/y"]},"Action":"sts:AssumeRole"}`)
	b := trustOnly(t, `{"Effect":"Allow","Action":["sts:AssumeRole"],"Principal":{"AWS":["arn:aws:iam::1:role/y","arn:aws:iam::1:role/x"]}}`)
	c := trustOnly(t, `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:role/x"},"Action":"sts:AssumeRole"}`)
	d := trustOnly(t, `{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::1:role/x"},"Action":"sts:AssumeRole"}`)
	e := trustOnly(t, `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:role/x"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:SecureTransport":true}}}`)
	if a.ContentHash() != b.ContentHash() {
		t.Error("reordering principals or actions, or dropping the Sid, changed the hash")
	}
	seen := map[string]string{}
	for name, st := range map[string]TrustStatement{"two principals": a, "one principal": c, "not principal": d, "condition": e} {
		h := st.ContentHash()
		if other, dup := seen[h]; dup {
			t.Errorf("%s and %s share a content hash", name, other)
		}
		seen[h] = name
	}
}

func TestTrustLegacyViewUnchanged(t *testing.T) {
	got, err := ParseTrustPolicy(`{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com","AWS":["arn:aws:iam::1:role/x","111122223333"]},"Action":"sts:AssumeRole"},
	  {"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"},
	   "Action":"sts:AssumeRoleWithWebIdentity",
	   "Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/ABC:sub":"system:serviceaccount:ns:sa"}}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []TrustPrincipal{
		{SubjectKind: SubjectKindCloudService, Subject: "lambda.amazonaws.com", Mechanism: MechanismSTSAssumeRole},
		{SubjectKind: SubjectKindIdentity, Subject: "arn:aws:iam::1:role/x", Mechanism: MechanismSTSAssumeRole},
		{SubjectKind: SubjectKindExternal, Subject: "111122223333", Mechanism: MechanismSTSAssumeRole},
		{SubjectKind: SubjectKindK8sSA, Subject: "system:serviceaccount:ns:sa", Issuer: "oidc.eks.us-east-1.amazonaws.com/id/ABC",
			K8sRef: "system:serviceaccount:ns:sa", Mechanism: MechanismOIDCFederation},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("legacy principals:\n got  %+v\n want %+v", got, want)
	}
}

func TestTrustReadTrustDocument(t *testing.T) {
	doc, hash, reason := ReadTrustDocument(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`)
	if doc == nil || len(hash) != 64 || reason != "" {
		t.Errorf("readable document = (%s, %q, %q)", doc, hash, reason)
	}
	doc, hash, reason = ReadTrustDocument(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":1},"Action":"sts:AssumeRole"}]}`)
	if doc == nil || hash == "" || !strings.HasPrefix(reason, "parse: 1 statement(s) unusable") {
		t.Errorf("document with an unusable statement = (%s, %q, %q); want stored, with its reason", doc, hash, reason)
	}
	doc, hash, reason = ReadTrustDocument(`%7B not json`)
	if doc != nil || hash != "" || !strings.HasPrefix(reason, "parse:") {
		t.Errorf("non-JSON document = (%s, %q, %q); want NULL with a reason", doc, hash, reason)
	}
	if doc, _, reason = ReadTrustDocument(""); doc != nil || reason == "" {
		t.Errorf("absent document = (%s, %q); want unreadable, never 'trusts nobody'", doc, reason)
	}
}
