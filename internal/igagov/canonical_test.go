package igagov

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

// RFC 8785 Appendix B: IEEE 754 bit patterns and their ES6 serialisation.
func TestFormatNumberES6_RFC8785AppendixB(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, c := range cases {
		if got := FormatNumberES6(math.Float64frombits(c.bits)); got != c.want {
			t.Errorf("%016x: got %s, want %s", c.bits, got, c.want)
		}
	}
}

func TestCanonicalize_RFC8785Examples(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			// RFC 8785 §3.2.2 (the "numbers / string / literals" example).
			name: "rfc8785-3.2.2",
			in: `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`,
			want: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{
			// RFC 8785 §3.2.3: sorting by UTF-16 code units. The emoji
			// (U+1F600, D83D DE00) sorts before U+FB33 although its code
			// point and UTF-8 bytes are larger.
			name: "rfc8785-3.2.3-sorting",
			in: `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`,
			want: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
		{name: "nested-sort", in: `{"b":{"z":1,"a":[{"y":true,"x":null}]},"a":"s"}`, want: `{"a":"s","b":{"a":[{"x":null,"y":true}],"z":1}}`},
		{name: "html-not-escaped", in: `"<&>\u2028"`, want: "\"<&>\u2028\""},
		{name: "controls", in: `"\u0000\u001f\u007f\b\f\t"`, want: "\"\\u0000\\u001f\u007f\\b\\f\\t\""},
		{name: "empty", in: ` { } `, want: `{}`},
		{name: "neg-zero", in: `-0.0`, want: `0`},
		{name: "integers", in: `[1,10,100,1e2,1E+2,123456789012345678901234567890]`, want: `[1,10,100,100,100,1.2345678901234568e+29]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got  %s\nwant %s", got, c.want)
			}
			again, err := Canonicalize(got)
			if err != nil || string(again) != string(got) {
				t.Fatalf("not idempotent: %s (%v)", again, err)
			}
		})
	}
}

func TestCanonicalize_RefusesNonIJSON(t *testing.T) {
	bad := map[string]string{
		"duplicate key":  `{"a":1,"a":2}`,
		"lone high":      `"\ud800"`,
		"lone low":       `"\udc00x"`,
		"high then bmp":  `"\ud800\u0041"`,
		"high then junk": `"\uD800xxdc00"`,
		"low then low":   `"\uDC00\uDC00"`,
		"invalid utf8":   "\"\xff\"",
		"utf8 surrogate": "\"\xed\xa0\x80\"",
		"overflow":       `1e400`,
		"trailing":       `{} x`,
		"leading zero":   `01`,
		"bare dot":       `1.`,
		"raw control":    "\"a\x01\"",
		"bad escape":     `"\x"`,
		"unterminated":   `{"a":`,
		"single quotes":  `{'a':1}`,
		"nan":            `NaN`,
		"empty":          ``,
		"trailing comma": `[1,]`,
	}
	for name, in := range bad {
		if _, err := Canonicalize([]byte(in)); !errors.Is(err, ErrNotIJSON) {
			t.Errorf("%s: want ErrNotIJSON, got %v", name, err)
		}
	}
	deep := strings.Repeat("[", maxJSONDepth+2) + strings.Repeat("]", maxJSONDepth+2)
	if _, err := Canonicalize([]byte(deep)); err == nil {
		t.Error("over-deep nesting accepted")
	}
}

func TestCanonicalizeValue_StructAndMapOrder(t *testing.T) {
	type s struct {
		Z string         `json:"z"`
		A map[string]int `json:"a"`
		H string         `json:"h"`
	}
	got, err := CanonicalizeValue(s{Z: "z", A: map[string]int{"y": 2, "b": 1}, H: "<b>"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":{"b":1,"y":2},"h":"<b>","z":"z"}`; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestLessUTF16(t *testing.T) {
	if !lessUTF16("\U0001F600", "\uFB33") {
		t.Fatal("U+1F600 must sort before U+FB33 by UTF-16 code units")
	}
	if !lessUTF16("a", "ab") || lessUTF16("ab", "a") || lessUTF16("a", "a") {
		t.Fatal("prefix ordering wrong")
	}
}

func TestDecodePolicyDocument_Shapes(t *testing.T) {
	// Statement as an object; Action as a string; URL-encoded as AWS returns.
	enc := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22arn%3Aaws%3As3%3A%3A%3Ab%2Fa%2Bb%22%7D%7D"
	doc, err := DecodePolicyDocument(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Action[0] != "s3:GetObject" ||
		doc.Statements[0].Resource[0] != "arn:aws:s3:::b/a+b" {
		t.Fatalf("decoded %+v", doc)
	}

	arr := `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {"Sid": "A", "Effect": "Allow", "NotAction": ["iam:*", "sts:*"], "NotResource": "arn:aws:s3:::x"},
	    {"Effect": "Deny", "Principal": {"AWS": ["arn:aws:iam::111122223333:role/r", "111122223333"], "Service": "lambda.amazonaws.com"},
	     "Action": "sqs:*", "Resource": "*",
	     "Condition": {"StringEquals": {"aws:PrincipalArn": "arn:x", "aws:SourceAccount": ["1", "2"]}, "Bool": {"aws:SecureTransport": false}}},
	    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*", "Custom": 1}
	  ]}`
	doc, err = DecodePolicyDocument(arr)
	if err != nil {
		t.Fatal(err)
	}
	st := doc.Statements
	if !st[0].IsNotAction || len(st[0].NotAction) != 2 || st[0].NotResource[0] != "arn:aws:s3:::x" {
		t.Fatalf("statement 0: %+v", st[0])
	}
	if st[1].Principal == nil || len(st[1].Principal.Values["AWS"]) != 2 || st[1].Principal.Wildcard {
		t.Fatalf("statement 1 principal: %+v", st[1].Principal)
	}
	if len(st[1].Conditions) != 3 || st[1].Conditions[0].Operator != "Bool" || st[1].Conditions[0].Values[0] != "false" {
		t.Fatalf("statement 1 conditions: %+v", st[1].Conditions)
	}
	if !st[2].Principal.Wildcard || len(st[2].Unknown) != 1 {
		t.Fatalf("statement 2: %+v", st[2])
	}
	var raw map[string]any
	if err := json.Unmarshal(st[1].Raw, &raw); err != nil || raw["Effect"] != "Deny" {
		t.Fatalf("raw: %s", st[1].Raw)
	}
}

func TestDecodePolicyDocument_Refusals(t *testing.T) {
	bad := map[string]string{
		"no statement":     `{"Version":"2012-10-17"}`,
		"bad effect":       `{"Statement":{"Effect":"allow","Action":"*"}}`,
		"both actions":     `{"Statement":{"Effect":"Allow","Action":"*","NotAction":"s3:*"}}`,
		"no action":        `{"Statement":{"Effect":"Allow","Resource":"*"}}`,
		"numeric action":   `{"Statement":{"Effect":"Allow","Action":[1]}}`,
		"principal string": `{"Statement":{"Effect":"Allow","Action":"*","Principal":"me"}}`,
		"statement string": `{"Statement":"x"}`,
		"not object":       `[]`,
		"duplicate key":    `{"Statement":{"Effect":"Allow","Effect":"Deny","Action":"*"}}`,
		"bad url encoding": `%zz`,
		"condition array":  `{"Statement":{"Effect":"Allow","Action":"*","Condition":[]}}`,
		"both principals":  `{"Statement":{"Effect":"Allow","Action":"*","Principal":"*","NotPrincipal":"*"}}`,
	}
	for name, in := range bad {
		if _, err := DecodePolicyDocument(in); !errors.Is(err, ErrPolicyDocument) {
			t.Errorf("%s: want ErrPolicyDocument, got %v", name, err)
		}
	}
}

func TestCanonicalDocument_WhitespaceAndEncodingInsensitive(t *testing.T) {
	a := `{"Version":"2012-10-17","Statement":[{"Sid":"AuthSecAllowAllExceptRemoved","Effect":"Allow","NotAction":["ec2:*","sqs:*"],"Resource":"*"}]}`
	b := "  {\n \"Statement\" : [ { \"Resource\":\"*\", \"NotAction\" : [\"ec2:*\",\"sqs:*\"],\"Effect\":\"Allow\",\"Sid\":\"AuthSecAllowAllExceptRemoved\"}],\"Version\":\"2012-10-17\"}\n"
	enc := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22AuthSecAllowAllExceptRemoved%22%2C%22Effect%22%3A%22Allow%22%2C%22NotAction%22%3A%5B%22ec2%3A%2A%22%2C%22sqs%3A%2A%22%5D%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"
	ca, ha, err := CanonicalDocument(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{b, enc} {
		cb, hb, err := CanonicalDocument(other)
		if err != nil {
			t.Fatal(err)
		}
		if string(ca) != string(cb) || ha != hb {
			t.Fatalf("canonical differs:\n%s\n%s", ca, cb)
		}
	}
	if !strings.HasPrefix(ha, "sha256:") || len(ha) != 71 {
		t.Fatalf("hash form %s", ha)
	}
	if _, _, err := CanonicalDocument(`{"Statement":"\u0000"}`); !errors.Is(err, ErrNotStorable) {
		t.Fatalf("U+0000 must be refused for jsonb storage, got %v", err)
	}
}

func TestStatementNamespaces(t *testing.T) {
	st := func(js string) Statement {
		d, err := DecodePolicyDocument(`{"Statement":` + js + `}`)
		if err != nil {
			t.Fatal(err)
		}
		return d.Statements[0]
	}
	cases := []struct {
		st   Statement
		ns   string
		want bool
	}{
		{st(`{"Effect":"Allow","Action":"*"}`), "sqs", true},
		{st(`{"Effect":"Allow","Action":"SQS:Send*"}`), "sqs", true},
		{st(`{"Effect":"Allow","Action":"s*:*"}`), "sqs", true},
		{st(`{"Effect":"Allow","Action":"s3:*"}`), "sqs", false},
		{st(`{"Effect":"Deny","Action":"sqs:*"}`), "sqs", false},
		{st(`{"Effect":"Allow","NotAction":"sqs:*"}`), "sqs", false},
		{st(`{"Effect":"Allow","NotAction":"sqs:SendMessage"}`), "sqs", true},
		{st(`{"Effect":"Allow","NotAction":"s3:*"}`), "sqs", true},
		{st(`{"Effect":"Allow","NotAction":"*"}`), "sqs", false},
	}
	for i, c := range cases {
		if got := c.st.GrantsNamespace(c.ns); got != c.want {
			t.Errorf("case %d: GrantsNamespace(%s) = %v", i, c.ns, got)
		}
	}
	if got := st(`{"Effect":"Allow","Action":["S3:Get*","sqs:*","s*:x","*"]}`).ExplicitNamespaces(); strings.Join(got, ",") != "s3,sqs" {
		t.Fatalf("ExplicitNamespaces %v", got)
	}
}

func TestGlobs(t *testing.T) {
	match := []struct {
		p, s string
		want bool
	}{
		{"iam:Create*", "IAM:CreateRole", true},
		{"iam:?reate*", "iam:CreateRole", true},
		{"iam:Create*", "iam:DeleteRole", false},
		{"*", "", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, c := range match {
		if globMatch(c.p, c.s) != c.want {
			t.Errorf("globMatch(%q,%q) != %v", c.p, c.s, c.want)
		}
	}
	inter := []struct {
		a, b string
		want bool
	}{
		{"iam:C*", "iam:Create*", true},
		{"iam:*", "iam:PassRole", true},
		{"iam:Get*", "iam:Create*", false},
		{"*:PassRole", "iam:Pass*", true},
		{"iam:Put*", "iam:Put*Policy", true},
		{"iam:PutRole", "iam:Put*Policy", false},
		{"iam:PutRolePolicy", "iam:Put*Policy", true},
		{"lambda:Update*", "lambda:UpdateFunctionCode", true},
	}
	for _, c := range inter {
		if globsIntersect(c.a, c.b) != c.want || globsIntersect(c.b, c.a) != c.want {
			t.Errorf("globsIntersect(%q,%q) != %v", c.a, c.b, c.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a, err := Fingerprint(KindUnusedService, "AROAEXAMPLE1", "sqs")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Fingerprint(KindUnusedService, "AROAEXAMPLE1", "sns")
	c, _ := Fingerprint(KindUnusedService, "AROAEXAMPLE1", "sqs")
	if a == b || a != c {
		t.Fatal("fingerprint not stable / not distinct")
	}
	// sha256("unused_service\x1fAROAEXAMPLE1\x1fsqs"), computed independently
	// (see testdata/golden_hashes.json and TestGoldenHashes).
	if _, err := Fingerprint("k", "AROA\x1fX", ""); err == nil {
		t.Fatal("U+001F inside a field must be refused")
	}
	if _, err := Fingerprint("", "AROA", ""); err == nil {
		t.Fatal("empty kind accepted")
	}
}

func strp(s string) *string { return &s }

func samplePlanInput() PlanHashInput {
	return PlanHashInput{
		ControlID: "6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11", Kind: "apply", Delivery: "direct",
		DesiredAttachment: "present", DesiredBoundaryARN: strp("arn:aws:iam::429418377036:policy/authsec/AuthSecBoundary-AROAEXAMPLE1"),
		DesiredDocumentHash: strp("sha256:" + strings.Repeat("a", 64)), ArtifactDisposition: "keep",
		BundleHash: "sha256:" + strings.Repeat("b", 64), EvidenceRev: 812, ResourcePolicyScanRunID: strp("0b6f7c1e-1d2a-4c55-8d0e-7a6b5c4d3e2f"),
		FirstAttachment: true, Unanalysed: []UnanalysedItem{{Key: "other_accounts"}, {Key: "unanalysed_form:ecr_repository", Form: "ecr_repository"}},
		PreconditionHash: "sha256:" + strings.Repeat("c", 64),
		Ops:              []map[string]string{{"op": "CreatePolicy"}, {"op": "PutRolePermissionsBoundary"}},
	}
}

func TestPlanAndMaterialHash(t *testing.T) {
	base := samplePlanInput()
	ph, err := PlanHash(base)
	if err != nil {
		t.Fatal(err)
	}
	mi := MaterialHashInput{Plan: base, ImpactHash: "sha256:" + strings.Repeat("d", 64),
		Gaps: []GapRef{{Key: "z", Hash: "h1"}, {Key: "a", Hash: "h2"}}}
	mh, err := MaterialHash(mi)
	if err != nil {
		t.Fatal(err)
	}

	// Evidence identifiers change plan_hash but not material_hash (§2.8).
	ev := base
	ev.BundleHash = "sha256:" + strings.Repeat("e", 64)
	ev.EvidenceRev = 813
	ev.ResourcePolicyScanRunID = strp("11111111-1111-1111-1111-111111111111")
	ph2, _ := PlanHash(ev)
	mh2, _ := MaterialHash(MaterialHashInput{Plan: ev, ImpactHash: mi.ImpactHash, Gaps: mi.Gaps})
	if ph2 == ph || mh2 != mh {
		t.Fatalf("evidence ids: plan %v material %v", ph2 != ph, mh2 == mh)
	}

	// Gap order and unanalysed order do not matter; content does.
	re := base
	re.Unanalysed = []UnanalysedItem{base.Unanalysed[1], base.Unanalysed[0]}
	mh3, _ := MaterialHash(MaterialHashInput{Plan: re, ImpactHash: mi.ImpactHash, Gaps: []GapRef{mi.Gaps[1], mi.Gaps[0]}})
	if mh3 != mh {
		t.Fatal("material hash depends on order")
	}

	// Each material input changes both hashes.
	mut := map[string]func(*PlanHashInput){
		"control":     func(p *PlanHashInput) { p.ControlID = "x" },
		"kind":        func(p *PlanHashInput) { p.Kind = "undo" },
		"delivery":    func(p *PlanHashInput) { p.Delivery = "export" },
		"attachment":  func(p *PlanHashInput) { p.DesiredAttachment = "absent" },
		"desired arn": func(p *PlanHashInput) { p.DesiredBoundaryARN = nil },
		"document":    func(p *PlanHashInput) { p.DesiredDocumentHash = strp("sha256:" + strings.Repeat("f", 64)) },
		"replaced":    func(p *PlanHashInput) { p.ReplacedBoundaryARN = strp("arn:x") },
		"disposition": func(p *PlanHashInput) { p.ArtifactDisposition = "delete" },
		"first":       func(p *PlanHashInput) { p.FirstAttachment = false },
		"unanalysed":  func(p *PlanHashInput) { p.Unanalysed = p.Unanalysed[:1] },
		"precond":     func(p *PlanHashInput) { p.PreconditionHash = "sha256:" + strings.Repeat("0", 64) },
		"ops":         func(p *PlanHashInput) { p.Ops = []string{"CreatePolicy"} },
	}
	for name, m := range mut {
		p := base
		m(&p)
		a, err1 := PlanHash(p)
		b, err2 := MaterialHash(MaterialHashInput{Plan: p, ImpactHash: mi.ImpactHash, Gaps: mi.Gaps})
		if err1 != nil || err2 != nil {
			t.Fatalf("%s: %v %v", name, err1, err2)
		}
		if a == ph || b == mh {
			t.Errorf("%s: plan changed %v, material changed %v", name, a != ph, b != mh)
		}
	}
	// NULL and "" are distinct.
	n1, n2 := base, base
	n1.ReplacedBoundaryARN = nil
	n2.ReplacedBoundaryARN = strp("")
	a, _ := PlanHash(n1)
	b, _ := PlanHash(n2)
	if a == b {
		t.Fatal("NULL and empty string hash alike")
	}
	// Impact and gaps change material only.
	mh4, _ := MaterialHash(MaterialHashInput{Plan: base, ImpactHash: "sha256:" + strings.Repeat("9", 64), Gaps: mi.Gaps})
	mh5, _ := MaterialHash(MaterialHashInput{Plan: base, ImpactHash: mi.ImpactHash, Gaps: mi.Gaps[:1]})
	if mh4 == mh || mh5 == mh {
		t.Fatal("impact or gaps do not change the material hash")
	}
	if _, err := PlanHash(PlanHashInput{}); err == nil {
		t.Fatal("empty plan input accepted")
	}
	if _, err := MaterialHash(MaterialHashInput{Plan: base}); err == nil {
		t.Fatal("material hash without impact accepted")
	}
}

func TestPreconditionAndImpactHashes(t *testing.T) {
	arn, doc := "arn:aws:iam::1:policy/authsec/B", "sha256:"+strings.Repeat("1", 64)
	s1 := ArtifactStateFacts{RoleID: "AROA1", BoundaryARN: &arn, BoundaryDocumentHash: &doc, AttachmentSet: []AttachedEntity{
		{Kind: "role", ID: "AROA2", Name: "b", Usage: UsageBoundary}, {Kind: "role", ID: "AROA1", Name: "a", Usage: UsageBoundary}}}
	s2 := s1
	s2.AttachmentSet = []AttachedEntity{s1.AttachmentSet[1], s1.AttachmentSet[0]}
	h1, err := StatePreconditionHash(s1)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := StatePreconditionHash(s2)
	if h1 != h2 {
		t.Fatal("attachment set order changes the state hash")
	}
	s3 := s1
	s3.AttachmentSet = s1.AttachmentSet[:1]
	if h3, _ := StatePreconditionHash(s3); h3 == h1 {
		t.Fatal("a new user of the policy must change the undo precondition (§8.3)")
	}
	if _, err := StatePreconditionHash(ArtifactStateFacts{RoleID: "AROA1", BoundaryARN: &arn}); err == nil {
		t.Fatal("ARN without document hash accepted")
	}
	ap := ApplyPrecondition{ArtifactState: s1, RoleARN: "arn:aws:iam::1:role/r", RolePath: "/",
		ManagedPolicies: []PolicyRef{{Ref: "b", DocumentHash: "h"}, {Ref: "a", DocumentHash: "h"}}}
	ah, err := ApplyPreconditionHash(ap)
	if err != nil {
		t.Fatal(err)
	}
	if ah == h1 {
		t.Fatal("apply and state preconditions share a domain")
	}
	ap2 := ap
	ap2.InlinePolicies = []PolicyRef{{Ref: "inline", DocumentHash: "h"}}
	if ah2, _ := ApplyPreconditionHash(ap2); ah2 == ah {
		t.Fatal("the role's own policies must enter the apply precondition")
	}

	im := Impact{Consumers: []ImpactConsumer{{"w2", RelExecutesAs}, {"w1", RelExecutesAs}, {"w1", RelExecutesAs}},
		OwnerUserIDs: []string{"u2", "u1"}, Removed: []ImpactService{{"sqs", RemoveNoAttempt}},
		Retained: []ImpactService{{"s3", RetainObserved}}, StatementRevisions: []string{"h2", "h1"},
		Routes: []Route{{Service: "sqs", Resource: "arn:q", Principal: PrincipalRoleARN, Effect: RouteEffectLimited}}}
	i1, err := ImpactHash(im)
	if err != nil {
		t.Fatal(err)
	}
	im2 := im
	im2.Consumers = []ImpactConsumer{{"w1", RelExecutesAs}, {"w2", RelExecutesAs}}
	im2.OwnerUserIDs = []string{"u1", "u2"}
	if i2, _ := ImpactHash(im2); i2 != i1 {
		t.Fatal("impact hash depends on order or duplicates")
	}
	im3 := im
	im3.Consumers = append(append([]ImpactConsumer{}, im.Consumers...), ImpactConsumer{"w3", RelExecutesAs})
	if i3, _ := ImpactHash(im3); i3 == i1 {
		t.Fatal("a new consumer must change impact_hash (A23)")
	}
}

func TestIntentHashKeyOrderInsensitive(t *testing.T) {
	a, err := IntentHash([]byte(`{"kind":"remove_control","reason":"x","control_ids":["a"]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := IntentHash([]byte("{ \"control_ids\" : [\"a\"], \"reason\":\"x\",\n\"kind\":\"remove_control\"}"))
	if a != b {
		t.Fatal("intent hash depends on formatting")
	}
	c, _ := HashCanonicalTagged(DomainImpact, json.RawMessage(`{"kind":"remove_control","reason":"x","control_ids":["a"]}`))
	if c == a {
		t.Fatal("intent and impact domains collide")
	}
}
