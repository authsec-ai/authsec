package igagov

import (
	"strings"
	"testing"
	"time"
)

func bundleInput(t testing.TB) BundleInput {
	cov := &ResourcePolicyEvidence{Coverage: completeCoverage()}
	return BundleInput{
		BuiltAt: now,
		Sources: []BundleSourceInput{{Kind: SourceAWSPublication, Rev: 812, PublishedAt: now.Add(-3 * time.Hour), ConnectorID: connA,
			ConnectorRun: runA1, Authenticated: true, Ordered: true, ActivityReportGeneratedAt: tp(now.Add(-3 * time.Hour)),
			ResourcePolicyCoverage: SummarizeCoverage(cov, regions), ResourcePolicyRun: runA1}},
		Target:          BundleTarget{AccountID: acct, RoleID: roleID, RoleARN: roleARN},
		RemovedServices: []string{"sqs"},
		Grants: []BundleGrant{
			{PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyB", AssignmentKind: AssignAttached, StatementKey: "PB#0", StatementHash: "hb", Services: []string{"sqs"}},
			{PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyA", AssignmentKind: AssignAttached, StatementKey: "PA#0", StatementHash: "ha", Services: []string{"sqs", "s3", "sqs"}},
		},
		Consumers: []ImpactConsumer{{WorkloadID: wl1, Relationship: RelExecutesAs}},
		Owners:    []string{"u2", "u1", "u1"},
		Activity: []BundleActivity{
			{Service: "sqs", State: EvidenceCollected, Outcome: QualNoAttempt, GrantAgeBasis: GrantAgePredatesObservation, QualifiedDays: 112},
			{Service: "s3", State: EvidenceCollected, Outcome: QualObserved, LastAuthenticatedAt: ts(tp(daysAgo(1))), GrantAgeBasis: GrantAgePredatesObservation, QualifiedDays: 112},
		},
		RouteAnalyses: []RouteAnalysis{AnalyzeRoutes("sqs", refundRole, &ResourcePolicyEvidence{Coverage: cov.Coverage}, regions)},
	}
}

func TestBuildBundle_TrustedAndHashed(t *testing.T) {
	b, err := BuildBundle(bundleInput(t), DefaultTrustRules())
	if err != nil {
		t.Fatal(err)
	}
	if b.Trust != TrustTrusted || len(b.TrustReasons) != 0 || len(b.Facts.Gaps) != 0 {
		t.Fatalf("trust %s %v gaps %v", b.Trust, b.TrustReasons, b.Facts.Gaps)
	}
	if b.Hash != ContentHash(b.Canonical) || !strings.HasPrefix(b.Hash, "sha256:") {
		t.Fatal("bundle_hash must be the content hash of the canonical text (050 trigger)")
	}
	if c, _ := Canonicalize(b.Canonical); string(c) != string(b.Canonical) {
		t.Fatal("bundle text is not canonical")
	}
	f := b.Facts
	if f.Sources[0].FreshnessHours != 3 || f.Target.EstateScope != "aws:account:"+acct ||
		f.Grants[0].StatementKey != "PA#0" || strings.Join(f.Grants[0].Services, ",") != "s3,sqs" ||
		strings.Join(f.Owners, ",") != "u1,u2" || f.Activity[0].Service != "s3" || f.Catalog != "catalog@1" {
		t.Fatalf("facts not normalised: %+v", f)
	}
	// Facts survive the round trip and trust re-derives identically.
	facts, trust, reasons, err := ParseBundle(b.Canonical, b.Hash)
	if err != nil || trust != b.Trust || len(reasons) != 0 || facts.Sources[0].ConnectorRun != runA1 {
		t.Fatalf("parse: %v %s %v", err, trust, reasons)
	}
	if _, _, _, err := ParseBundle(b.Canonical, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("hash mismatch accepted")
	}
	pretty := strings.Replace(string(b.Canonical), ",", ", ", 1)
	if _, _, _, err := ParseBundle([]byte(pretty), ContentHash([]byte(pretty))); err == nil {
		t.Fatal("non-canonical text accepted")
	}
	// Order of inputs does not change the hash.
	in := bundleInput(t)
	in.Grants[0], in.Grants[1] = in.Grants[1], in.Grants[0]
	in.Activity[0], in.Activity[1] = in.Activity[1], in.Activity[0]
	b2, _ := BuildBundle(in, DefaultTrustRules())
	if b2.Hash != b.Hash {
		t.Fatal("bundle hash depends on input order")
	}
}

// A53: evidence not trustworthy.
func TestBuildBundle_A53_Trust(t *testing.T) {
	t.Run("a: activity report older than the freshness rule → untrusted, naming the source", func(t *testing.T) {
		in := bundleInput(t)
		in.Sources[0].ActivityReportGeneratedAt = tp(now.Add(-25 * time.Hour))
		b, err := BuildBundle(in, DefaultTrustRules())
		if err != nil {
			t.Fatal(err)
		}
		if b.Trust != TrustUntrusted || !containsSub(b.TrustReasons, "stale") || !containsSub(b.TrustReasons, runA1) {
			t.Fatalf("%s %v", b.Trust, b.TrustReasons)
		}
		in.Sources[0].ActivityReportGeneratedAt = tp(now.Add(-24 * time.Hour))
		if b, _ := BuildBundle(in, DefaultTrustRules()); b.Trust != TrustTrusted {
			t.Fatalf("exactly 24 h is still fresh: %v", b.TrustReasons)
		}
	})
	t.Run("b: resource-policy coverage partial → partial with each gap", func(t *testing.T) {
		in := bundleInput(t)
		rows := completeCoverage()
		for i := range rows {
			if rows[i].Form == "sqs_queue" && rows[i].Region == "eu-west-1" {
				rows[i].State, rows[i].Reason = CoveragePartial, "2 queues unreadable"
			}
		}
		ev := &ResourcePolicyEvidence{Coverage: rows}
		in.Sources[0].ResourcePolicyCoverage = SummarizeCoverage(ev, regions)
		in.RouteAnalyses = []RouteAnalysis{AnalyzeRoutes("sqs", refundRole, ev, regions)}
		b, err := BuildBundle(in, DefaultTrustRules())
		if err != nil {
			t.Fatal(err)
		}
		if b.Trust != TrustPartial || len(b.Facts.Gaps) != 1 || b.Facts.Gaps[0].Key != "resource_policy_coverage:sqs_queue:eu-west-1" {
			t.Fatalf("%s %v %+v", b.Trust, b.TrustReasons, b.Facts.Gaps)
		}
		if len(b.GapRefs) != 1 || b.GapRefs[0].Key != b.Facts.Gaps[0].Key || !strings.HasPrefix(b.GapRefs[0].Hash, "sha256:") {
			t.Fatalf("gap refs %+v", b.GapRefs)
		}
		if b.Facts.Sources[0].Trust != TrustPartial {
			t.Fatalf("source trust %s", b.Facts.Sources[0].Trust)
		}
	})
	t.Run("c: a Kubernetes source → untrusted with K-1", func(t *testing.T) {
		in := bundleInput(t)
		in.Sources = append(in.Sources, BundleSourceInput{Kind: SourceK8sSweep, PublishedAt: now, ConnectorID: "k", ConnectorRun: "sweep-9"})
		b, _ := BuildBundle(in, DefaultTrustRules())
		if b.Trust != TrustUntrusted || !containsSub(b.TrustReasons, "K-1") || !containsSub(b.TrustReasons, "unauthenticated") {
			t.Fatalf("%s %v", b.Trust, b.TrustReasons)
		}
	})
	t.Run("unauthenticated / unordered sources are untrusted", func(t *testing.T) {
		for _, edit := range []func(*BundleSourceInput){
			func(s *BundleSourceInput) { s.Authenticated = false },
			func(s *BundleSourceInput) { s.Ordered = false },
		} {
			in := bundleInput(t)
			edit(&in.Sources[0])
			if b, _ := BuildBundle(in, DefaultTrustRules()); b.Trust != TrustUntrusted {
				t.Fatalf("%s %v", b.Trust, b.TrustReasons)
			}
		}
	})
	t.Run("a removed service without collected activity cannot support removal", func(t *testing.T) {
		in := bundleInput(t)
		in.RemovedServices = []string{"sqs", "sns"}
		b, _ := BuildBundle(in, DefaultTrustRules())
		if b.Trust != TrustUntrusted || !containsSub(b.TrustReasons, "activity_not_collected:sns") {
			t.Fatalf("%s %v", b.Trust, b.TrustReasons)
		}
	})
	t.Run("uncollected forms of a removed namespace and unresolved consumers are gaps", func(t *testing.T) {
		in := bundleInput(t)
		in.RemovedServices = []string{"ecr"}
		in.Activity = append(in.Activity, BundleActivity{Service: "ecr", State: EvidenceCollected, Outcome: QualNoAttempt, QualifiedDays: 90})
		in.RouteAnalyses = []RouteAnalysis{AnalyzeRoutes("ecr", refundRole, &ResourcePolicyEvidence{Coverage: completeCoverage()}, regions),
			AnalyzeRoutes("sqs", refundRole, &ResourcePolicyEvidence{Coverage: completeCoverage()}, regions)}
		in.ConsumersUnresolved = 2
		b, _ := BuildBundle(in, DefaultTrustRules())
		var keys []string
		for _, g := range b.Facts.Gaps {
			keys = append(keys, g.Key)
		}
		if b.Trust != TrustPartial || strings.Join(keys, ",") != "consumers_unresolved,unanalysed_form:ecr_registry,unanalysed_form:ecr_repository" {
			t.Fatalf("%s %v", b.Trust, keys)
		}
	})
	t.Run("routes of removed services are facts, not gaps", func(t *testing.T) {
		in := bundleInput(t)
		ev := &ResourcePolicyEvidence{Coverage: completeCoverage(), Observations: []ResourcePolicyObservation{
			queue(t, "refunds", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+roleARN+`"},"Action":"sqs:*","Resource":"*"}}`)}}
		in.RouteAnalyses = []RouteAnalysis{AnalyzeRoutes("sqs", refundRole, ev, regions)}
		b, _ := BuildBundle(in, DefaultTrustRules())
		if b.Trust != TrustTrusted || len(b.Facts.Routes) != 1 || b.Facts.Routes[0].Effect != RouteEffectLimited {
			t.Fatalf("%s %+v", b.Trust, b.Facts.Routes)
		}
	})
}

func TestBuildBundle_Refusals(t *testing.T) {
	cases := map[string]func(*BundleInput){
		"no source":          func(in *BundleInput) { in.Sources = nil },
		"no build time":      func(in *BundleInput) { in.BuiltAt = time.Time{} },
		"no target":          func(in *BundleInput) { in.Target = BundleTarget{} },
		"negative consumers": func(in *BundleInput) { in.ConsumersUnresolved = -1 },
		"duplicate activity": func(in *BundleInput) { in.Activity = append(in.Activity, in.Activity[0]) },
		"NUL in a fact":      func(in *BundleInput) { in.Owners = []string{"a\x00b"} },
	}
	for name, edit := range cases {
		in := bundleInput(t)
		edit(&in)
		if _, err := BuildBundle(in, DefaultTrustRules()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func containsSub(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
