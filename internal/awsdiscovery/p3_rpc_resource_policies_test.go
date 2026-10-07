package awsdiscovery

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery/rpfake"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// T3.03b (SPEC-iga-phase3-policy.md §3.9): resource-policy collection over
// fake clients -- every form present / absent / denied / throttled /
// paginated, coverage completeness per form and region, the shared Lambda
// listing, the budget, and the discovery template's grant.

const rpAcct = "429418377036"

const rpPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::429418377036:role/app"},"Action":"sqs:SendMessage","Resource":"*"}]}`

func rpClients(regions map[string]*rpfake.Region) ResourcePolicyClientsFunc {
	return func(_ context.Context, region string) (ResourcePolicyClients, error) {
		r, ok := regions[region]
		if !ok {
			return ResourcePolicyClients{}, errors.New("no fake for " + region)
		}
		return ResourcePolicyClients{S3: r, S3Control: r, KMS: r, SQS: r, SNS: r, Lambda: r, Secrets: r}, nil
	}
}

func fastCollector() *ResourcePolicyCollector {
	return NewResourcePolicyCollector(CollectorOptions{MinCallInterval: -1, Backoff: time.Nanosecond,
		Sleep: func(context.Context, time.Duration) error { return nil }})
}

// fullRegion holds one resource of every regional form, each with a policy.
func fullRegion(name string) *rpfake.Region {
	fnARN := "arn:aws:lambda:" + name + ":" + rpAcct + ":function:refund"
	return &rpfake.Region{
		Name: name, AccountID: rpAcct, PageSize: 1,
		DirBuckets:   []rpfake.Named{{Name: "fast--use1-az4--x-s3", Policy: rpPolicy}},
		AccessPoints: []rpfake.Named{{Name: "exports-ap", Policy: rpPolicy}},
		OLAPs:        []rpfake.Named{{Name: "redact-olap", Policy: rpPolicy}},
		Keys:         []rpfake.ARNPolicy{{ARN: "arn:aws:kms:" + name + ":" + rpAcct + ":key/k1", Policy: rpPolicy}},
		Queues: []rpfake.Queue{
			{URL: "https://sqs." + name + ".amazonaws.com/" + rpAcct + "/refunds", Policy: rpPolicy},
			{URL: "https://sqs." + name + ".amazonaws.com/" + rpAcct + "/plain"},
		},
		Topics: []rpfake.ARNPolicy{{ARN: "arn:aws:sns:" + name + ":" + rpAcct + ":alerts", Policy: rpPolicy}},
		Functions: []rpfake.Function{{Name: "refund", ARN: fnARN,
			Versions: []rpfake.Version{{Version: "1"}, {Version: "2", Policy: rpPolicy}},
			Aliases:  []rpfake.Named{{Name: "live", Policy: rpPolicy}, {Name: "beta"}}}},
		Layers:  []rpfake.Layer{{ARN: "arn:aws:lambda:" + name + ":" + rpAcct + ":layer:shared", Versions: []rpfake.LayerVersion{{Version: 1, Policy: rpPolicy}, {Version: 2}}}},
		Secrets: []rpfake.ARNPolicy{{ARN: "arn:aws:secretsmanager:" + name + ":" + rpAcct + ":secret:db-AbCdEf", Policy: rpPolicy}},
	}
}

func homeRegion() *rpfake.Region {
	r := fullRegion("us-east-1")
	r.Buckets = []rpfake.Bucket{{Name: "exports", Region: "us-east-1"}, {Name: "logs", Region: "us-east-1"}}
	r.BucketPolicies = map[string]string{"exports": rpPolicy}
	return r
}

func byKey(cs []FormCoverage) map[string]FormCoverage {
	out := map[string]FormCoverage{}
	for _, c := range cs {
		out[c.Form+"/"+c.Region] = c
	}
	return out
}

func readsByARN(c FormCoverage) map[string]PolicyRead {
	out := map[string]PolicyRead{}
	for _, r := range c.Reads {
		out[r.ARN] = r
	}
	return out
}

// The forms are exactly 056's CHECK list and igagov's collected catalog, and
// the account-scoped ones are igagov's account-scoped ones.
func TestP3RPCFormsMatch056AndCatalog(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "master", "056_cloud_resource_policy.sql"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)resource_form\s+text NOT NULL CHECK \(resource_form IN \((.*?)\)\)`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("056 resource_form CHECK not found")
	}
	var check []string
	for _, m := range regexp.MustCompile(`'([a-z0-9_]+)'`).FindAllSubmatch(block[1], -1) {
		check = append(check, string(m[1]))
	}
	var catalog []string
	for _, f := range igagov.AllForms() {
		if f.State != igagov.FormCollected {
			continue
		}
		catalog = append(catalog, f.Name)
		if (f.Scope == igagov.ScopeAccount) != IsAccountScopedForm(f.Name) {
			t.Errorf("%s: igagov scope %s, collector account-scoped=%v", f.Name, f.Scope, IsAccountScopedForm(f.Name))
		}
	}
	got := CollectedForms()
	for _, l := range [][]string{check, catalog, got} {
		sort.Strings(l)
	}
	if strings.Join(got, ",") != strings.Join(check, ",") || strings.Join(got, ",") != strings.Join(catalog, ",") {
		t.Fatalf("forms disagree:\n collector %v\n 056 CHECK %v\n catalog   %v", got, check, catalog)
	}
	// The state vocabulary is 056's too.
	for _, s := range []string{CoverageComplete, CoveragePartial, CoverageDenied, CoverageNotCollected} {
		if !strings.Contains(string(raw), "'"+s+"'") {
			t.Errorf("state %q is not in 056", s)
		}
	}
}

// Every form, present and absent, paginated one item per page, in two
// selected regions, plus an enabled-but-unselected region.
func TestP3RPCCollectsEveryFormComplete(t *testing.T) {
	regions := map[string]*rpfake.Region{
		"us-east-1": homeRegion(), "eu-west-1": fullRegion("eu-west-1"),
		"us-west-2": {Name: "us-west-2", AccountID: rpAcct, PageSize: 1,
			MRAPs: []rpfake.MRAP{{Name: "global", Alias: "mfzwi23gnjvgw.mrap", Policy: rpPolicy}, {Name: "bare", Alias: "abc.mrap"}}},
	}
	cov := fastCollector().Collect(context.Background(), CollectInput{AccountID: rpAcct, Partition: "aws",
		SelectedRegions: []string{"us-east-1", "eu-west-1"}, EnabledRegions: []string{"us-east-1", "eu-west-1", "ap-south-1"},
		Clients: rpClients(regions)})
	got := byKey(cov)

	// Account forms once; regional forms in each selected region; the
	// unselected enabled region not_collected for every regional form.
	want := 2 + 11*2 + 11
	if len(cov) != want {
		t.Fatalf("coverage rows = %d, want %d: %v", len(cov), want, keys(got))
	}
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		for _, form := range CollectedForms() {
			if IsAccountScopedForm(form) {
				continue
			}
			c, ok := got[form+"/"+region]
			if !ok || c.State != CoverageComplete || c.ReadOK != c.Enumerated || c.ReadFailed != 0 || c.Enumerated == 0 {
				t.Errorf("%s/%s = %+v, want complete with every listed resource read", form, region, c)
			}
		}
		if c := got[FormS3ObjectLambdaAccessPoint+"/ap-south-1"]; c.State != CoverageNotCollected || c.Reason != ReasonRegionNotSelected {
			t.Errorf("unselected region = %+v", c)
		}
	}
	if c := got["s3_bucket/us-east-1"]; c.State != CoverageComplete || c.Enumerated != 2 {
		t.Fatalf("s3_bucket = %+v", c)
	} else if r := readsByARN(c); !r["arn:aws:s3:::exports"].Present || r["arn:aws:s3:::logs"].Present {
		t.Errorf("bucket reads = %+v (exports has a policy, logs has none)", r)
	}
	if c := got["s3_multi_region_access_point/us-west-2"]; c.State != CoverageComplete || c.Enumerated != 2 {
		t.Fatalf("mrap = %+v", c)
	} else if r := readsByARN(c); !r["arn:aws:s3::"+rpAcct+":accesspoint/mfzwi23gnjvgw.mrap"].Present {
		t.Errorf("mrap reads = %+v", r)
	}
	// $LATEST is not a published version; version 1 has no policy, 2 has one.
	if c := got["lambda_function_version/us-east-1"]; c.Enumerated != 2 {
		t.Errorf("versions = %+v", c)
	} else if r := readsByARN(c); r["arn:aws:lambda:us-east-1:"+rpAcct+":function:refund:1"].Present ||
		!r["arn:aws:lambda:us-east-1:"+rpAcct+":function:refund:2"].Present {
		t.Errorf("version reads = %+v", r)
	}
	// A39: the function has no policy, its alias does -- each its own form.
	fn := readsByARN(got["lambda_function/us-east-1"])
	al := readsByARN(got["lambda_alias/us-east-1"])
	if fn["arn:aws:lambda:us-east-1:"+rpAcct+":function:refund"].Present ||
		!al["arn:aws:lambda:us-east-1:"+rpAcct+":function:refund:live"].Present ||
		al["arn:aws:lambda:us-east-1:"+rpAcct+":function:refund:beta"].Present {
		t.Errorf("function %+v / aliases %+v", fn, al)
	}
	ap := readsByARN(got["s3_access_point/eu-west-1"])
	if !ap["arn:aws:s3:eu-west-1:"+rpAcct+":accesspoint/exports-ap"].Present {
		t.Errorf("access point reads = %+v", ap)
	}
	// Queue ARNs derive from the URL; the Policy attribute only.
	q := readsByARN(got["sqs_queue/eu-west-1"])
	if !q["arn:aws:sqs:eu-west-1:"+rpAcct+":refunds"].Present || q["arn:aws:sqs:eu-west-1:"+rpAcct+":plain"].Present {
		t.Errorf("queue reads = %+v", q)
	}
	if regions["us-east-1"].Calls["ListQueues"] != 2 {
		t.Errorf("ListQueues pages = %d, want 2 (one queue per page)", regions["us-east-1"].Calls["ListQueues"])
	}
	// SecretsPolicyAPI has no GetSecretValue: collection cannot call it (the
	// fake's GetSecretValue panics if anything ever did).
}

// Denied, throttled and failing reads, form by form.
func TestP3RPCDeniedThrottledAndFailedReads(t *testing.T) {
	type tc struct {
		name, form   string
		mutate       func(r *rpfake.Region)
		state        string
		reasonSubstr string
	}
	denied := rpfake.APIError("AccessDeniedException")
	cases := []tc{
		{"list denied", FormSQSQueue, func(r *rpfake.Region) { r.Errs = map[string]error{"ListQueues": rpfake.APIError("AccessDenied")} }, CoverageDenied, "sqs:ListQueues refused (AccessDenied)"},
		{"every read denied", FormKMSKey, func(r *rpfake.Region) { r.Errs = map[string]error{"GetKeyPolicy": denied} }, CoverageDenied, "every policy read refused"},
		{"one read denied", FormS3AccessPoint, func(r *rpfake.Region) {
			r.AccessPoints = append(r.AccessPoints, rpfake.Named{Name: "second"})
			r.Errs = map[string]error{"GetAccessPointPolicy:exports-ap": rpfake.APIError("AccessDenied")}
		}, CoveragePartial, "1 of 2 policies could not be read"},
		{"throttled then ok", FormSNSTopic, func(r *rpfake.Region) { r.Throttles = map[string]int{"GetTopicAttributes": 2, "ListTopics": 1} }, CoverageComplete, ""},
		{"throttled past retries", FormSecretsManagerSecret, func(r *rpfake.Region) { r.Throttles = map[string]int{"GetResourcePolicy": 5} }, CoveragePartial, "ThrottlingException"},
		{"list throttled past retries", FormLambdaLayerVersion, func(r *rpfake.Region) { r.Throttles = map[string]int{"ListLayers": 9} }, CoveragePartial, "lambda:ListLayers failed (ThrottlingException)"},
		{"child listing denied", FormLambdaAlias, func(r *rpfake.Region) { r.Errs = map[string]error{"ListAliases": denied} }, CoverageDenied, "lambda:ListAliases AccessDeniedException"},
		{"service not offered", FormS3DirectoryBucket, func(r *rpfake.Region) {
			r.Errs = map[string]error{"ListDirectoryBuckets": &net.DNSError{Err: "no such host", Name: "s3express-control.eu-west-1.amazonaws.com", IsNotFound: true}}
		}, CoverageComplete, "service not offered"},
		{"other error", FormS3ObjectLambdaAccessPoint, func(r *rpfake.Region) {
			r.Errs = map[string]error{"GetAccessPointPolicyForObjectLambda": rpfake.APIError("InternalError")}
		}, CoveragePartial, "InternalError"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fullRegion("eu-west-1")
			c.mutate(r)
			cov := byKey(fastCollector().Collect(context.Background(), CollectInput{AccountID: rpAcct,
				SelectedRegions: []string{"eu-west-1"}, Clients: rpClients(map[string]*rpfake.Region{"eu-west-1": r})}))
			got := cov[c.form+"/eu-west-1"]
			if got.State != c.state || !strings.Contains(got.Reason, c.reasonSubstr) {
				t.Fatalf("%s = %s %q, want %s containing %q", c.form, got.State, got.Reason, c.state, c.reasonSubstr)
			}
			if got.State == CoverageComplete && (got.ReadFailed != 0 || got.ReadOK != got.Enumerated) {
				t.Fatalf("complete with %d/%d/%d", got.Enumerated, got.ReadOK, got.ReadFailed)
			}
			if got.State != CoverageComplete && got.Reason == "" {
				t.Fatal("a non-complete row must say why")
			}
			// One form's trouble is never another's: KMS stays complete unless
			// it is the form under test.
			if c.form != FormKMSKey && cov[FormKMSKey+"/eu-west-1"].State != CoverageComplete {
				t.Errorf("kms_key affected: %+v", cov[FormKMSKey+"/eu-west-1"])
			}
		})
	}
}

// A refused ListFunctions leaves all three function forms unenumerated, and
// each says so; layers and the rest are unaffected.
func TestP3RPCListFunctionsDeniedDeniesThreeForms(t *testing.T) {
	r := fullRegion("eu-west-1")
	r.Errs = map[string]error{"ListFunctions": rpfake.APIError("AccessDeniedException")}
	cov := byKey(fastCollector().Collect(context.Background(), CollectInput{AccountID: rpAcct,
		SelectedRegions: []string{"eu-west-1"}, Clients: rpClients(map[string]*rpfake.Region{"eu-west-1": r})}))
	for _, f := range []string{FormLambdaFunction, FormLambdaFunctionVersion, FormLambdaAlias} {
		if c := cov[f+"/eu-west-1"]; c.State != CoverageDenied || !strings.Contains(c.Reason, "lambda:ListFunctions") {
			t.Errorf("%s = %+v", f, c)
		}
	}
	if c := cov[FormLambdaLayerVersion+"/eu-west-1"]; c.State != CoverageComplete {
		t.Errorf("layers = %+v", c)
	}
}

// A46 at the collector: SQS unreadable in one region only.
func TestP3RPCCoverageLostInOneRegion(t *testing.T) {
	east, west := homeRegion(), fullRegion("eu-west-1")
	west.Errs = map[string]error{"GetQueueAttributes": rpfake.APIError("AccessDenied")}
	cov := byKey(fastCollector().Collect(context.Background(), CollectInput{AccountID: rpAcct,
		SelectedRegions: []string{"us-east-1", "eu-west-1"},
		Clients:         rpClients(map[string]*rpfake.Region{"us-east-1": east, "eu-west-1": west})}))
	if c := cov["sqs_queue/us-east-1"]; c.State != CoverageComplete {
		t.Errorf("east = %+v", c)
	}
	if c := cov["sqs_queue/eu-west-1"]; c.State != CoverageDenied || c.ReadFailed != 2 || c.Enumerated != 2 {
		t.Errorf("west = %+v", c)
	}
}

// The budget: a deadline that passes mid-form leaves it partial.
func TestP3RPCBudgetLeavesFormPartial(t *testing.T) {
	r := fullRegion("eu-west-1")
	for i := 0; i < 5; i++ {
		r.Secrets = append(r.Secrets, rpfake.ARNPolicy{ARN: "arn:aws:secretsmanager:eu-west-1:" + rpAcct + ":secret:s" + string(rune('a'+i))})
	}
	clock := time.Unix(1000, 0)
	calls := 0
	c := NewResourcePolicyCollector(CollectorOptions{MinCallInterval: -1, Deadline: time.Unix(1000, 0).Add(time.Minute),
		Now: func() time.Time {
			calls++
			if r.Calls["GetResourcePolicy"] >= 3 {
				return clock.Add(time.Hour)
			}
			return clock
		}, Sleep: func(context.Context, time.Duration) error { return nil }})
	cov := byKey(c.Collect(context.Background(), CollectInput{AccountID: rpAcct, SelectedRegions: []string{"eu-west-1"},
		Clients: rpClients(map[string]*rpfake.Region{"eu-west-1": r})}))
	got := cov[FormSecretsManagerSecret+"/eu-west-1"]
	if got.State != CoveragePartial || got.ReadOK != 3 || got.Enumerated != 6 || !strings.Contains(got.Reason, "budget") {
		t.Fatalf("secrets = %+v", got)
	}
}

// A listing that repeats its page token is partial, never a loop.
func TestP3RPCRepeatedTokenIsPartial(t *testing.T) {
	c := fastCollector()
	a := newAcc(FormKMSKey, "eu-west-1", "kms:ListKeys")
	n := 0
	c.pages(context.Background(), a, "kms", "eu-west-1", func(_ context.Context, _ *string) (*string, error) {
		n++
		tok := "same"
		return &tok, nil
	})
	if n != 2 || a.finish().State != CoveragePartial {
		t.Fatalf("pages=%d state=%+v", n, a.finish())
	}
}

func TestP3RPCNotCollectedAllAndPartition(t *testing.T) {
	cov := NotCollectedAll("aws", []string{"eu-west-1", "us-east-1"}, "discovery template update needed")
	if len(cov) != 2+11*2 {
		t.Fatalf("rows = %d", len(cov))
	}
	for _, c := range cov {
		if c.State != CoverageNotCollected || c.Reason == "" || c.Enumerated != 0 {
			t.Fatalf("%+v", c)
		}
	}
	if AccountFormRegion(FormS3Bucket, "aws-us-gov") != "us-gov-west-1" || AccountFormRegion(FormS3MultiRegionAccessPoint, "aws") != "us-west-2" ||
		PartitionOf("arn:aws-cn:iam::1:role/x") != "aws-cn" {
		t.Fatal("account regions / partition")
	}
	if QueueARNFromURL("https://sqs.eu-west-1.amazonaws.com/429418377036/q", "eu-west-1", "aws") != "arn:aws:sqs:eu-west-1:429418377036:q" ||
		QueueARNFromURL("https://example.com/q", "eu-west-1", "aws") != "" {
		t.Fatal("queue ARN")
	}
}

// The discovery template grants exactly the collection and migration
// actions, in their own statements, under the bumped version; older
// versions are recognised as not granting collection.
func TestP3RPCTemplateGrantsCollectionActions(t *testing.T) {
	tpl := strings.ReplaceAll(CloudFormationTemplate, "\r\n", "\n")
	statement := func(sid string) []string {
		m := regexp.MustCompile(`(?s)- Sid: ` + sid + `\n\s+Effect: Allow\n\s+Action:\n(.*?)\n\s+Resource:`).FindStringSubmatch(tpl)
		if m == nil {
			t.Fatalf("statement %s not found", sid)
		}
		var out []string
		for _, line := range strings.Split(m[1], "\n") {
			if a := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")); a != "" {
				out = append(out, a)
			}
		}
		sort.Strings(out)
		return out
	}
	wantRP := append([]string{"s3:GetBucketPolicy", "kms:GetKeyPolicy"}, ResourcePolicyCollectionActions()...)
	sort.Strings(wantRP)
	if got := statement("ResourcePolicies"); strings.Join(got, ",") != strings.Join(wantRP, ",") {
		t.Errorf("ResourcePolicies grants\n %v\nwant\n %v", got, wantRP)
	}
	wantME := MigrationEvidenceActions()
	sort.Strings(wantME)
	if got := statement("MigrationEvidence"); strings.Join(got, ",") != strings.Join(wantME, ",") {
		t.Errorf("MigrationEvidence grants\n %v\nwant\n %v", got, wantME)
	}
	// lambda:ListFunctions stays in WorkloadReads; nothing new is hard-denied,
	// and the secret-value deny is still there.
	if !regexp.MustCompile(`(?m)^\s+- lambda:ListFunctions\s*$`).MatchString(tpl) {
		t.Error("lambda:ListFunctions is not granted")
	}
	deny := map[string]bool{}
	for _, p := range HardDenies() {
		for _, a := range p.Actions {
			deny[a] = true
		}
	}
	for _, a := range append(ResourcePolicyCollectionActions(), MigrationEvidenceActions()...) {
		if deny[a] {
			t.Errorf("%s is hard-denied", a)
		}
	}
	if !deny["secretsmanager:GetSecretValue"] {
		t.Error("GetSecretValue is no longer denied")
	}
	if TemplateVersion != ResourcePolicyTemplateVersion || PermissionsVersion != ResourcePolicyTemplateVersion {
		t.Errorf("versions: template %s, permissions %s, collection %s", TemplateVersion, PermissionsVersion, ResourcePolicyTemplateVersion)
	}
	for v, want := range map[string]bool{"": false, "2026-09-24": false, "2026-09-23": false, TemplateVersion: true, "2027-01-01": true} {
		if GrantsResourcePolicyCollection(v) != want {
			t.Errorf("GrantsResourcePolicyCollection(%q) = %v", v, !want)
		}
	}
	if o := TemplateOutdated("2026-09-24"); o == nil || !*o {
		t.Error("a 2026-09-24 stack must read outdated: it lacks the collection permissions")
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
