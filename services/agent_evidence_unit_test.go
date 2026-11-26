package services

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/models"
)

// Unit tests of the evidence store and coverage that need no database.

func TestEvidenceRowOf_PrincipalClassAndRedaction(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	e := agentruntime.Event{EventID: "ev1", EventTime: now.Add(-90 * time.Second), EventSource: "secretsmanager.amazonaws.com",
		EventName: "GetSecretValue", EventType: "AwsApiCall", PrincipalType: "AssumedRole",
		PrincipalARN: "arn:aws:sts::111111111111:assumed-role/app/s", SessionIssuerARN: "arn:aws:iam::111111111111:role/app",
		ErrorCode: "AccessDenied", ErrorMessage: "User x is not authorized to read secret hunter2", AuthorizationDenied: true}
	r, ok := evidenceRowOf(e, now)
	if !ok {
		t.Fatal("row refused")
	}
	if r.Principal != "arn:aws:iam::111111111111:role/app" || r.PrincipalDetail != e.PrincipalARN {
		t.Errorf("principal %q detail %q", r.Principal, r.PrincipalDetail)
	}
	if r.SkewMS != 90000 || r.Outcome != "denied" || r.RecordClass != EvidenceClassElevated || r.Provider != "aws" || len(r.RawHash) != 64 {
		t.Errorf("row %+v", r)
	}
	if strings.Contains(r.Body, "hunter2") || strings.Contains(r.Body, "not authorized") {
		t.Error("the error message must never be stored")
	}
	plain := agentruntime.Event{EventID: "ev2", EventSource: "ec2.amazonaws.com", EventName: "DescribeInstances",
		PrincipalType: "IAMUser", PrincipalARN: "arn:aws:iam::111111111111:user/bob"}
	r, _ = evidenceRowOf(plain, now)
	if r.RecordClass != EvidenceClassDefault || r.Principal != plain.PrincipalARN || !r.EventTime.Equal(now) {
		t.Errorf("plain row %+v", r)
	}
	if _, ok := evidenceRowOf(agentruntime.Event{}, now); ok {
		t.Error("an event without id must not be stored")
	}
	az := agentruntime.Event{Provider: agentruntime.ProviderAzure, EventID: "a", PrincipalID: "oid", PrincipalARN: "upn@x"}
	if r, _ := evidenceRowOf(az, now); r.Principal != "oid" || r.Provider != "azure" {
		t.Errorf("azure principal %q", r.Principal)
	}
}

func TestHeartbeatSilenceUsesStreamRule(t *testing.T) {
	created := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	secs := int64(3600)
	h := SourceHeartbeat{CreatedAt: created, SilentAfterSeconds: &secs}
	if s, _ := heartbeatSilence(h, created.Add(30*time.Minute)); s {
		t.Error("within the threshold: not silent")
	}
	if s, since := heartbeatSilence(h, created.Add(2*time.Hour)); !s || !since.Equal(created) {
		t.Errorf("never delivered: silent since creation, got %v %v", s, since)
	}
	last := created.Add(3 * time.Hour)
	h.LastReceivedAt = &last
	if s, _ := heartbeatSilence(h, last.Add(10*time.Minute)); s {
		t.Error("delivered recently: not silent")
	}
	h.SilentAfterSeconds = nil
	if s, _ := heartbeatSilence(h, last.Add(100*time.Hour)); s {
		t.Error("no threshold: never silent")
	}
}

func capsByID(rs []CapabilityResult) map[string]CapabilityResult {
	m := map[string]CapabilityResult{}
	for _, r := range rs {
		m[r.Capability] = r
	}
	return m
}

func TestComputeScopeCapabilities(t *testing.T) {
	aws := coverageScope{Scope: "111111111111", Kind: "account", Provider: models.CloudProviderAWS,
		StreamActive: true, PolledTrail: true, EnforcementState: "verified", BrokerRoles: 2}
	got := capsByID(computeScopeCapabilities(aws, coverageWorkspace{Gateways: 1, Slack: true}))
	if len(got) != 13 {
		t.Fatalf("want C1..C13, got %d", len(got))
	}
	want := map[string]string{"C1": CapabilityOn, "C2": CapabilityOff, "C3": CapabilityOff, "C4": CapabilityOff,
		"C5": CapabilityOff, "C6": CapabilityOn, "C7": CapabilityPartial, "C8": CapabilityPartial, "C9": CapabilityOff,
		"C10": CapabilityOff, "C11": CapabilityOff, "C12": CapabilityPartial, "C13": CapabilityPartial}
	for c, s := range want {
		if got[c].State != s {
			t.Errorf("%s: %s (%s), want %s", c, got[c].State, got[c].Detail, s)
		}
	}
	for _, c := range []string{"C4", "C9", "C11"} {
		if !strings.Contains(got[c].Detail, capNotImplemented) {
			t.Errorf("%s must say not implemented: %q", c, got[c].Detail)
		}
	}
	aws.StreamSilent = true
	if c1 := capsByID(computeScopeCapabilities(aws, coverageWorkspace{}))["C1"]; c1.State != CapabilityPartial || c1.Fallback == "" {
		t.Errorf("silent stream: %+v", c1)
	}
	aws.StreamActive, aws.PolledTrail = false, false
	if c1 := capsByID(computeScopeCapabilities(aws, coverageWorkspace{}))["C1"]; c1.State != CapabilityOff {
		t.Errorf("nothing read: %+v", c1)
	}
	k8s := capsByID(computeScopeCapabilities(coverageScope{Provider: models.ProviderK8s, Kind: "cluster"}, coverageWorkspace{}))
	if k8s["C1"].State != CapabilityOff {
		t.Errorf("cluster without audit: %+v", k8s["C1"])
	}
	k8s = capsByID(computeScopeCapabilities(coverageScope{Provider: models.ProviderK8s, AuditSeen: true}, coverageWorkspace{}))
	if k8s["C1"].State != CapabilityOn {
		t.Errorf("cluster with audit: %+v", k8s["C1"])
	}
}

/* --------------------------------- fake S3 --------------------------------- */

type fakeTrailBucket struct {
	objects map[string][]byte
	gets    int
}

func (f *fakeTrailBucket) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := aws.ToString(in.Prefix)
	out := &s3.ListObjectsV2Output{}
	seen := map[string]bool{}
	var keys []string
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if in.Delimiter != nil {
			rest := strings.TrimPrefix(k, prefix)
			if i := strings.Index(rest, aws.ToString(in.Delimiter)); i >= 0 {
				cp := prefix + rest[:i+1]
				if !seen[cp] {
					seen[cp] = true
					out.CommonPrefixes = append(out.CommonPrefixes, s3types.CommonPrefix{Prefix: aws.String(cp)})
				}
				continue
			}
		}
		out.Contents = append(out.Contents, s3types.Object{Key: aws.String(k)})
	}
	return out, nil
}

func (f *fakeTrailBucket) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.gets++
	b, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, fmt.Errorf("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func trailRecord(id, account, at string) map[string]any {
	return map[string]any{"eventID": id, "eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com",
		"eventTime": at, "recipientAccountId": account, "awsRegion": "us-east-1",
		"userIdentity": map[string]any{"type": "IAMUser", "arn": "arn:aws:iam::" + account + ":user/u" + id}}
}

func gzTrailFile(t *testing.T, recs ...map[string]any) []byte {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"Records": recs})
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

// FakeTrailBucket builds a bucket of two regions and days (exported to the
// package's tests only).
func newFakeTrailBucket(t *testing.T, account string) *fakeTrailBucket {
	base := "logs/AWSLogs/" + account + "/CloudTrail/"
	return &fakeTrailBucket{objects: map[string][]byte{
		base + "us-east-1/2026/11/20/" + account + "_CloudTrail_us-east-1_20261120T1005Z_a.json.gz": gzTrailFile(t,
			trailRecord("b1", account, "2026-11-20T10:00:00Z"), trailRecord("b2", account, "2026-11-20T10:01:00Z"),
			trailRecord("other", "999999999999", "2026-11-20T10:02:00Z")),
		base + "eu-west-1/2026/11/21/" + account + "_CloudTrail_eu-west-1_20261121T0005Z_b.json.gz": gzTrailFile(t,
			trailRecord("b3", account, "2026-11-21T00:01:00Z")),
		// Outside the window: not read.
		base + "us-east-1/2026/11/23/" + account + "_CloudTrail_us-east-1_20261123T0005Z_c.json.gz": gzTrailFile(t,
			trailRecord("late", account, "2026-11-23T00:01:00Z")),
	}}
}

func TestReadTrailWindowFakeS3(t *testing.T) {
	const account = "111111111111"
	api := newFakeTrailBucket(t, account)
	loc := TrailLocation{Bucket: "b", Prefix: "logs", AccountID: account}
	var got []string
	from := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	st, err := ReadTrailWindow(context.Background(), api, loc, nil, from, from.Add(48*time.Hour), 0, func(es []agentruntime.Event) error {
		for _, e := range es {
			got = append(got, e.EventID)
			if e.RawHash == "" || e.AccountID != account {
				t.Errorf("event %+v", e)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "b1,b2,b3" || st.Objects != 2 || st.Events != 3 || st.Partial {
		t.Fatalf("got %v stats %+v (another account's record and the late file must be left out)", got, st)
	}
	// The object cap makes the read partial.
	st, err = ReadTrailWindow(context.Background(), api, loc, nil, from, from.Add(48*time.Hour), 1, func([]agentruntime.Event) error { return nil })
	if err != nil || !st.Partial || st.Objects != 1 {
		t.Fatalf("capped: %+v %v", st, err)
	}
}

func TestTrailFileStamp(t *testing.T) {
	ts, ok := trailFileStamp("x/111111111111_CloudTrail_us-east-1_20261120T1005Z_abc.json.gz")
	if !ok || !ts.Equal(time.Date(2026, 11, 20, 10, 5, 0, 0, time.UTC)) {
		t.Fatalf("%v %v", ts, ok)
	}
	if _, ok := trailFileStamp("x/digest.json.gz"); ok {
		t.Fatal("no stamp expected")
	}
}

func TestAzureEventSecretShape(t *testing.T) {
	s, err := GenerateAzureEventSecret()
	if err != nil || !wellFormedAzureEventSecret(s) || !strings.HasPrefix(s, AzureEventSecretPrefix) {
		t.Fatalf("%v %v", err, wellFormedAzureEventSecret(s))
	}
	for _, bad := range []string{"", "aev_" + s[5:], s + "x", s[:len(s)-1] + "!"} {
		if wellFormedAzureEventSecret(bad) {
			t.Errorf("%q must not be well formed", bad)
		}
	}
	_ = uuid.Nil
}
