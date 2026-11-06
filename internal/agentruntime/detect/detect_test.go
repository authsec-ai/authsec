package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// established is a baseline past its learning period.
func established() *Baseline { return NewBaseline(t0.Add(-72 * time.Hour)) }

func ev(source, name string) agentruntime.Event {
	return agentruntime.Event{EventID: source + name, EventTime: t0, EventSource: source, EventName: name,
		EventType: "AwsApiCall", SourceIP: "203.0.113.10", Region: "us-east-1"}
}

func only(t *testing.T, fs []Finding, id ID) Finding {
	t.Helper()
	var hit []Finding
	for _, f := range fs {
		if f.Detection == id {
			hit = append(hit, f)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("want exactly one %s finding, got %v", id, fs)
	}
	return hit[0]
}

func none(t *testing.T, fs []Finding, id ID) {
	t.Helper()
	for _, f := range fs {
		if f.Detection == id {
			t.Fatalf("unexpected %s finding: %v", id, f)
		}
	}
}

func TestD1SecretReads(t *testing.T) {
	cfg := DefaultConfig()
	cases := []struct {
		name string
		e    agentruntime.Event
		sev  string // "" = no finding
	}{
		{"GetSecretValue", ev("secretsmanager.amazonaws.com", "GetSecretValue"), SeverityHigh},
		{"BatchGetSecretValue", ev("secretsmanager.amazonaws.com", "BatchGetSecretValue"), SeverityHigh},
		{"ListSecrets is not a read of a value", ev("secretsmanager.amazonaws.com", "ListSecrets"), ""},
		{"GetParameter with decryption", ssm("GetParameter", "true"), SeverityMedium},
		{"GetParameters with decryption", ssm("GetParameters", "true"), SeverityMedium},
		{"GetParametersByPath with decryption", ssm("GetParametersByPath", "true"), SeverityMedium},
		{"GetParameter without decryption", ssm("GetParameter", "false"), ""},
		{"GetParameter, decryption not stated", ev("ssm.amazonaws.com", "GetParameter"), ""},
		{"GetParametersByPath, decryption not stated", ev("ssm.amazonaws.com", "GetParametersByPath"), ""},
		{"kms Decrypt of a secret by the caller", withFacts(ev("kms.amazonaws.com", "Decrypt"), agentruntime.FactSecretContext, "true"), SeverityMedium},
		{"kms Decrypt, no secret context", ev("kms.amazonaws.com", "Decrypt"), ""},
	}
	for _, c := range cases {
		fs := Evaluate(cfg, established(), c.e, t0)
		if c.sev == "" {
			none(t, fs, D1)
			continue
		}
		if f := only(t, fs, D1); f.Severity != c.sev {
			t.Errorf("%s: severity %s, want %s", c.name, f.Severity, c.sev)
		}
	}
}

// §10: kms:Decrypt made by Secrets Manager or SSM on the principal's behalf
// duplicates the GetSecretValue / GetParameter alert and is dropped.
func TestD1KMSDecryptViaSecretsManagerOrSSMDropped(t *testing.T) {
	for _, by := range []string{"secretsmanager.amazonaws.com", "ssm.amazonaws.com", "SecretsManager.amazonaws.com"} {
		e := ev("kms.amazonaws.com", "Decrypt")
		e.InvokedBy = by
		none(t, Evaluate(DefaultConfig(), established(), e, t0), D1)
	}
	// Any service-made decrypt is dropped; only direct calls count.
	e := withFacts(ev("kms.amazonaws.com", "Decrypt"), agentruntime.FactSecretContext, "true")
	e.InvokedBy = "lambda.amazonaws.com"
	none(t, Evaluate(DefaultConfig(), established(), e, t0), D1)
}

func withFacts(e agentruntime.Event, k, v string) agentruntime.Event {
	e.RequestFacts = map[string]string{k: v}
	return e
}

func ssm(name, withDecryption string) agentruntime.Event {
	e := ev("ssm.amazonaws.com", name)
	e.RequestFacts = map[string]string{FactWithDecryption: withDecryption}
	return e
}

// Only a decrypting ssm read is a secret read; unstated is not (lab
// 2026-11-05: 217 plain GetParameter calls made one alert).
func TestD1SSMOnlyWithDecryption(t *testing.T) {
	none(t, Evaluate(DefaultConfig(), established(), ssm("GetParameter", "false"), t0), D1)
	none(t, Evaluate(DefaultConfig(), established(), ev("ssm.amazonaws.com", "GetParameter"), t0), D1)
	none(t, Evaluate(DefaultConfig(), established(), ssm("GetParameter", ""), t0), D1)
	if f := only(t, Evaluate(DefaultConfig(), established(), ssm("GetParameter", "true"), t0), D1); f.Severity != SeverityMedium {
		t.Fatalf("severity %s", f.Severity)
	}
	only(t, Evaluate(DefaultConfig(), established(), ssm("GetParameters", "TRUE"), t0), D1)
	// Other ssm calls never count, decrypting or not.
	none(t, Evaluate(DefaultConfig(), established(), ssm("DescribeParameters", "true"), t0), D1)
}

// A parsed record carries the fact through to D1.
func TestD1SSMParsedRecord(t *testing.T) {
	rec := func(with string) agentruntime.Event {
		raw := `{"eventID":"p-` + with + `","eventTime":"2026-11-05T12:00:00Z","eventSource":"ssm.amazonaws.com",
		 "eventName":"GetParameter","eventType":"AwsApiCall","requestParameters":{"name":"/app/db","withDecryption":` + with + `}}`
		e, err := agentruntime.ParseCloudTrailRecord([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	only(t, Evaluate(DefaultConfig(), established(), rec("true"), t0), D1)
	none(t, Evaluate(DefaultConfig(), established(), rec("false"), t0), D1)
}

func TestD2D3D4(t *testing.T) {
	cfg := DefaultConfig()
	for _, c := range []struct {
		src, name string
		id        ID
		sev       string
	}{
		{"iam.amazonaws.com", "CreateAccessKey", D2, SeverityHigh},
		{"iam.amazonaws.com", "CreateLoginProfile", D2, SeverityHigh},
		{"iam.amazonaws.com", "UpdateLoginProfile", D2, SeverityHigh},
		{"sts.amazonaws.com", "GetFederationToken", D2, SeverityHigh},
		{"iam.amazonaws.com", "AttachRolePolicy", D3, SeverityHigh},
		{"iam.amazonaws.com", "PutUserPolicy", D3, SeverityHigh},
		{"iam.amazonaws.com", "UpdateAssumeRolePolicy", D3, SeverityHigh},
		{"iam.amazonaws.com", "CreateRole", D3, SeverityHigh},
		{"iam.amazonaws.com", "SetDefaultPolicyVersion", D3, SeverityHigh},
		{"iam.amazonaws.com", "AddRoleToInstanceProfile", D3, SeverityHigh},
		{"cloudtrail.amazonaws.com", "StopLogging", D4, SeverityHigh},
		{"cloudtrail.amazonaws.com", "PutAdvancedEventSelectors", D4, SeverityHigh},
		{"bedrock.amazonaws.com", "DeleteModelInvocationLoggingConfiguration", D4, SeverityHigh},
		{"logs.amazonaws.com", "DeleteLogGroup", D4, SeverityMedium},
	} {
		f := only(t, Evaluate(cfg, established(), ev(c.src, c.name), t0), c.id)
		if f.Severity != c.sev {
			t.Errorf("%s %s: severity %s, want %s", c.src, c.name, f.Severity, c.sev)
		}
		if !strings.Contains(f.Detail, c.name) {
			t.Errorf("%s: detail %q does not name the call", c.name, f.Detail)
		}
	}
	none(t, Evaluate(cfg, established(), ev("iam.amazonaws.com", "ListRoles"), t0), D3)
}

// D1-D4 and D6-D8 only on successful calls.
func TestFailedCallsRaiseNothingButD5(t *testing.T) {
	for _, e := range []agentruntime.Event{ev("secretsmanager.amazonaws.com", "GetSecretValue"),
		ev("iam.amazonaws.com", "CreateAccessKey"), ev("iam.amazonaws.com", "AttachRolePolicy"),
		ev("cloudtrail.amazonaws.com", "StopLogging")} {
		e.ErrorCode = "ResourceNotFoundException"
		if fs := Evaluate(DefaultConfig(), established(), e, t0); len(fs) != 0 {
			t.Errorf("%s failed: %v", e.EventName, fs)
		}
	}
	// A streaming completion record is not a call.
	e := ev("secretsmanager.amazonaws.com", "GetSecretValue")
	e.EventType = "AwsServiceEvent"
	none(t, Evaluate(DefaultConfig(), established(), e, t0), D1)
}

func TestDisabledDetectionRaisesNothing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Disabled[D1] = true
	none(t, Evaluate(cfg, established(), ev("secretsmanager.amazonaws.com", "GetSecretValue"), t0), D1)
}

func denial(at time.Time) agentruntime.Event {
	e := ev("s3.amazonaws.com", "GetObject")
	e.EventTime, e.ErrorCode, e.AuthorizationDenied = at, "AccessDenied", true
	return e
}

func TestD5Threshold(t *testing.T) {
	cfg := DefaultConfig()
	b := established()
	fired := 0
	for i := 0; i < 9; i++ {
		fired += len(Evaluate(cfg, b, denial(t0.Add(time.Duration(i)*20*time.Second)), t0))
	}
	if fired != 0 {
		t.Fatalf("9 denials raised %d findings", fired)
	}
	f := only(t, Evaluate(cfg, b, denial(t0.Add(3*time.Minute)), t0), D5)
	if !strings.Contains(f.Detail, "10 authorization denials") {
		t.Errorf("detail %q", f.Detail)
	}
	// The 11th in the same window does not fire again (crossing only).
	none(t, Evaluate(cfg, b, denial(t0.Add(3*time.Minute+time.Second)), t0), D5)
}

func TestD5WindowSlides(t *testing.T) {
	cfg := DefaultConfig()
	b := established()
	// 10 denials spread over 20 minutes never make 10 within 5.
	for i := 0; i < 10; i++ {
		none(t, Evaluate(cfg, b, denial(t0.Add(time.Duration(i)*2*time.Minute)), t0), D5)
	}
	// Custom threshold: 3 in 2 minutes.
	cfg.DenialBurst, cfg.DenialWindow = 3, 2*time.Minute
	b = established()
	Evaluate(cfg, b, denial(t0), t0)
	Evaluate(cfg, b, denial(t0.Add(30*time.Second)), t0)
	only(t, Evaluate(cfg, b, denial(t0.Add(70*time.Second)), t0), D5)
}

func TestD5PersistedBucketsCount(t *testing.T) {
	b := established()
	b.LoadBucket(KindDenied, MinuteKey(t0), 9)
	only(t, Evaluate(DefaultConfig(), b, denial(t0.Add(10*time.Second)), t0), D5)
}

func modelCall(model string, at time.Time) agentruntime.Event {
	e := ev(agentruntime.SourceBedrock, "Converse")
	e.EventTime = at
	e.RequestFacts = map[string]string{agentruntime.FactModelID: model}
	return e
}

func TestD6NewModel(t *testing.T) {
	b := established()
	b.Know(KindModel, "anthropic.claude-old")
	b.Know(KindIP, "203.0.113.10")
	b.Know(KindRegion, "us-east-1")
	none(t, Evaluate(DefaultConfig(), b, modelCall("anthropic.claude-old", t0), t0), D6)
	f := only(t, Evaluate(DefaultConfig(), b, modelCall("anthropic.claude-new", t0), t0), D6)
	if !strings.Contains(f.Detail, "anthropic.claude-new") {
		t.Errorf("detail %q", f.Detail)
	}
	// Learned: the second call is not new.
	none(t, Evaluate(DefaultConfig(), b, modelCall("anthropic.claude-new", t0.Add(time.Minute)), t0), D6)
	// Failed calls neither alert nor learn.
	e := modelCall("anthropic.claude-third", t0)
	e.ErrorCode = "ThrottlingException"
	none(t, Evaluate(DefaultConfig(), b, e, t0), D6)
	if b.Seen(KindModel, "anthropic.claude-third") {
		t.Error("a failed call taught the baseline a model")
	}
}

func TestD6Spike(t *testing.T) {
	cfg := DefaultConfig()
	b := established()
	b.Know(KindModel, "m")
	b.Know(KindIP, "203.0.113.10")
	b.Know(KindRegion, "us-east-1")
	// 7 days at 4 calls an hour: mean 4, threshold 20.
	for h := 1; h <= BaselineHours; h++ {
		b.LoadBucket(KindHourly, HourKey(t0.Add(-time.Duration(h)*time.Hour)), 4)
	}
	fired := 0
	for i := 0; i < 25; i++ {
		fs := Evaluate(cfg, b, modelCall("m", t0.Add(time.Duration(i)*time.Minute)), t0)
		for _, f := range fs {
			if f.Detection == D6 {
				fired++
				if i != 20 {
					t.Errorf("spike fired at call %d, want the 21st", i+1)
				}
			}
		}
	}
	if fired != 1 {
		t.Errorf("spike fired %d times, want once", fired)
	}
}

func TestD6SpikeNeedsABaseline(t *testing.T) {
	b := established()
	b.Know(KindModel, "m")
	b.Know(KindIP, "203.0.113.10")
	b.Know(KindRegion, "us-east-1")
	// Only 3 hours of history: no baseline, no spike however many calls.
	for h := 1; h <= 3; h++ {
		b.LoadBucket(KindHourly, HourKey(t0.Add(-time.Duration(h)*time.Hour)), 1)
	}
	for i := 0; i < 100; i++ {
		none(t, Evaluate(DefaultConfig(), b, modelCall("m", t0.Add(time.Duration(i)*time.Second)), t0), D6)
	}
}

func TestD7NewRole(t *testing.T) {
	b := established()
	b.Know(KindRole, "arn:aws:iam::111111111111:role/known")
	e := ev("sts.amazonaws.com", "AssumeRole")
	e.RequestFacts = map[string]string{agentruntime.FactRoleARN: "arn:aws:iam::111111111111:role/known"}
	none(t, Evaluate(DefaultConfig(), b, e, t0), D7)
	e.RequestFacts[agentruntime.FactRoleARN] = "arn:aws:iam::222222222222:role/admin"
	f := only(t, Evaluate(DefaultConfig(), b, e, t0), D7)
	if !strings.Contains(f.Detail, "222222222222") {
		t.Errorf("detail %q", f.Detail)
	}
	none(t, Evaluate(DefaultConfig(), b, e, t0), D7)
}

func TestD8NewPlace(t *testing.T) {
	b := established()
	b.Know(KindModel, "m")
	b.Know(KindIP, "203.0.113.10")
	b.Know(KindRegion, "us-east-1")
	none(t, Evaluate(DefaultConfig(), b, modelCall("m", t0), t0), D8)

	e := modelCall("m", t0)
	e.SourceIP = "198.51.100.7"
	f := only(t, Evaluate(DefaultConfig(), b, e, t0), D8)
	if !strings.Contains(f.Detail, "198.51.100.7") || strings.Contains(f.Detail, "region") {
		t.Errorf("detail %q", f.Detail)
	}
	e.SourceIP, e.Region = "203.0.113.10", "eu-west-1"
	f = only(t, Evaluate(DefaultConfig(), b, e, t0), D8)
	if !strings.Contains(f.Detail, "eu-west-1") {
		t.Errorf("detail %q", f.Detail)
	}
}

func TestD8SkipsAWSServiceSources(t *testing.T) {
	b := established()
	b.Know(KindModel, "m")
	b.Know(KindRegion, "us-east-1")
	for _, ip := range []string{"lambda.amazonaws.com", "AWS Internal", "bedrock.amazonaws.com"} {
		e := modelCall("m", t0)
		e.SourceIP = ip
		none(t, Evaluate(DefaultConfig(), b, e, t0), D8)
		if b.Seen(KindIP, ip) {
			t.Errorf("%s learned as a source IP", ip)
		}
	}
	e := modelCall("m", t0)
	e.SourceIP, e.InvokedBy = "198.51.100.99", "bedrock.amazonaws.com"
	none(t, Evaluate(DefaultConfig(), b, e, t0), D8)
}

// The first day of a new identity learns D6-D8 silently; then novelty alerts.
func TestNeverSeenLearnsSilentlyOnTheFirstDay(t *testing.T) {
	observed := t0
	b := NewBaseline(observed)
	// A 90-day backfill on the first scan: many models, IPs, regions, roles.
	for i := 0; i < 50; i++ {
		e := modelCall("model-"+string(rune('a'+i%26)), t0.Add(-time.Duration(i)*time.Hour))
		e.SourceIP = "198.51.100." + string(rune('0'+i%10))
		e.Region = []string{"us-east-1", "us-west-2", "eu-west-1"}[i%3]
		for _, f := range Evaluate(DefaultConfig(), b, e, observed.Add(time.Hour)) {
			if f.Detection == D6 || f.Detection == D8 {
				t.Fatalf("learning period raised %v", f)
			}
		}
		r := ev("sts.amazonaws.com", "AssumeRole")
		r.RequestFacts = map[string]string{agentruntime.FactRoleARN: "arn:aws:iam::1:role/r" + string(rune('a'+i%26))}
		none(t, Evaluate(DefaultConfig(), b, r, observed.Add(time.Hour)), D7)
	}
	// D1 is not about novelty: it fires during learning.
	only(t, Evaluate(DefaultConfig(), b, ev("secretsmanager.amazonaws.com", "GetSecretValue"), observed.Add(time.Hour)), D1)

	// After the first day, a never-seen model alerts.
	later := observed.Add(25 * time.Hour)
	only(t, Evaluate(DefaultConfig(), b, modelCall("brand-new", later), later), D6)
	// A zero ObservedSince is a new identity: learning.
	if !NewBaseline(time.Time{}).Learning(DefaultConfig(), later) {
		t.Error("a zero ObservedSince is not learning")
	}
}

func TestChangesAggregate(t *testing.T) {
	b := NewBaseline(t0)
	Evaluate(DefaultConfig(), b, modelCall("m", t0), t0)
	Evaluate(DefaultConfig(), b, modelCall("m", t0.Add(time.Minute)), t0)
	var model, hourly *Change
	for _, c := range b.Changes() {
		c := c
		switch c.Kind {
		case KindModel:
			model = &c
		case KindHourly:
			hourly = &c
		}
	}
	if model == nil || model.Delta != 2 || !model.First.Equal(t0) || !model.Last.Equal(t0.Add(time.Minute)) {
		t.Errorf("model change %+v", model)
	}
	if hourly == nil || hourly.Delta != 2 || hourly.Key != HourKey(t0) {
		t.Errorf("hourly change %+v", hourly)
	}
}
