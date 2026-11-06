// Package detect holds the agent runtime detections D1-D8
// (SPEC-agent-runtime-visibility.md §5.7, with §10's D1 change): pure
// functions over one normalised CloudTrail event and the per-identity
// baseline the caller loads and persists. Nothing here reads a database, a
// clock or the network; the caller passes "now".
//
// The caller decides who is evaluated (identities labelled AI workload,
// suggested agent or agent), deduplicates findings into alerts and delivers
// them (services/agent_runtime_alerts.go).
//
// Learning (the "first run must not flood" rule). The "never seen"
// detections -- D6's new model, D7's new role and D8's new source IP or
// region -- learn SILENTLY while the identity is in its learning period:
// LearningPeriod (default 24 h) of wall-clock time from when AuthSec first
// observed the identity (Baseline.ObservedSince). A first scan that reads 90
// days of history therefore only builds the baseline; from the next day on,
// something never seen raises a finding. D6's volume spike needs no learning
// period: it fires only once BaselineMinHours of hourly history exist. D1-D5
// are not about novelty and always evaluate.
package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// ID is a detection id (spec §5.7). The API filters and settings use these.
type ID string

// Detections.
const (
	D1 ID = "D1" // reads a secret
	D2 ID = "D2" // creates credentials
	D3 ID = "D3" // changes IAM
	D4 ID = "D4" // weakens logging
	D5 ID = "D5" // acts outside its grant (burst of denials)
	D6 ID = "D6" // new model or volume spike
	D7 ID = "D7" // new role assumption
	D8 ID = "D8" // model call from an unexpected place
)

// All lists every detection, in order.
var All = []ID{D1, D2, D3, D4, D5, D6, D7, D8}

// Valid reports whether id is a known detection.
func Valid(id ID) bool {
	for _, d := range All {
		if d == id {
			return true
		}
	}
	return false
}

// Severities.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
)

// SeverityRank orders severities (higher is worse); unknown is 0.
func SeverityRank(s string) int {
	switch s {
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	}
	return 0
}

// Name is a detection's short title, as the console and Slack show it.
func Name(id ID) string {
	switch id {
	case D1:
		return "Read a secret"
	case D2:
		return "Created credentials"
	case D3:
		return "Changed IAM"
	case D4:
		return "Weakened logging"
	case D5:
		return "Acted outside its grant"
	case D6:
		return "New model or volume spike"
	case D7:
		return "New role assumption"
	case D8:
		return "Model call from an unexpected place"
	}
	return string(id)
}

// FactWithDecryption is the RequestFacts key the shared parser fills with
// "true" or "false" from ssm's requestParameters.withDecryption
// (agentruntime.FactWithDecryption).
const FactWithDecryption = agentruntime.FactWithDecryption

// Config is one workspace's detection configuration.
type Config struct {
	// Disabled detections raise nothing; their baselines still learn.
	Disabled map[ID]bool
	// D5: DenialBurst denials within DenialWindow (spec §10 Q7: 10 in 5 min).
	DenialBurst  int
	DenialWindow time.Duration
	// D6: last hour's model calls > SpikeFactor x the 7-day hourly mean
	// (Q7: k = 5). The mean is floored at SpikeFloor so a near-idle identity
	// does not alert on its second call; at least BaselineMinHours of history
	// must exist ("when a baseline exists").
	SpikeFactor      float64
	SpikeFloor       float64
	BaselineMinHours int
	// LearningPeriod: see the package comment.
	LearningPeriod time.Duration
}

// Defaults (spec §10, Q7).
const (
	DefaultDenialBurst      = 10
	DefaultDenialWindow     = 5 * time.Minute
	DefaultSpikeFactor      = 5.0
	DefaultSpikeFloor       = 1.0
	DefaultBaselineMinHours = 24
	DefaultLearningPeriod   = 24 * time.Hour
	// BaselineHours is D6's baseline span: 7 days of hourly buckets.
	BaselineHours = 7 * 24
)

// DefaultConfig is every detection on with the defaults.
func DefaultConfig() Config {
	return Config{
		Disabled:    map[ID]bool{},
		DenialBurst: DefaultDenialBurst, DenialWindow: DefaultDenialWindow,
		SpikeFactor: DefaultSpikeFactor, SpikeFloor: DefaultSpikeFloor,
		BaselineMinHours: DefaultBaselineMinHours, LearningPeriod: DefaultLearningPeriod,
	}
}

// Enabled reports whether id raises findings.
func (c Config) Enabled(id ID) bool { return !c.Disabled[id] }

func (c Config) normalised() Config {
	d := DefaultConfig()
	if c.DenialBurst < 1 {
		c.DenialBurst = d.DenialBurst
	}
	if c.DenialWindow < time.Minute {
		c.DenialWindow = d.DenialWindow
	}
	if c.SpikeFactor <= 0 {
		c.SpikeFactor = d.SpikeFactor
	}
	if c.SpikeFloor <= 0 {
		c.SpikeFloor = d.SpikeFloor
	}
	if c.BaselineMinHours < 1 {
		c.BaselineMinHours = d.BaselineMinHours
	}
	if c.LearningPeriod < 0 {
		c.LearningPeriod = d.LearningPeriod
	}
	return c
}

/* ------------------------------------------------------------------------- */
/*                                  Baseline                                  */
/* ------------------------------------------------------------------------- */

// Baseline kinds (agent_alert_baseline.kind).
const (
	KindModel  = "model"  // model ids called (D6)
	KindRole   = "role"   // role ARNs assumed (D7)
	KindIP     = "ip"     // source IPs of model calls (D8)
	KindRegion = "region" // regions of model calls (D8)
	KindHourly = "hourly" // model calls per clock hour; key HourKey (D6 spike)
	KindDenied = "denied" // authorization denials per minute; key MinuteKey (D5)
	// KindObserved is one row per identity (key ""): first_seen is when
	// AuthSec first observed it -- the start of its learning period.
	KindObserved = "observed"
)

// HourKey is the hourly bucket key of t.
func HourKey(t time.Time) string { return t.UTC().Truncate(time.Hour).Format(time.RFC3339) }

// MinuteKey is the per-minute bucket key of t.
func MinuteKey(t time.Time) string { return t.UTC().Truncate(time.Minute).Format(time.RFC3339) }

// Change is one baseline row to upsert: count += Delta, first_seen =
// least(First), last_seen = greatest(Last).
type Change struct {
	Kind, Key   string
	First, Last time.Time
	Delta       int
}

// Baseline is one identity's learned state. Load it with Know / LoadBucket,
// evaluate events in time order, then persist Changes.
type Baseline struct {
	// ObservedSince is when AuthSec first observed the identity (wall
	// clock). Zero means "now": the identity is new and learning.
	ObservedSince time.Time

	seen    map[string]map[string]bool
	hourly  map[int64]int // unix hour -> model calls
	denied  map[int64]int // unix minute -> denials
	changes map[[2]string]*Change
}

// NewBaseline is an empty baseline for an identity first observed at
// observedSince.
func NewBaseline(observedSince time.Time) *Baseline {
	return &Baseline{ObservedSince: observedSince, seen: map[string]map[string]bool{},
		hourly: map[int64]int{}, denied: map[int64]int{}, changes: map[[2]string]*Change{}}
}

// Know records a stored "seen" key (model, role, ip, region).
func (b *Baseline) Know(kind, key string) {
	if b.seen[kind] == nil {
		b.seen[kind] = map[string]bool{}
	}
	b.seen[kind][key] = true
}

// Seen reports whether key of kind is known.
func (b *Baseline) Seen(kind, key string) bool { return b.seen[kind][key] }

// LoadBucket records a stored hourly or denied bucket count. Unknown kinds
// and unparsable keys are ignored.
func (b *Baseline) LoadBucket(kind, key string, count int) {
	t, err := time.Parse(time.RFC3339, key)
	if err != nil {
		return
	}
	switch kind {
	case KindHourly:
		b.hourly[t.Unix()/3600] += count
	case KindDenied:
		b.denied[t.Unix()/60] += count
	}
}

// Changes are the rows to persist, ordered by kind and key.
func (b *Baseline) Changes() []Change {
	out := make([]Change, 0, len(b.changes))
	for _, c := range b.changes {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (b *Baseline) note(kind, key string, at time.Time) {
	k := [2]string{kind, key}
	c, ok := b.changes[k]
	if !ok {
		c = &Change{Kind: kind, Key: key, First: at, Last: at}
		b.changes[k] = c
	}
	if at.Before(c.First) {
		c.First = at
	}
	if at.After(c.Last) {
		c.Last = at
	}
	c.Delta++
}

// learn records key as seen and reports whether it was new.
func (b *Baseline) learn(kind, key string, at time.Time) bool {
	isNew := !b.Seen(kind, key)
	b.Know(kind, key)
	b.note(kind, key, at)
	return isNew
}

// Learning reports whether the identity is in its learning period at now.
func (b *Baseline) Learning(cfg Config, now time.Time) bool {
	if b.ObservedSince.IsZero() {
		return true
	}
	return now.Sub(b.ObservedSince) < cfg.normalised().LearningPeriod
}

// hourlyMean is the mean model calls per hour over the BaselineHours before
// hour cur, from the earliest stored bucket in that span; ok is false when
// fewer than minHours of history exist.
func (b *Baseline) hourlyMean(cur int64, minHours int) (mean float64, ok bool) {
	earliest := cur
	sum := 0
	for h, n := range b.hourly {
		if h >= cur || h < cur-BaselineHours {
			continue
		}
		sum += n
		if h < earliest {
			earliest = h
		}
	}
	hours := cur - earliest
	if hours < int64(minHours) || sum == 0 {
		return 0, false
	}
	return float64(sum) / float64(hours), true
}

func (b *Baseline) deniedInWindow(cur int64, minutes int) int {
	n := 0
	for m := cur - int64(minutes) + 1; m <= cur; m++ {
		n += b.denied[m]
	}
	return n
}

/* ------------------------------------------------------------------------- */
/*                                  Evaluate                                  */
/* ------------------------------------------------------------------------- */

// Finding is one detection raised by one event.
type Finding struct {
	Detection ID
	Severity  string
	// Detail says what matched: the API name, the new model id, role ARN,
	// source IP or region, or the counts of a burst or spike. It never
	// carries a secret value (events carry none) nor a secret's name.
	Detail string
}

// Evaluate runs every detection on e for one identity, updating b (learning
// and counters) whether or not a detection is enabled. Call it in event-time
// order. now is the wall clock (learning period only).
func Evaluate(cfg Config, b *Baseline, e agentruntime.Event, now time.Time) []Finding {
	cfg = cfg.normalised()
	var out []Finding
	add := func(id ID, sev, detail string) {
		if cfg.Enabled(id) {
			out = append(out, Finding{Detection: id, Severity: sev, Detail: detail})
		}
	}
	learning := b.Learning(cfg, now)
	at := e.EventTime.UTC()
	success := e.ErrorCode == "" && e.IsAPICall()

	if success {
		if sev, ok := SecretRead(e); ok {
			add(D1, sev, api(e))
		}
		if CreatesCredentials(e) {
			add(D2, SeverityHigh, api(e))
		}
		if ChangesIAM(e) {
			add(D3, SeverityHigh, api(e))
		}
		if sev, ok := WeakensLogging(e); ok {
			add(D4, sev, api(e))
		}
		if e.IsModelCall() {
			// D6: a model id never seen for the identity.
			if model := strings.TrimSpace(e.RequestFacts[agentruntime.FactModelID]); model != "" {
				if b.learn(KindModel, model, at) && !learning {
					add(D6, SeverityMedium, "first call to model "+model)
				}
			}
			// D6: volume spike over the 7-day hourly baseline. Fires when
			// the hour's count crosses the threshold, once per hour.
			cur := at.Unix() / 3600
			prev := b.hourly[cur]
			b.hourly[cur] = prev + 1
			b.note(KindHourly, HourKey(at), at.Truncate(time.Hour))
			if mean, ok := b.hourlyMean(cur, cfg.BaselineMinHours); ok {
				floor := mean
				if floor < cfg.SpikeFloor {
					floor = cfg.SpikeFloor
				}
				thr := cfg.SpikeFactor * floor
				if float64(prev) <= thr && float64(prev+1) > thr {
					add(D6, SeverityMedium, fmt.Sprintf("%d model calls this hour, over %.4g x the 7-day hourly mean of %.2f", prev+1, cfg.SpikeFactor, mean))
				}
			}
			// D8: a source IP or region never seen for the identity. AWS
			// service source addresses and calls made by a service on the
			// identity's behalf say nothing about where it runs.
			if e.InvokedBy == "" {
				var where []string
				if ip := strings.TrimSpace(e.SourceIP); ip != "" && !IsAWSServiceSource(ip) {
					if b.learn(KindIP, ip, at) && !learning {
						where = append(where, "source IP "+ip)
					}
				}
				if region := strings.TrimSpace(e.Region); region != "" {
					if b.learn(KindRegion, region, at) && !learning {
						where = append(where, "region "+region)
					}
				}
				if len(where) > 0 {
					add(D8, SeverityMedium, "model call from new "+strings.Join(where, " and "))
				}
			}
		}
		// D7: sts:AssumeRole into a role this identity never assumed.
		if e.EventSource == "sts.amazonaws.com" && e.EventName == "AssumeRole" {
			if role := strings.TrimSpace(e.RequestFacts[agentruntime.FactRoleARN]); role != "" {
				if b.learn(KindRole, role, at) && !learning {
					add(D7, SeverityMedium, "assumed "+role)
				}
			}
		}
	}

	// D5: N authorization denials within M minutes. Fires when the window's
	// count reaches N.
	if e.AuthorizationDenied {
		cur := at.Unix() / 60
		b.denied[cur]++
		b.note(KindDenied, MinuteKey(at), at.Truncate(time.Minute))
		minutes := int(cfg.DenialWindow / time.Minute)
		n := b.deniedInWindow(cur, minutes)
		if n-1 < cfg.DenialBurst && n >= cfg.DenialBurst {
			add(D5, SeverityMedium, fmt.Sprintf("%d authorization denials within %d minutes (last: %s)", n, minutes, api(e)))
		}
	}
	return out
}

// api is "service:EventName" ("secretsmanager:GetSecretValue").
func api(e agentruntime.Event) string {
	svc := strings.TrimSuffix(e.EventSource, ".amazonaws.com")
	if svc == "" {
		return e.EventName
	}
	return svc + ":" + e.EventName
}

// IsAWSServiceSource reports whether a sourceIPAddress names an AWS service
// ("lambda.amazonaws.com", "AWS Internal") rather than an address.
func IsAWSServiceSource(ip string) bool {
	ip = strings.ToLower(strings.TrimSpace(ip))
	return strings.HasSuffix(ip, ".amazonaws.com") || ip == "aws internal"
}

// SecretRead is D1 (spec §5.7 with §10's change): Secrets Manager
// GetSecretValue / BatchGetSecretValue (high); SSM GetParameter,
// GetParameters, GetParametersByPath only with
// with_decryption=true (medium); KMS Decrypt (medium) ONLY when the principal
// called it directly (no invokedBy: service-made decrypts accompany a read
// already alerted on) and its encryption context names a secret or parameter.
//
// DECISION (lab 2026-11-05): a plain GetParameter reads configuration (217
// of them made one alert), not a secret: only a decrypting read returns a
// SecureString's value. A record that does not state withDecryption is
// treated as not decrypting and raises nothing (AWS's own default is
// false); a SecureString read always passes withDecryption=true.
func SecretRead(e agentruntime.Event) (severity string, ok bool) {
	switch e.EventSource {
	case "secretsmanager.amazonaws.com":
		if e.EventName == "GetSecretValue" || e.EventName == "BatchGetSecretValue" {
			return SeverityHigh, true
		}
	case "ssm.amazonaws.com":
		switch e.EventName {
		case "GetParameter", "GetParameters", "GetParametersByPath":
			if !strings.EqualFold(strings.TrimSpace(e.RequestFacts[FactWithDecryption]), "true") {
				return "", false
			}
			return SeverityMedium, true
		}
	case "kms.amazonaws.com":
		if e.EventName == "Decrypt" {
			if strings.TrimSpace(e.InvokedBy) != "" || e.RequestFacts[agentruntime.FactSecretContext] != "true" {
				return "", false
			}
			return SeverityMedium, true
		}
	}
	return "", false
}

var credentialCalls = map[string]map[string]bool{
	"iam.amazonaws.com": {"CreateAccessKey": true, "CreateLoginProfile": true, "UpdateLoginProfile": true},
	"sts.amazonaws.com": {"GetFederationToken": true},
}

// CreatesCredentials is D2.
func CreatesCredentials(e agentruntime.Event) bool {
	return credentialCalls[e.EventSource][e.EventName]
}

var iamChangeCalls = map[string]bool{
	"AttachRolePolicy": true, "AttachUserPolicy": true, "AttachGroupPolicy": true,
	"PutRolePolicy": true, "PutUserPolicy": true, "PutGroupPolicy": true,
	"UpdateAssumeRolePolicy": true, "CreateRole": true, "CreatePolicyVersion": true,
	"SetDefaultPolicyVersion": true, "AddRoleToInstanceProfile": true,
}

// ChangesIAM is D3.
func ChangesIAM(e agentruntime.Event) bool {
	return e.EventSource == "iam.amazonaws.com" && iamChangeCalls[e.EventName]
}

var loggingCalls = map[string]map[string]string{
	"cloudtrail.amazonaws.com": {"StopLogging": SeverityHigh, "DeleteTrail": SeverityHigh, "PutEventSelectors": SeverityHigh,
		"PutAdvancedEventSelectors": SeverityHigh, "UpdateTrail": SeverityHigh},
	"bedrock.amazonaws.com": {"DeleteModelInvocationLoggingConfiguration": SeverityHigh},
	"logs.amazonaws.com":    {"DeleteLogGroup": SeverityMedium},
}

// WeakensLogging is D4 with its severity.
func WeakensLogging(e agentruntime.Event) (severity string, ok bool) {
	sev, ok := loggingCalls[e.EventSource][e.EventName]
	return sev, ok
}
