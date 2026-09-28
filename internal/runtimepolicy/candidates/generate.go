// Package candidates is the §8.2 draft generator.
//
// It groups observed access by workload incarnation, executable or image
// version, environment and action class. Allows come only from eligible
// successes and declared dependencies that pass the risk filters. Denied
// attempts, incidents, sensitive resources, new public destinations, privilege
// changes and wildcards are recorded and never become an allow. Missing
// coverage marks the candidate partial; it does not add or drop rules.
// The same inputs produce the same input hash and the same rules.
package candidates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	// GeneratorVersion is stored on every candidate rule.
	GeneratorVersion = "trd2-s8.2-1"
	// BaselineWindow is the production confidence window.
	BaselineWindow = 7 * 24 * time.Hour
	// LimitedObservationWindow is the short preview that must be labelled.
	LimitedObservationWindow = 5 * time.Minute
)

// Input is everything the generator is allowed to see. It does not read a database.
type Input struct {
	WorkloadIDs   []string
	GraphRevision int64
	WindowStart   time.Time
	WindowEnd     time.Time
	Observations  []Observation
	Declared      []Dependency
	Coverage      []Coverage
}

// Observation is one iga_observed_access fact, already classified.
type Observation struct {
	ID                string
	WorkloadID        string
	RuntimeInstanceID string
	Executable        string
	Environment       string
	Action            string
	Outcome           string
	ResourceID        string
	NativeKind        string
	Address           string
	Path              string
	ObservedAt        time.Time
	Incident          bool
	Sensitive         bool
	Internet          bool
	Privilege         bool
	Wildcard          bool
	Schedule          string
}

// Dependency is a declared workload-to-resource binding.
type Dependency struct {
	WorkloadID  string
	ResourceID  string
	BindingKind string
	Action      string
	NativeKind  string
	Address     string
	Path        string
	Sensitive   bool
	Internet    bool
	Privilege   bool
	Wildcard    bool
	Schedule    string
}

// Coverage is one collector class. State is complete, stale, unknown or partial.
type Coverage struct {
	CollectorID string
	Class       string
	State       string
}

// Rule is one proposed allow. It is not published.
type Rule struct {
	ID               string    `json:"id"`
	Action           string    `json:"action"`
	ResourceID       string    `json:"resource_id,omitempty"`
	Path             string    `json:"path,omitempty"`
	Effect           string    `json:"effect"`
	ObservationIDs   []string  `json:"observation_ids"`
	FirstSeen        time.Time `json:"first_seen,omitempty"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	Count            int       `json:"count"`
	Groups           []string  `json:"groups"`
	NativeContext    any       `json:"native_context,omitempty"`
	GeneratorVersion string    `json:"generator_version"`
	Declared         bool      `json:"declared,omitempty"`
}

// Record is a denied attempt or a review item. It is never an allow.
type Record struct {
	ObservationID string   `json:"observation_id,omitempty"`
	WorkloadID    string   `json:"workload_id,omitempty"`
	ResourceID    string   `json:"resource_id,omitempty"`
	Action        string   `json:"action,omitempty"`
	Path          string   `json:"path,omitempty"`
	Outcome       string   `json:"outcome,omitempty"`
	Reasons       []string `json:"reasons"`
}

// Detection is an explicit finding hint. A7 does not write runtime_findings.
type Detection struct {
	Kind          string `json:"kind"`
	ObservationID string `json:"observation_id,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
	Path          string `json:"path,omitempty"`
	Outcome       string `json:"outcome,omitempty"`
}

// Result is the draft suggestion. Rules are the only allow set.
type Result struct {
	Partial             bool
	LimitedObservation  bool
	InputHash           string
	Coverage            []Coverage
	Rules               []Rule
	Denied              []Record
	Review              []Record
	Detections          []Detection
	UnobservedScheduled []string
	ExcludedIncidents   int
}

// Generate builds a candidate. Empty workload ids or an inverted window is an error.
func Generate(in Input) (Result, error) {
	if len(in.WorkloadIDs) == 0 {
		return Result{}, errInput("workload_ids are required")
	}
	if in.WindowEnd.IsZero() || in.WindowStart.IsZero() || in.WindowEnd.Before(in.WindowStart) {
		return Result{}, errInput("evidence window must have a start and an end")
	}
	want := map[string]bool{}
	for _, id := range in.WorkloadIDs {
		if id != "" {
			want[id] = true
		}
	}
	var out Result
	out.LimitedObservation = in.WindowEnd.Sub(in.WindowStart) <= LimitedObservationWindow
	out.Coverage = normalizeCoverage(in.Coverage)
	out.Partial = !coverageComplete(out.Coverage)

	type bucket struct {
		rule   Rule
		seen   map[string]bool
		groups map[string]bool
	}
	allows := map[string]*bucket{}
	addAllow := func(action, resource, path, workload, runtime, exe, env, native, address string, at time.Time, obsID string, declared bool) {
		if action == "" || isShadowPath(path) {
			return
		}
		key := action + "\x00" + resource + "\x00" + path
		b := allows[key]
		if b == nil {
			b = &bucket{
				rule: Rule{
					ID: ruleID(action, resource, path), Action: action, ResourceID: resource, Path: path,
					Effect: "allow", GeneratorVersion: GeneratorVersion, Declared: declared,
					NativeContext: map[string]any{"native_kind": native, "address": address, "path": path, "resource_id": resource},
				},
				seen: map[string]bool{}, groups: map[string]bool{},
			}
			allows[key] = b
		}
		if declared {
			b.rule.Declared = true
		}
		if obsID != "" && !b.seen[obsID] {
			b.seen[obsID] = true
			b.rule.Count++
			if b.rule.FirstSeen.IsZero() || at.Before(b.rule.FirstSeen) {
				b.rule.FirstSeen = at
			}
			if at.After(b.rule.LastSeen) {
				b.rule.LastSeen = at
			}
		}
		g := strings.Join([]string{workload, runtime, exe, env, action}, "|")
		b.groups[g] = true
	}

	seenSchedule := map[string]bool{}
	for _, o := range in.Observations {
		if !want[o.WorkloadID] || o.ObservedAt.Before(in.WindowStart) || o.ObservedAt.After(in.WindowEnd) {
			continue
		}
		if o.Schedule != "" {
			seenSchedule[o.Schedule] = true
		}
		if o.Incident {
			out.ExcludedIncidents++
			continue
		}
		if isShadowPath(o.Path) {
			out.Detections = append(out.Detections, Detection{
				Kind: "sensitive_file_access", ObservationID: o.ID, ResourceID: o.ResourceID, Path: o.Path, Outcome: o.Outcome,
			})
			out.Denied = append(out.Denied, Record{
				ObservationID: o.ID, WorkloadID: o.WorkloadID, ResourceID: o.ResourceID,
				Action: o.Action, Path: o.Path, Outcome: o.Outcome, Reasons: []string{"sensitive_file"},
			})
			continue
		}
		if o.Outcome == "denied" || o.Outcome == "attempted" {
			out.Denied = append(out.Denied, Record{
				ObservationID: o.ID, WorkloadID: o.WorkloadID, ResourceID: o.ResourceID,
				Action: o.Action, Path: o.Path, Outcome: o.Outcome, Reasons: []string{o.Outcome},
			})
			continue
		}
		if o.Outcome != "success" {
			continue
		}
		reasons := riskReasons(o.Sensitive, o.Internet, o.Privilege, o.Wildcard)
		if len(reasons) > 0 {
			out.Review = append(out.Review, Record{
				ObservationID: o.ID, WorkloadID: o.WorkloadID, ResourceID: o.ResourceID,
				Action: o.Action, Path: o.Path, Outcome: o.Outcome, Reasons: reasons,
			})
			continue
		}
		addAllow(o.Action, o.ResourceID, o.Path, o.WorkloadID, o.RuntimeInstanceID, o.Executable, o.Environment, o.NativeKind, o.Address, o.ObservedAt, o.ID, false)
	}
	declaredSched := map[string]bool{}
	for _, d := range in.Declared {
		if !want[d.WorkloadID] {
			continue
		}
		if d.Schedule != "" {
			declaredSched[d.Schedule] = true
		}
		reasons := riskReasons(d.Sensitive || d.BindingKind == "secret_ref", d.Internet, d.Privilege, d.Wildcard)
		if isShadowPath(d.Path) {
			reasons = append(reasons, "sensitive_file")
		}
		if len(reasons) > 0 || d.BindingKind == "secret_ref" {
			if len(reasons) == 0 {
				reasons = []string{"sensitive"}
			}
			out.Review = append(out.Review, Record{
				WorkloadID: d.WorkloadID, ResourceID: d.ResourceID, Action: d.Action, Path: d.Path, Reasons: reasons,
			})
			continue
		}
		if d.Action == "" {
			continue
		}
		addAllow(d.Action, d.ResourceID, d.Path, d.WorkloadID, "", "", "", d.NativeKind, d.Address, time.Time{}, "", true)
	}
	for label := range declaredSched {
		if !seenSchedule[label] {
			out.UnobservedScheduled = append(out.UnobservedScheduled, label)
		}
	}
	sort.Strings(out.UnobservedScheduled)

	ids := make([]string, 0, len(allows))
	for id := range allows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := allows[id]
		for obs := range b.seen {
			b.rule.ObservationIDs = append(b.rule.ObservationIDs, obs)
		}
		sort.Strings(b.rule.ObservationIDs)
		for g := range b.groups {
			b.rule.Groups = append(b.rule.Groups, g)
		}
		sort.Strings(b.rule.Groups)
		if b.rule.ObservationIDs == nil {
			b.rule.ObservationIDs = []string{}
		}
		out.Rules = append(out.Rules, b.rule)
	}
	sortRecords(out.Denied)
	sortRecords(out.Review)
	sort.Slice(out.Detections, func(i, j int) bool {
		return out.Detections[i].ObservationID < out.Detections[j].ObservationID
	})
	out.InputHash = hashInput(in, want)
	return out, nil
}

func riskReasons(sensitive, internet, privilege, wildcard bool) []string {
	var r []string
	if sensitive {
		r = append(r, "sensitive")
	}
	if internet {
		r = append(r, "internet_destination")
	}
	if privilege {
		r = append(r, "privilege_change")
	}
	if wildcard {
		r = append(r, "wildcard")
	}
	return r
}

func sortRecords(rs []Record) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].ObservationID != rs[j].ObservationID {
			return rs[i].ObservationID < rs[j].ObservationID
		}
		return rs[i].ResourceID < rs[j].ResourceID
	})
}

func ruleID(action, resource, path string) string {
	sum := sha256.Sum256([]byte(action + "\x00" + resource + "\x00" + path))
	return "allow-" + hex.EncodeToString(sum[:])[:12]
}

func isShadowPath(path string) bool {
	path = strings.TrimSpace(path)
	return path == "/etc/shadow" || strings.HasSuffix(path, "/shadow")
}

func coverageComplete(rows []Coverage) bool {
	if len(rows) == 0 {
		return false
	}
	for _, row := range rows {
		switch row.State {
		case "complete", "complete_for_selected_scope":
		default:
			return false
		}
	}
	return true
}

func normalizeCoverage(rows []Coverage) []Coverage {
	if len(rows) == 0 {
		return []Coverage{{Class: "collectors", State: "unknown"}}
	}
	out := append([]Coverage(nil), rows...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CollectorID != out[j].CollectorID {
			return out[i].CollectorID < out[j].CollectorID
		}
		return out[i].Class < out[j].Class
	})
	return out
}

func hashInput(in Input, want map[string]bool) string {
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	obs := append([]Observation(nil), in.Observations...)
	sort.Slice(obs, func(i, j int) bool { return obs[i].ID < obs[j].ID })
	deps := append([]Dependency(nil), in.Declared...)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].WorkloadID != deps[j].WorkloadID {
			return deps[i].WorkloadID < deps[j].WorkloadID
		}
		return deps[i].ResourceID < deps[j].ResourceID
	})
	body, _ := json.Marshal(struct {
		Workloads []string      `json:"workloads"`
		Graph     int64         `json:"graph_revision"`
		Start     string        `json:"start"`
		End       string        `json:"end"`
		Obs       []Observation `json:"observations"`
		Deps      []Dependency  `json:"declared"`
		Coverage  []Coverage    `json:"coverage"`
		Version   string        `json:"generator_version"`
	}{
		Workloads: ids, Graph: in.GraphRevision,
		Start: in.WindowStart.UTC().Format(time.RFC3339Nano),
		End:   in.WindowEnd.UTC().Format(time.RFC3339Nano),
		Obs:   obs, Deps: deps, Coverage: normalizeCoverage(in.Coverage), Version: GeneratorVersion,
	})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Interpret classifies one resource so the service and the tests share the filters.
type InterpretInput struct {
	Action      string
	Outcome     string
	Attribution string
	BindingKind string
	NativeKind  string
	Metadata    map[string]any
}

// Traits is the classification Interpret returns.
type Traits struct {
	Action    string
	Path      string
	Address   string
	Sensitive bool
	Internet  bool
	Privilege bool
	Wildcard  bool
	Incident  bool
	Schedule  string
	Shadow    bool
}

// Interpret applies the §8.2 risk filters to one row.
func Interpret(in InterpretInput) Traits {
	var t Traits
	t.Action = normalizeAction(in.Action, in.BindingKind)
	t.Path, _ = in.Metadata["path"].(string)
	t.Address, _ = in.Metadata["address"].(string)
	if s, ok := in.Metadata["schedule"].(string); ok {
		t.Schedule = s
	}
	if in.Attribution != "" && strings.HasPrefix(in.Attribution, "schedule:") {
		t.Schedule = strings.TrimPrefix(in.Attribution, "schedule:")
	}
	t.Incident = in.Attribution == "incident" || strings.Contains(in.Attribution, "incident")
	t.Shadow = isShadowPath(t.Path)
	t.Sensitive = t.Shadow || in.BindingKind == "secret_ref" || strings.Contains(in.NativeKind, "secret") || t.Action == "secret.read" || truthy(in.Metadata["sensitive"])
	t.Internet = internetAddress(t.Address) || truthy(in.Metadata["internet"])
	t.Privilege = t.Action == "exec" || truthy(in.Metadata["privilege_change"])
	t.Wildcard = strings.Contains(t.Path, "*") || truthy(in.Metadata["wildcard"])
	return t
}

func truthy(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func normalizeAction(action, binding string) string {
	switch action {
	case "network.connect", "connect", "network_connect":
		return "network.connect"
	case "file.read", "open", "read":
		return "file.read"
	case "file.write", "write":
		return "file.write"
	case "exec":
		return "exec"
	case "secret.read":
		return "secret.read"
	case "admission":
		return "admission"
	}
	switch binding {
	case "secret_ref":
		return "secret.read"
	case "service_dependency":
		return "network.connect"
	case "mount", "declared":
		return "file.read"
	default:
		return action
	}
}

func internetAddress(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

type inputError string

func (e inputError) Error() string { return string(e) }

func errInput(msg string) error { return inputError(msg) }

// IsInputError reports a caller error, not a generator failure.
func IsInputError(err error) bool {
	_, ok := err.(inputError)
	return ok
}
