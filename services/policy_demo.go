package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Policy UI demo (/api/policy-demo/v1). A policy names an agent, the identity
// it acts as, one S3 bucket (optionally one prefix), the access it may have and
// a time window. These rows are stored and listed, and the AWS documents such a
// policy WOULD produce are generated from them for display. Nothing is deployed
// to AWS, evaluated or enforced, and nothing outside the demo routes reads them.

// PolicyDemoError is a refusal with its HTTP status and a message for people.
type PolicyDemoError struct {
	Status  int
	Code    string
	Message string
	Field   string
}

func (e *PolicyDemoError) Error() string { return e.Message }

func demoBad(field, msg string) *PolicyDemoError {
	return &PolicyDemoError{Status: http.StatusBadRequest, Code: "invalid_parameter", Message: msg, Field: field}
}

// PolicyDemoRow is the stored policy.
type PolicyDemoRow struct {
	ID            uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID      `gorm:"type:uuid;not null"`
	Name          string         `gorm:"not null"`
	Description   string         `gorm:"not null;default:''"`
	Agent         string         `gorm:"not null;default:''"`
	Identity      string         `gorm:"not null;default:''"`
	ResourceType  string         `gorm:"not null;default:'s3'"`
	Resource      string         `gorm:"not null"`
	Prefix        string         `gorm:"not null;default:''"`
	Actions       pq.StringArray `gorm:"type:text[];not null"`
	ProtectBucket bool           `gorm:"not null;default:true"`
	RequireTLS    bool           `gorm:"column:require_tls;not null;default:true"`
	StartTime     *time.Time
	EndTime       *time.Time
	Paused        bool       `gorm:"not null;default:false"`
	CreatedBy     *uuid.UUID `gorm:"type:uuid"`
	CreatedAt     time.Time  `gorm:"not null;default:now()"`
	UpdatedAt     time.Time  `gorm:"not null;default:now()"`
}

func (PolicyDemoRow) TableName() string { return "policy_demo_policies" }

// PolicyDemoInput is the body of create, update and preview.
type PolicyDemoInput struct {
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Agent         string     `json:"agent"`
	Identity      string     `json:"identity"`
	ResourceType  string     `json:"resource_type"`
	Resource      string     `json:"resource"`
	Prefix        string     `json:"prefix"`
	Actions       []string   `json:"actions"`
	ProtectBucket *bool      `json:"protect_bucket"`
	RequireTLS    *bool      `json:"require_tls"`
	StartTime     *time.Time `json:"start_time"`
	EndTime       *time.Time `json:"end_time"`
}

// PolicyDemoView is a policy as served, with where it stands in time and the
// documents it would produce.
type PolicyDemoView struct {
	ID            uuid.UUID            `json:"id"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Agent         string               `json:"agent"`
	Identity      string               `json:"identity"`
	ResourceType  string               `json:"resource_type"`
	Resource      string               `json:"resource"`
	Prefix        string               `json:"prefix"`
	Actions       []string             `json:"actions"`
	ProtectBucket bool                 `json:"protect_bucket"`
	RequireTLS    bool                 `json:"require_tls"`
	StartTime     *time.Time           `json:"start_time"`
	EndTime       *time.Time           `json:"end_time"`
	Paused        bool                 `json:"paused"`
	Phase         string               `json:"phase"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
	Generated     *PolicyDemoGenerated `json:"generated,omitempty"`
}

// ordered is a JSON object that keeps its keys in the order given, so a
// generated policy reads the way AWS documents are written (Version, then
// Statement; Sid, Effect, Principal, Action, Resource, Condition).
type ordered [][2]any

func (o ordered) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(kv[0])
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(kv[1])
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// PolicyDemoGenerated is what AWS would see.
type PolicyDemoGenerated struct {
	// AttachTo is the identity the role policy would be attached to.
	AttachTo string `json:"attach_to"`
	// Summary is the policy in plain sentences.
	Summary []string `json:"summary"`
	// Warnings are interactions the author should know about.
	Warnings        []string `json:"warnings"`
	RolePolicy      ordered  `json:"role_policy"`
	BucketStatement []any    `json:"bucket_policy_statements"`
}

// Phases of a policy against the clock.
const (
	PolicyDemoScheduled = "scheduled"
	PolicyDemoActive    = "active"
	PolicyDemoExpired   = "expired"
	PolicyDemoPaused    = "paused"
)

// PolicyDemoActions are the access levels a policy can grant, and the S3
// actions each stands for.
var PolicyDemoActions = map[string][]string{
	"read":   {"s3:GetObject"},
	"write":  {"s3:PutObject"},
	"delete": {"s3:DeleteObject"},
}

var (
	demoBucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	demoARNRE    = regexp.MustCompile(`^arn:aws[a-z-]*:s3:::`)
)

func demoPhase(r PolicyDemoRow, now time.Time) string {
	switch {
	case r.Paused:
		return PolicyDemoPaused
	case r.StartTime != nil && now.Before(*r.StartTime):
		return PolicyDemoScheduled
	case r.EndTime != nil && !now.Before(*r.EndTime):
		return PolicyDemoExpired
	}
	return PolicyDemoActive
}

// normalise validates in and returns the row it describes (without identity
// columns). The bucket is accepted as a name or as arn:aws:s3:::name.
func (in PolicyDemoInput) normalise() (PolicyDemoRow, error) {
	var r PolicyDemoRow
	r.Name = strings.TrimSpace(in.Name)
	if r.Name == "" || len(r.Name) > 120 {
		return r, demoBad("name", "Give the policy a name of up to 120 characters.")
	}
	r.Description = strings.TrimSpace(in.Description)
	if len(r.Description) > 500 {
		return r, demoBad("description", "The description can be up to 500 characters.")
	}
	r.Agent = strings.TrimSpace(in.Agent)
	if r.Agent == "" {
		return r, demoBad("agent", "Name the agent this policy is for.")
	}
	r.Identity = strings.TrimSpace(in.Identity)
	if r.Identity == "" {
		return r, demoBad("identity", "Name the identity (role or account) the agent acts as.")
	}
	r.ResourceType = strings.ToLower(strings.TrimSpace(in.ResourceType))
	if r.ResourceType == "" {
		r.ResourceType = "s3"
	}
	if r.ResourceType != "s3" {
		return r, demoBad("resource_type", "Only S3 is available in this demo.")
	}
	bucket := strings.TrimSpace(in.Resource)
	bucket = demoARNRE.ReplaceAllString(bucket, "")
	if i := strings.Index(bucket, "/"); i >= 0 { // arn:aws:s3:::bucket/prefix/* pasted whole
		if in.Prefix == "" {
			in.Prefix = strings.TrimSuffix(strings.TrimSuffix(bucket[i+1:], "*"), "/") + "/"
		}
		bucket = bucket[:i]
	}
	if !demoBucketRE.MatchString(bucket) {
		return r, demoBad("resource", "Enter an S3 bucket name: 3 to 63 lowercase letters, digits, dots or hyphens.")
	}
	r.Resource = bucket
	prefix := strings.TrimSpace(in.Prefix)
	prefix = strings.TrimPrefix(prefix, "/")
	prefix = strings.TrimSuffix(prefix, "*")
	if prefix == "/" {
		prefix = ""
	}
	if len(prefix) > 512 || strings.ContainsAny(prefix, "*?") {
		return r, demoBad("prefix", "A prefix is a folder path such as invoices/ (no wildcards).")
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	r.Prefix = prefix
	seen := map[string]bool{}
	for _, a := range in.Actions {
		a = strings.ToLower(strings.TrimSpace(a))
		if _, ok := PolicyDemoActions[a]; !ok {
			return r, demoBad("actions", fmt.Sprintf("%q is not an access level. Choose read, write or delete.", a))
		}
		if !seen[a] {
			seen[a] = true
			r.Actions = append(r.Actions, a)
		}
	}
	if len(r.Actions) == 0 {
		return r, demoBad("actions", "Choose at least one kind of access.")
	}
	r.ProtectBucket, r.RequireTLS = true, true
	if in.ProtectBucket != nil {
		r.ProtectBucket = *in.ProtectBucket
	}
	if in.RequireTLS != nil {
		r.RequireTLS = *in.RequireTLS
	}
	r.StartTime, r.EndTime = in.StartTime, in.EndTime
	if r.StartTime != nil && r.EndTime != nil && !r.EndTime.After(*r.StartTime) {
		return r, demoBad("end_time", "The end must be after the start.")
	}
	return r, nil
}

// generate builds the AWS documents the policy would produce: an Allow role
// policy for the identity, limited to the prefix and to the window by
// aws:CurrentTime conditions, and the Deny statements for the bucket.
func demoGenerate(r PolicyDemoRow) *PolicyDemoGenerated {
	bucketARN := "arn:aws:s3:::" + r.Resource
	objectARN := bucketARN + "/" + r.Prefix + "*"
	var window ordered
	if r.StartTime != nil {
		window = append(window, [2]any{"DateGreaterThan", ordered{{"aws:CurrentTime", r.StartTime.UTC().Format(time.RFC3339)}}})
	}
	if r.EndTime != nil {
		window = append(window, [2]any{"DateLessThan", ordered{{"aws:CurrentTime", r.EndTime.UTC().Format(time.RFC3339)}}})
	}
	// cond is the window plus an optional prefix restriction.
	cond := func(prefixLike string) ordered {
		out := append(ordered{}, window...)
		if prefixLike != "" {
			out = append(out, [2]any{"StringLike", ordered{{"s3:prefix", prefixLike}}})
		}
		return out
	}
	has := map[string]bool{}
	for _, a := range r.Actions {
		has[a] = true
	}

	var stmts []any
	add := func(sid, action, resource string, c ordered) {
		s := ordered{{"Sid", sid}, {"Effect", "Allow"}, {"Action", action}, {"Resource", resource}}
		if len(c) > 0 {
			s = append(s, [2]any{"Condition", c})
		}
		stmts = append(stmts, s)
	}
	where := "the bucket"
	if r.Prefix != "" {
		where = "the " + r.Prefix + " folder"
	}
	var summary []string
	if has["read"] {
		prefixLike := ""
		if r.Prefix != "" {
			prefixLike = r.Prefix + "*"
		}
		add("ListApprovedPrefix", "s3:ListBucket", bucketARN, cond(prefixLike))
		add("ReadApprovedPrefix", "s3:GetObject", objectARN, cond(""))
		summary = append(summary, fmt.Sprintf("%s can list and read objects in %s of %s.", r.Agent, where, r.Resource))
	}
	if has["write"] {
		add("WriteApprovedPrefix", "s3:PutObject", objectARN, cond(""))
		summary = append(summary, fmt.Sprintf("%s can upload and overwrite objects in %s of %s.", r.Agent, where, r.Resource))
	}
	if has["delete"] {
		add("DeleteApprovedPrefix", "s3:DeleteObject", objectARN, cond(""))
		summary = append(summary, fmt.Sprintf("%s can delete objects in %s of %s.", r.Agent, where, r.Resource))
	}
	switch {
	case r.StartTime != nil && r.EndTime != nil:
		summary = append(summary, fmt.Sprintf("Only from %s to %s (UTC); AWS stops honouring it at the end time by itself.",
			r.StartTime.UTC().Format("2 Jan 2006 15:04"), r.EndTime.UTC().Format("2 Jan 2006 15:04")))
	case r.EndTime != nil:
		summary = append(summary, fmt.Sprintf("Until %s (UTC); AWS stops honouring it at the end time by itself.", r.EndTime.UTC().Format("2 Jan 2006 15:04")))
	case r.StartTime != nil:
		summary = append(summary, fmt.Sprintf("From %s (UTC), with no end.", r.StartTime.UTC().Format("2 Jan 2006 15:04")))
	default:
		summary = append(summary, "No time limit: it applies until the policy is paused or removed.")
	}

	var warnings []string
	var bucket []any
	if r.ProtectBucket {
		denied := []string{"s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl", "s3:PutEncryptionConfiguration"}
		if !has["delete"] {
			denied = append([]string{"s3:DeleteObject"}, denied...)
		} else {
			warnings = append(warnings, "This policy allows delete, so the bucket's \"cannot change or delete\" guard leaves s3:DeleteObject out; the other protections stay.")
		}
		bucket = append(bucket, ordered{{"Sid", "AgentsCannotChangeOrDelete"}, {"Effect", "Deny"}, {"Principal", "*"}, {"Action", denied},
			{"Resource", []string{bucketARN, bucketARN + "/*"}},
			{"Condition", ordered{{"StringLike", ordered{{"aws:PrincipalTag/AgentId", "*"}}}}}})
		summary = append(summary, "Agents tagged with an AgentId cannot change this bucket's policy, ACLs or encryption"+map[bool]string{true: ".", false: ", or delete objects."}[has["delete"]])
		warnings = append(warnings, "The guard applies to roles carrying an AgentId tag, so the identity must be tagged with one.")
	}
	if r.RequireTLS {
		bucket = append(bucket, ordered{{"Sid", "RequireTLS"}, {"Effect", "Deny"}, {"Principal", "*"}, {"Action", "s3:*"},
			{"Resource", []string{bucketARN, bucketARN + "/*"}},
			{"Condition", ordered{{"Bool", ordered{{"aws:SecureTransport", "false"}}}}}})
		summary = append(summary, "Everyone, not only this agent, must use TLS to reach the bucket.")
		warnings = append(warnings, "Require TLS affects every caller of the bucket, not only this agent.")
	}
	if len(bucket) == 0 {
		bucket = []any{}
	}
	if warnings == nil {
		warnings = []string{}
	}
	return &PolicyDemoGenerated{
		AttachTo: r.Identity, Summary: summary, Warnings: warnings, BucketStatement: bucket,
		RolePolicy: ordered{{"Version", "2012-10-17"}, {"Statement", stmts}},
	}
}

func demoView(r PolicyDemoRow, now time.Time, withDocs bool) PolicyDemoView {
	v := PolicyDemoView{ID: r.ID, Name: r.Name, Description: r.Description, Agent: r.Agent, Identity: r.Identity,
		ResourceType: r.ResourceType, Resource: r.Resource, Prefix: r.Prefix, Actions: append([]string{}, r.Actions...),
		ProtectBucket: r.ProtectBucket, RequireTLS: r.RequireTLS, StartTime: r.StartTime, EndTime: r.EndTime, Paused: r.Paused,
		Phase: demoPhase(r, now), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if withDocs {
		v.Generated = demoGenerate(r)
	}
	return v
}

// PolicyDemoService is the demo's storage.
type PolicyDemoService struct {
	db  *gorm.DB
	now func() time.Time
}

func NewPolicyDemoService(db *gorm.DB) *PolicyDemoService {
	return &PolicyDemoService{db: db, now: time.Now}
}

func demoNotFound() *PolicyDemoError {
	return &PolicyDemoError{Status: http.StatusNotFound, Code: "not_found", Message: "That policy does not exist."}
}

// Preview validates in and returns what it would produce, storing nothing.
func (s *PolicyDemoService) Preview(in PolicyDemoInput) (*PolicyDemoView, error) {
	r, err := in.normalise()
	if err != nil {
		return nil, err
	}
	now := s.now()
	r.CreatedAt, r.UpdatedAt = now, now
	v := demoView(r, now, true)
	return &v, nil
}

// List returns the workspace's policies, newest first, filtered by a name or
// resource search and by phase.
func (s *PolicyDemoService) List(ws uuid.UUID, q, phase, resource string) ([]PolicyDemoView, error) {
	tx := s.db.Where("workspace_id = ?", ws)
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + strings.NewReplacer("%", `\%`, "_", `\_`).Replace(q) + "%"
		tx = tx.Where("(name ILIKE ? OR agent ILIKE ? OR resource ILIKE ? OR identity ILIKE ?)", like, like, like, like)
	}
	if resource != "" {
		tx = tx.Where("resource = ?", strings.ToLower(resource))
	}
	var rows []PolicyDemoRow
	if err := tx.Order("created_at DESC, id").Limit(500).Find(&rows).Error; err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]PolicyDemoView, 0, len(rows))
	for _, r := range rows {
		v := demoView(r, now, false)
		if phase != "" && v.Phase != phase {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *PolicyDemoService) load(ws, id uuid.UUID) (*PolicyDemoRow, error) {
	var r PolicyDemoRow
	if err := s.db.Where("workspace_id = ? AND id = ?", ws, id).Take(&r).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, demoNotFound()
		}
		return nil, err
	}
	return &r, nil
}

func (s *PolicyDemoService) Get(ws, id uuid.UUID) (*PolicyDemoView, error) {
	r, err := s.load(ws, id)
	if err != nil {
		return nil, err
	}
	v := demoView(*r, s.now(), true)
	return &v, nil
}

func (s *PolicyDemoService) Create(ws uuid.UUID, by *uuid.UUID, in PolicyDemoInput) (*PolicyDemoView, error) {
	r, err := in.normalise()
	if err != nil {
		return nil, err
	}
	r.WorkspaceID, r.CreatedBy = ws, by
	if err := s.db.Create(&r).Error; err != nil {
		return nil, err
	}
	v := demoView(r, s.now(), true)
	return &v, nil
}

func (s *PolicyDemoService) Update(ws, id uuid.UUID, in PolicyDemoInput) (*PolicyDemoView, error) {
	cur, err := s.load(ws, id)
	if err != nil {
		return nil, err
	}
	r, err := in.normalise()
	if err != nil {
		return nil, err
	}
	cur.Name, cur.Description, cur.Agent, cur.Identity, cur.ResourceType = r.Name, r.Description, r.Agent, r.Identity, r.ResourceType
	cur.Resource, cur.Prefix, cur.Actions, cur.ProtectBucket, cur.RequireTLS = r.Resource, r.Prefix, r.Actions, r.ProtectBucket, r.RequireTLS
	cur.StartTime, cur.EndTime, cur.UpdatedAt = r.StartTime, r.EndTime, s.now()
	if err := s.db.Save(cur).Error; err != nil {
		return nil, err
	}
	v := demoView(*cur, s.now(), true)
	return &v, nil
}

// SetPaused pauses or resumes a policy.
func (s *PolicyDemoService) SetPaused(ws, id uuid.UUID, paused bool) (*PolicyDemoView, error) {
	cur, err := s.load(ws, id)
	if err != nil {
		return nil, err
	}
	cur.Paused, cur.UpdatedAt = paused, s.now()
	if err := s.db.Save(cur).Error; err != nil {
		return nil, err
	}
	v := demoView(*cur, s.now(), true)
	return &v, nil
}

func (s *PolicyDemoService) Delete(ws, id uuid.UUID) error {
	res := s.db.Where("workspace_id = ? AND id = ?", ws, id).Delete(&PolicyDemoRow{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return demoNotFound()
	}
	return nil
}

// Seed adds three sample policies, one active, one scheduled and one expired,
// so a new workspace has something to look at. It adds nothing once the
// workspace has any policy.
func (s *PolicyDemoService) Seed(ws uuid.UUID, by *uuid.UUID) ([]PolicyDemoView, error) {
	var n int64
	if err := s.db.Model(&PolicyDemoRow{}).Where("workspace_id = ?", ws).Count(&n).Error; err != nil {
		return nil, err
	}
	if n > 0 {
		return s.List(ws, "", "", "")
	}
	now := s.now()
	t := func(d time.Duration) *time.Time { x := now.Add(d).Truncate(time.Minute); return &x }
	samples := []PolicyDemoInput{
		{Name: "Invoice reader for the finance agent", Description: "Lets the finance agent read invoices for the month-end close, then stops.",
			Agent: "finance-close-agent", Identity: "finance-agent-role", Resource: "finance-reports", Prefix: "invoices/", Actions: []string{"read"},
			StartTime: t(-2 * time.Hour), EndTime: t(22 * time.Hour)},
		{Name: "Data-lake loader (scheduled)", Description: "A weekend backfill: the loader may read and write raw data.",
			Agent: "my-agentic-ai", Identity: "my-privilege-account", Resource: "data-lake-raw", Prefix: "ingest/", Actions: []string{"read", "write"},
			StartTime: t(48 * time.Hour), EndTime: t(96 * time.Hour)},
		{Name: "Audit export (ended)", Description: "A one-day read of the archive for an audit that has finished.",
			Agent: "audit-helper", Identity: "audit-readonly", Resource: "compliance-archive", Actions: []string{"read"},
			StartTime: t(-72 * time.Hour), EndTime: t(-48 * time.Hour)},
	}
	for i := len(samples) - 1; i >= 0; i-- { // oldest first, so the newest is listed first
		if _, err := s.Create(ws, by, samples[i]); err != nil {
			return nil, err
		}
	}
	return s.List(ws, "", "", "")
}
