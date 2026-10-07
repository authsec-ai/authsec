package igagov

import (
	"errors"
	"strings"
	"testing"
)

// §2.7's example intent, with real-shaped ids.
const specIntent = `{
  "kind": "right_size_services",
  "subjects": [{ "identity_account_id": "c41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "role_id": "AROAEXAMPLEREFUND01", "account_id": "429418377036" }],
  "retain": [
    { "service": "s3",       "basis": "observed",   "last_attempt": "2026-09-28T10:02:00Z" },
    { "service": "logs",     "basis": "dependency", "catalog": "ecs-task-execution@1" },
    { "service": "dynamodb", "basis": "owner",      "reason": "quarterly reconciliation job", "review_by": "2027-01-15" },
    { "service": "glue",     "basis": "unreviewed", "reason": "granted but absent from the activity report" }
  ],
  "remove": [
    { "service": "ec2", "basis": "no_attempt", "qualified_days": 112, "grant_age_basis": "observed_since_change" },
    { "service": "sqs", "basis": "no_attempt", "qualified_days": 112, "grant_age_basis": "predates_observation",
      "route_usage": "confirm_required", "route_state": "bypass_known",
      "routes": [{ "resource": "arn:aws:sqs:us-east-1:429418377036:refunds", "principal": "role_session" }] }
  ],
  "observation_days": 7,
  "rollout": { "canary_target": "AROAEXAMPLEREFUND01", "canary_hours": 48 },
  "delivery": "direct",
  "finding_ids": ["0f0e0d0c-0b0a-4908-8706-050403020100"],
  "evidence_rev": 812
}`

const specRemoveControl = `{ "kind": "remove_control", "control_ids": ["6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11"], "reason": "decommissioning" }`

const specDedicated = `{
  "kind": "dedicated_identity",
  "source": { "identity_account_id": "c41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "role_id": "AROAEXAMPLEREFUND01", "account_id": "429418377036" },
  "workload": { "workload_id": "a17d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "binding_kind": "ecs_task_role",
                "binding_ref": "arn:aws:ecs:us-east-1:429418377036:service/payments/refund-reconciler" },
  "new_role": {
    "name": "refund-reconciler-role", "path": "/",
    "trust_policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "managed_policy_arns": ["arn:aws:iam::429418377036:policy/RefundAccess"],
    "inline_policies": [{ "name": "refund-inline", "document_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111" }],
    "boundary_arn": "arn:aws:iam::429418377036:policy/TeamBoundary"
  },
  "delivery": "iac_pr"
}`

func TestParseIntent_SpecExamples(t *testing.T) {
	for name, raw := range map[string]string{"right_size": specIntent, "remove_control": specRemoveControl, "dedicated": specDedicated} {
		in, err := ParseIntent([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c, h, err := CanonicalIntent(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		h2, err := IntentHash([]byte(raw))
		if err != nil || h != h2 {
			t.Fatalf("%s: typed and raw intent hashes differ (%v)", name, err)
		}
		if _, err := ParseIntent(c); err != nil {
			t.Fatalf("%s: canonical intent does not re-parse: %v", name, err)
		}
	}
}

func mutateIntent(t *testing.T, raw string, edit func(*RightSizeIntent)) error {
	t.Helper()
	in, err := ParseIntent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	cp := *in.RightSize
	cp.Subjects = append([]Subject{}, cp.Subjects...)
	cp.Retain = append([]RetainEntry{}, cp.Retain...)
	cp.Remove = append([]RemoveEntry{}, cp.Remove...)
	edit(&cp)
	return ValidateIntent(Intent{Kind: cp.Kind, RightSize: &cp})
}

func TestValidateIntent_RightSizeRules(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*RightSizeIntent)
		field string
	}{
		{"no subjects", func(r *RightSizeIntent) { r.Subjects = nil }, "subjects"},
		{"bad role id", func(r *RightSizeIntent) { r.Subjects[0].RoleID = "RefundTaskRole" }, "subjects[0].role_id"},
		{"bad account", func(r *RightSizeIntent) { r.Subjects[0].AccountID = "4294" }, "subjects[0].account_id"},
		{"duplicate subject", func(r *RightSizeIntent) { r.Subjects = append(r.Subjects, r.Subjects[0]) }, "subjects[1].role_id"},
		{"retain and remove", func(r *RightSizeIntent) {
			r.Retain = append(r.Retain, RetainEntry{Service: "sqs", Basis: RetainUnreviewed})
		}, "remove[1].service"},
		{"owner retain without review date", func(r *RightSizeIntent) { r.Retain[2].ReviewBy = "" }, "retain[2].review_by"},
		{"owner retain without reason", func(r *RightSizeIntent) { r.Retain[2].Reason = " " }, "retain[2].reason"},
		{"unknown dependency context", func(r *RightSizeIntent) { r.Retain[1].Catalog = "made-up@1" }, "retain[1].catalog"},
		{"observed without last attempt", func(r *RightSizeIntent) { r.Retain[0].LastAttempt = "" }, "retain[0].last_attempt"},
		{"bad retain basis", func(r *RightSizeIntent) { r.Retain[3].Basis = "maybe" }, "retain[3].basis"},
		{"removal under 30 days", func(r *RightSizeIntent) { r.Remove[0].QualifiedDays = 29 }, "remove[0].qualified_days"},
		{"unknown grant age removed", func(r *RightSizeIntent) { r.Remove[0].GrantAgeBasis = GrantAgeUnknown }, "remove[0].grant_age_basis"},
		{"bad remove basis", func(r *RightSizeIntent) { r.Remove[0].Basis = "owner" }, "remove[0].basis"},
		{"service namespace shape", func(r *RightSizeIntent) { r.Remove[0].Service = "EC2" }, "remove[0].service"},
		{"none_observed with bypass", func(r *RightSizeIntent) { r.Remove[1].RouteUsage = RouteUsageNoneObserved }, "remove[1].route_state"},
		{"route state without routes", func(r *RightSizeIntent) { r.Remove[1].Routes = nil }, "remove[1].routes"},
		{"route principal", func(r *RightSizeIntent) { r.Remove[1].Routes[0].Principal = "role" }, "remove[1].routes[0].principal"},
		{"nothing removed", func(r *RightSizeIntent) { r.Remove = nil }, "remove"},
		{"observation days", func(r *RightSizeIntent) { r.ObservationDays = 91 }, "observation_days"},
		{"canary not a subject", func(r *RightSizeIntent) { r.Rollout.CanaryTarget = "AROAOTHER0000000" }, "rollout.canary_target"},
		{"canary hours", func(r *RightSizeIntent) { r.Rollout.CanaryHours = 337 }, "rollout.canary_hours"},
		{"delivery", func(r *RightSizeIntent) { r.Delivery = "email" }, "delivery"},
		{"finding id", func(r *RightSizeIntent) { r.FindingIDs = []string{"x"} }, "finding_ids[0]"},
		{"evidence rev", func(r *RightSizeIntent) { r.EvidenceRev = 0 }, "evidence_rev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := mutateIntent(t, specIntent, func(r *RightSizeIntent) {
				ro := *r.Rollout
				r.Rollout = &ro
				r.Remove[1].Routes = append([]IntentRoute{}, r.Remove[1].Routes...)
				c.edit(r)
			})
			var ie IntentErrors
			if !errors.As(err, &ie) {
				t.Fatalf("want IntentErrors, got %v", err)
			}
			found := false
			for _, e := range ie {
				if e.Field == c.field {
					found = true
				}
			}
			if !found {
				t.Fatalf("no error on %s: %v", c.field, ie)
			}
		})
	}
}

func TestParseIntent_Refusals(t *testing.T) {
	cases := map[string]string{
		"unknown member": strings.Replace(specRemoveControl, `"reason"`, `"surprise": 1, "reason"`, 1),
		"unknown kind":   `{"kind":"grant_everything"}`,
		"not json":       `{"kind":`,
		"duplicate key":  `{"kind":"remove_control","kind":"remove_control","control_ids":[],"reason":"x"}`,
		"no reason":      `{"kind":"remove_control","control_ids":["6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11"],"reason":""}`,
		"dup controls":   `{"kind":"remove_control","control_ids":["6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11","6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11"],"reason":"x"}`,
		"split direct":   strings.Replace(specDedicated, `"delivery": "iac_pr"`, `"delivery": "direct"`, 1),
		"split binding":  strings.Replace(specDedicated, `"ecs_task_role"`, `"eks_pod_identity"`, 1),
		"split path":     strings.Replace(specDedicated, `"path": "/"`, `"path": "no-slash"`, 1),
		"split hash":     strings.Replace(specDedicated, `"sha256:0000`, `"md5:0000`, 1),
	}
	for name, raw := range cases {
		if _, err := ParseIntent([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateIntent(Intent{Kind: IntentRightSizeServices}); err == nil {
		t.Error("kind without body accepted")
	}
}
