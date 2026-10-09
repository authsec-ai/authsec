package integration

// Shared plumbing for the T6.3 workload detail and tab tests (GET
// /workloads/:id, /identities, /resources): the P2-0 lab's REAL scan worker
// and projector, read through the REAL route table (p2_read_harness_test.go).
// Everything here is prefixed wdetail so it cannot collide with another
// stream's helpers in this package.

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"
)

// wdetailFn is one Lambda function of a fixture: its name, the role it runs
// as ("" for none) and its environment variable names. Each variable gets a
// value the collector must never keep (wdetailSecretValue).
type wdetailFn struct {
	name, role string
	env        []string
}

// wdetailSecretValue is every fixture environment variable's value: it must
// appear in no response and no stored row.
const wdetailSecretValue = "wdetail-secret-value-never-stored"

// wdetailFunctions makes a region's Lambda list exactly these functions --
// several in ONE region, which the lab's own lambda() cannot (B1: two
// workloads sharing one role come through the pipeline together).
func wdetailFunctions(a *p2Account, region string, fns ...wdetailFn) {
	f := a.lambdas[region]
	if f == nil {
		f = &fakeLambda{}
		a.lambdas[region] = f
	}
	f.functions = nil
	for _, fn := range fns {
		cfg := lambdatypes.FunctionConfiguration{
			FunctionArn:  aws.String("arn:aws:lambda:" + region + ":" + a.id + ":function:" + fn.name),
			FunctionName: aws.String(fn.name), Role: aws.String(fn.role), State: lambdatypes.StateActive,
		}
		if len(fn.env) > 0 {
			vars := map[string]string{}
			for _, k := range fn.env {
				vars[k] = wdetailSecretValue
			}
			cfg.Environment = &lambdatypes.EnvironmentResponse{Variables: vars}
		}
		f.functions = append(f.functions, cfg)
	}
}

// wdetailEnvironmentUnread makes ListFunctions return one function's
// environment as AWS does when Lambda cannot decrypt its variables with the
// function's KMS key: an error in place of the variables.
func wdetailEnvironmentUnread(a *p2Account, region, name string) {
	a.lab.t.Helper()
	for i, fn := range a.lambdas[region].functions {
		if aws.ToString(fn.FunctionName) == name {
			a.lambdas[region].functions[i].Environment = &lambdatypes.EnvironmentResponse{Error: &lambdatypes.EnvironmentError{
				ErrorCode: aws.String("KMSAccessDeniedException"),
				Message:   aws.String("Lambda was unable to decrypt the environment variables because KMS access was denied."),
			}}
			return
		}
	}
	a.lab.t.Fatalf("no Lambda function %q in %s", name, region)
}

// wdetailWorkload is the id of the workspace's workload of this name (the
// active one when a retired one shares the name).
func wdetailWorkload(t *testing.T, l *p2Lab, name string) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND display_name = ?
	          ORDER BY (lifecycle = 'active') DESC, created_at DESC`, l.ws, name).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("no workload named %q was projected", name)
	}
	return ids[0]
}

// wdetailIdentity is the id of the live AWS identity of this name.
func wdetailIdentity(t *testing.T, l *p2Lab, name string) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	          AND display_name = ? ORDER BY (lifecycle = 'active') DESC, created_at DESC`, l.ws, name).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("no identity named %q was projected", name)
	}
	return ids[0]
}

// wdetailGet calls a route and requires 200.
func wdetailGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, 200)
	return body
}

// wdetailPaths are the three routes of one workload.
func wdetailPaths(id string) []string {
	return []string{"/workloads/" + id, "/workloads/" + id + "/identities", "/workloads/" + id + "/resources"}
}

// wdetailJSON is a body as compact JSON, for failure messages and leak checks.
func wdetailJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// wdetailStrings is a JSON array of strings.
func wdetailStrings(v any) []string {
	var out []string
	for _, x := range wdetailSlice(v) {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func wdetailSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// wdetailSharedLab is E3/E5's slice through the pipeline: ticket-tools and
// refund-tools, two Lambda functions in ONE region, both running as
// SharedToolRole, which holds TicketRead (Sid ReadTickets) and ToolboxRead
// (no Sid) -- both allowing s3:GetObject on arn:aws:s3:::support-tickets/*.
func wdetailSharedLab(t *testing.T, name string) (*p2Lab, *p2Account) {
	t.Helper()
	l := newP2Lab(t, name, true)
	return l, wdetailShared(l)
}

// wdetailShared builds wdetailSharedLab's account in an existing lab and
// scans it. Tests with several labs create them ALL before the first scan:
// each lab clears the shared run table when it is created.
func wdetailShared(l *p2Lab) *p2Account {
	l.t.Helper()
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROAWDETAILSHARED001")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	a.attach("SharedToolRole", a.managed("ToolboxRead", docToolboxRead))
	wdetailFunctions(a, "us-east-1",
		wdetailFn{name: "ticket-tools", role: role, env: []string{"TICKET_QUEUE", "LOG_LEVEL"}},
		wdetailFn{name: "refund-tools", role: role})
	l.scanAndProject(a)
	return a
}
