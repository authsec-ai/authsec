package integration

// T6.10 follow-ups: the read-path changes the §5.6 measurement made, each held
// to the behaviour it must keep (the load test in tests/load holds them to
// their speed).
//
//   - Reader.Read plans every statement with its own bind values
//     (plan_cache_mode = force_custom_plan) and never JIT-compiles one
//     (jit = off), for its transaction only.
//   - The workload q's provider-id arm tests the ARN's suffix before the two
//     regular expressions that extract the id: still an EXACT, case-sensitive
//     match of the whole id (D-76), never a suffix match.
//   - The Evidence panel reads every target's resource policy in ONE statement
//     (ResourcePoliciesOf) and still decides each text by its own
//     observations (D-19).

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// §5.6 / T6.10: inside a read every statement is planned with its bind values
// -- a generic plan chosen for a typical object is ruinous for "*" or a hub
// role -- and never JIT-compiled (hundreds of milliseconds of compilation for
// a statement the planner merely costs high); and only inside it: set as
// SET LOCAL, so the pooled connection is handed back as it was. One
// connection, so "after" is the same session as "inside".
//
// Safeguards (mutation-checked): each setting inside Read; LOCAL on them.
func TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead(t *testing.T) {
	l := newP2Lab(t, "p2-load-plan-cache", true)
	l.scanAndProject(oneLambda(l))

	db, err := gorm.Open(postgres.Open(os.Getenv("IGA_TEST_DSN")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	pool.SetMaxOpenConns(1)
	defer pool.Close()

	// The settings a read must run under, and the value each must have.
	want := map[string]string{"plan_cache_mode": "force_custom_plan", "jit": "off"}
	show := func(tx *gorm.DB) map[string]string {
		out := map[string]string{}
		for name := range want {
			var v string
			if err := tx.Raw(`SHOW ` + name).Row().Scan(&v); err != nil {
				t.Fatalf("show %s: %v", name, err)
			}
			out[name] = v
		}
		return out
	}
	before := show(db)
	for name, v := range want {
		if before[name] == v {
			t.Fatalf("fixture: the server default of %s is already %s; the test proves nothing", name, v)
		}
	}
	r := igaread.NewReader(db, []byte("k"))
	var inside, optional map[string]string
	if err := r.Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		inside = show(q.DB())
		// Optional work runs in a savepoint: the settings hold there too.
		_, err := q.Optional(func(tx *gorm.DB) error { optional = show(tx); return nil })
		return err
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	for name, v := range want {
		if inside[name] != v || optional[name] != v {
			t.Errorf("%s inside the read = %q, in its optional work %q; want %q in both", name, inside[name], optional[name], v)
		}
	}
	after := show(db)
	for name := range want {
		if after[name] != before[name] {
			t.Errorf("%s on the pooled connection after the read = %q, want %q: the read must not change the session",
				name, after[name], before[name])
		}
	}
}

// D-76 over a workload whose provider id is not in its name: an EC2 instance
// (its id i-..., its Name tag the display name) and a Bedrock agent (its id,
// its name). q equal to the id finds the object; a proper suffix of the id, a
// longer tail of the ARN, and the id in another case do not -- the arm is an
// exact, case-sensitive match of the whole id however it is evaluated.
//
// Safeguards (mutation-checked): the suffix pre-test is right(), not left();
// the full provider-id equality still follows it.
func TestP2LoadWorkloadQMatchesTheWholeProviderID(t *testing.T) {
	l := newP2Lab(t, "p2-load-q-provider-id", true)
	a := l.account(accountA)
	role := a.role("load-host-role", "AROALOADHOSTROLE0001")
	a.lambda("us-east-1", "load-fn", role)
	agentARN := "arn:aws:bedrock:us-east-1:" + a.id + ":agent/LOADAGENT1"
	f := &s3bFakes{
		ec2: &fakeEC2{instances: []ec2types.Instance{{InstanceId: aws.String("i-0load0provider01"),
			Tags:  []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("billing-host")}},
			State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}}}},
		bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"LOADAGENT1": {
			AgentId: aws.String("LOADAGENT1"), AgentArn: aws.String(agentARN), AgentName: aws.String("support-bot"),
			AgentResourceRoleArn: aws.String(role),
		}}},
	}
	s3bScanAndProject(l, a, f)
	api := l.api()

	names := func(q string) []string {
		code, body := api.get("/workloads" + qs("q", q))
		mustStatus(t, "workloads q="+q, code, body, http.StatusOK)
		var out []string
		for _, row := range digl(body, "data") {
			out = append(out, digs(row, "name"))
		}
		return out
	}
	// The fixture: the ids are in no display name, so only the exact arm can
	// match them.
	all := names("")
	if !listsSameSet(all, []string{"billing-host", "support-bot", "load-fn"}) {
		t.Fatalf("fixture: workloads = %v, want billing-host, support-bot, load-fn", all)
	}
	for _, c := range []struct {
		q    string
		want []string
	}{
		{"i-0load0provider01", []string{"billing-host"}},
		{"LOADAGENT1", []string{"support-bot"}},
		{"load0provider01", nil},             // a proper suffix of the id
		{"instance/i-0load0provider01", nil}, // a longer tail of the ARN
		{"agent/LOADAGENT1", nil},            // the same, for the agent
		{"I-0LOAD0PROVIDER01", nil},          // exact is case-sensitive
		{"loadagent1", nil},                  // ... and so is this one
		{"load-fn", []string{"load-fn"}},     // the name arm, for contrast
	} {
		if got := names(c.q); !listsSameSet(got, c.want) {
			t.Errorf("q=%q = %v, want %v", c.q, got, c.want)
		}
	}
}

// D-19 per text, batched: a grouped Evidence request whose grants name two
// buckets -- one whose policy the published run read, one whose read was
// denied -- marks resource_policy_not_projected on the first grant only, with
// that bucket alone, exactly as each grant's own request does. Two scans move
// the read bucket's policy from a Deny to none, so its newest observation is
// the one resource_policy reports.
//
// Safeguard (mutation-checked): each text is decided by its own candidates
// (the batch is split by subject).
func TestP2LoadGroupedEvidenceReadsEachTargetsOwnResourcePolicy(t *testing.T) {
	l := newP2Lab(t, "p2-load-grouped-resource-policy", true)
	a := l.account(accountA)
	a.role("BucketRole", "AROALOADBUCKETROLE01")
	a.attach("BucketRole", a.managed("TwoBuckets", evidenceDoc(
		`{"Sid":"ListRead","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::load-read-bucket"}`,
		`{"Sid":"ListDenied","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::load-denied-bucket"}`)))
	withDeny := evidenceDoc(`{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"*"}`)
	withoutDeny := evidenceDoc(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + a.id + `:root"},` +
		`"Action":"s3:ListBucket","Resource":"arn:aws:s3:::load-read-bucket"}`)
	// Only load-read-bucket has a policy the fake answers; the other read is
	// denied (fakeS3Policy).
	evidenceCycle(l, a, evidenceFakes{bucketPolicies: map[string]string{"load-read-bucket": withDeny}})
	evidenceCycle(l, a, evidenceFakes{bucketPolicies: map[string]string{"load-read-bucket": withoutDeny}})
	api := l.api()

	read := evidenceGrant(t, l, "BucketRole", "TwoBuckets", "ListRead")
	denied := evidenceGrant(t, l, "BucketRole", "TwoBuckets", "ListDenied")
	readBucket := loadResourceID(t, l, "arn:aws:s3:::load-read-bucket")
	deniedBucket := loadResourceID(t, l, "arn:aws:s3:::load-denied-bucket")

	// Each resource on its own (ResourcePolicyOf): read with the newest
	// observation's verdict, and not read.
	for _, c := range []struct {
		id      uuid.UUID
		read    bool
		hasDeny any
	}{{readBucket, true, false}, {deniedBucket, false, nil}} {
		code, body := api.get("/resources/" + c.id.String())
		mustStatus(t, "resource "+c.id.String(), code, body, http.StatusOK)
		if dig(body, "data", "resource_policy", "read") != c.read || dig(body, "data", "resource_policy", "has_deny") != c.hasDeny {
			t.Errorf("resource %s resource_policy = %v, want read %v, has_deny %v", c.id, dig(body, "data", "resource_policy"), c.read, c.hasDeny)
		}
	}

	// Each grant on its own.
	want := map[string][]string{read: {refOf("resource", readBucket)}, denied: nil}
	for claim, resources := range want {
		lim := evidenceLim(evidenceGet(t, api, claim), "resource_policy_not_projected")
		if got := loadLimResources(lim); !listsSameSet(got, resources) {
			t.Errorf("%s alone: resource_policy_not_projected resources = %v, want %v", claim, got, resources)
		}
	}

	// Both in one request (D-79): the same answer per grant, in request order.
	for _, order := range [][]string{{read, denied}, {denied, read}} {
		code, body := api.get("/evidence" + qs("claim", order[0], "claim", order[1]))
		mustStatus(t, "grouped evidence", code, body, http.StatusOK)
		items := digl(body, "data")
		if len(items) != 2 {
			t.Fatalf("grouped evidence data = %v, want two items", dig(body, "data"))
		}
		for i, claim := range order {
			lim := evidenceLim(map[string]any{"data": items[i]}, "resource_policy_not_projected")
			if got := loadLimResources(lim); !listsSameSet(got, want[claim]) {
				t.Errorf("grouped %v, item %d (%s): resource_policy_not_projected resources = %v, want %v",
					order, i, claim, got, want[claim])
			}
		}
	}
}

// loadResourceID is the id of the workspace's resource with a display name.
func loadResourceID(t *testing.T, l *p2Lab, text string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_resources WHERE workspace_id = ? AND display_name = ?`, l.ws, text).
		Row().Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			t.Fatalf("fixture: no resource %s", text)
		}
		t.Fatalf("resource %s: %v", text, err)
	}
	return id
}

// loadLimResources is a limitation's resources list (nil for no limitation).
func loadLimResources(lim map[string]any) []string {
	if lim == nil {
		return nil
	}
	var out []string
	for _, r := range digl(lim, "resources") {
		out = append(out, r.(string))
	}
	return out
}
