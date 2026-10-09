package integration

import (
	"context"
	"database/sql"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/services"
)

// fix/p3-tidy item 4a (§2.2 "a role recreated with the same name has a new
// RoleId and is a new subject"; §2.12 "reads by key through immutable_key"):
// a role is deleted and recreated under the same ARN, and the next scan has
// collected the new RoleId but no publication has projected it yet. The
// graph's live row at that ARN is still the OLD incarnation. Resolving by
// ARN (and by the old RoleId, and by the old identity's object id) must not
// return it: not_found role_recreated. Once a publication projects the new
// incarnation, the ARN resolves to it.
func TestP3TidyResolveByARNNeverReturnsTheOldIncarnation(t *testing.T) {
	l := newP3eLab(t, "p3-tidy-recreated")
	a := l.account(accountA)
	arn := p3eOldRole(a, "TidyRecreatedRole", "AROATIDYOLD0001", 200*24*time.Hour, "TidyRecreatedWork", p3eSQSS3)
	a.lambda("us-east-1", "tidy-recreated", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})
	l.cycle(a, nil)
	oldID := bdbIdentity(t, l.p2Lab, "TidyRecreatedRole")
	api := l.api()
	resolve := func() []map[string]any {
		t.Helper()
		code, body := api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{
			{"provider": "aws", "account_id": accountA, "role_arn": arn},
			{"provider": "aws", "role_id": "AROATIDYOLD0001"},
			{"object_id": oldID.String()},
		}})
		if code != http.StatusOK {
			t.Fatalf("resolve: %d %v", code, body)
		}
		return p3eList(body)
	}
	for i, r := range resolve() {
		id, _ := r["identity"].(map[string]any)
		if r["status"] != services.TargetResolved || id["role_id"] != "AROATIDYOLD0001" {
			t.Fatalf("key %d before the recreation: %v", i, r)
		}
	}

	// Delete + recreate under the same name; the scan collects the new
	// RoleId, the graph is not re-projected yet.
	a.role("TidyRecreatedRole", "AROATIDYNEW0001")
	l.scanOnly(a)
	for i, r := range resolve() {
		if r["status"] != services.TargetNotFound || r["reason"] != services.TargetReasonRoleRecreated || r["identity"] != nil {
			t.Fatalf("key %d after the recreation, before publication: %v, want not_found role_recreated (never the old incarnation)", i, r)
		}
	}

	// The publication projects the new incarnation: the ARN resolves to it.
	l.projectOnly()
	code, body := api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{
		{"provider": "aws", "account_id": accountA, "role_arn": arn}, {"provider": "aws", "role_id": "AROATIDYOLD0001"}}})
	res := p3eList(body)
	if code != http.StatusOK || len(res) != 2 {
		t.Fatalf("resolve after publication: %d %v", code, body)
	}
	if id, _ := res[0]["identity"].(map[string]any); res[0]["status"] != services.TargetResolved || id["role_id"] != "AROATIDYNEW0001" ||
		id["id"] == oldID.String() {
		t.Fatalf("ARN after publication: %v, want the new incarnation", res[0])
	}
	if res[1]["status"] != services.TargetNotFound {
		t.Fatalf("the old RoleId after publication: %v, want not_found", res[1])
	}
}

// txCountingPool is the lab's *sql.DB with a count of repeatable-read
// transactions begun through it (gorm begins every transaction through
// BeginTx; a nested one is a savepoint and never reaches it).
type txCountingPool struct {
	*sql.DB
	rr atomic.Int64
}

func (p *txCountingPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if opts != nil && opts.Isolation == sql.LevelRepeatableRead {
		p.rr.Add(1)
	}
	return p.DB.BeginTx(ctx, opts)
}

// fix/p3-tidy item 4b: 50 keys are answered from ONE repeatable-read
// snapshot, not one per key (each describe used to open its own snapshot
// transaction for the evidence build). Real resolver, real PostgreSQL; the
// pool only counts.
func TestP3TidyResolveFiftyKeysUsesOneSnapshot(t *testing.T) {
	l := newP3eLab(t, "p3-tidy-fifty")
	a := l.account(accountA)
	type role struct{ name, id, arn string }
	var roles []role
	for _, r := range []struct{ name, id string }{
		{"TidyFiftyA", "AROATIDYFIFTYA1"}, {"TidyFiftyB", "AROATIDYFIFTYB1"}, {"TidyFiftyC", "AROATIDYFIFTYC1"},
		{"TidyFiftyD", "AROATIDYFIFTYD1"}, {"TidyFiftyE", "AROATIDYFIFTYE1"},
	} {
		arn := p3eOldRole(a, r.name, r.id, 200*24*time.Hour, r.name+"Work", p3eSQSS3)
		a.lambda("us-east-1", r.name+"-fn", arn)
		l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})
		roles = append(roles, role{r.name, r.id, arn})
	}
	l.cycle(a, nil)
	var keys []services.TargetKey
	for len(keys) < services.MaxTargetKeys {
		for _, r := range roles {
			keys = append(keys, services.TargetKey{Provider: "aws", AccountID: accountA, RoleARN: r.arn},
				services.TargetKey{Provider: "aws", RoleID: r.id})
		}
	}
	keys = keys[:services.MaxTargetKeys]
	if err := services.ValidateTargetKeys(keys); err != nil {
		t.Fatal(err)
	}

	raw, err := l.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool := &txCountingPool{DB: raw}
	counted, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	res, err := services.NewGovTargets(counted).Resolve(context.Background(), l.ws, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != services.MaxTargetKeys {
		t.Fatalf("%d answers for %d keys", len(res), services.MaxTargetKeys)
	}
	for i, r := range res {
		if r.Status != services.TargetResolved || r.Identity == nil || r.Evidence == nil || r.Evidence.PublishedRev == nil {
			t.Fatalf("key %d: %+v, want resolved with its evidence", i, r)
		}
		want := keys[i].RoleID
		if want == "" {
			for _, ro := range roles {
				if ro.arn == keys[i].RoleARN {
					want = ro.id
				}
			}
		}
		if r.Identity.RoleID != want {
			t.Fatalf("key %d resolved to %s, want %s", i, r.Identity.RoleID, want)
		}
	}
	if n := pool.rr.Load(); n != 1 {
		t.Fatalf("%d repeatable-read snapshots for %d keys, want 1", n, services.MaxTargetKeys)
	}
}
