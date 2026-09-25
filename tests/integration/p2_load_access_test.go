package integration

// T6.10: Resource › Access finds its page of holders grant-first, or
// identity-first for a reference named by very many statements ("*"). The
// switch is a plan choice (igaread rdetailAccessDenseAt), so both strategies
// must give every reference the same pages -- through the lab's REAL scans
// and projections, over each state D-18 distinguishes: a role's own grant, a
// group's grant expanded to its members, a member who left (ended with
// include_ended), a grant that began after the member left (never his), a
// detached policy's ended grant, and that ended grant BESIDE a current one of
// the same holder on the same reference (the default page lists the holder,
// and must still leave the ended row out).

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// Safeguards (mutation-checked): the identity-first page's direct probe, its
// member probe, the membership overlap on its member rows, its states on the
// membership, its states on a listed holder's direct rows, and its cursor
// predicate.
func TestP2LoadAccessStrategiesAgreeOnTheLab(t *testing.T) {
	l := newP2Lab(t, "p2-load-access-strategies", true)
	a := l.account(accountA)
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aUser(a, "bob", "AIDABOBBOBBOBBOBBOB1")
	s3aUser(a, "carol", "AIDACAROLCAROLCAROL1")
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	opsRead := a.managed("OpsRead", `{"Version":"2012-10-17","Statement":[{"Sid":"OpsRead",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::ops-bucket/*","*"]}]}`)
	s3aGroupAttach(t, a, "ops", opsRead)
	a.role("deployer", "AROADEPLOYERDEPLOYE1")
	a.attach("deployer", opsRead)
	// deployer also reaches "*" through a policy of its own, which it keeps
	// when OpsRead is detached below: then it holds an ended and a current
	// grant on "*" -- a holder the default page lists, beside a row it must
	// not. (Only "*": ops-bucket/*'s five rows stay as they are.)
	a.attach("deployer", changesManaged(a, "DeployWide", `{"Version":"2012-10-17","Statement":[{"Sid":"DeployWide",`+
		`"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`))
	a.role("auditor", "AROAAUDITORAUDITORA1")
	a.attach("auditor", opsRead)
	a.iam.userGroups["priya"] = []string{"ops"}
	a.iam.userGroups["bob"] = []string{"ops"}
	l.scanAndProject(a)

	compare := func(stage string) {
		t.Helper()
		var ids []uuid.UUID
		if err := l.db.Raw(`SELECT id FROM iga_resources WHERE workspace_id = ? ORDER BY id`, l.ws).Scan(&ids).Error; err != nil {
			t.Fatalf("resources: %v", err)
		}
		if len(ids) == 0 {
			t.Fatalf("%s: fixture has no resources", stage)
		}
		grantFirst := igaread.NewReader(l.db, []byte("load-access")).WithAccessDenseAt(1 << 30)
		identityFirst := igaread.NewReader(l.db, []byte("load-access")).WithAccessDenseAt(1)
		for _, id := range ids {
			for _, ended := range []string{"", "true"} {
				for _, limit := range []int{1, 2, 100} {
					want := loadAccessWalk(t, grantFirst, l.ws, id, ended, limit)
					got := loadAccessWalk(t, identityFirst, l.ws, id, ended, limit)
					if len(want) != len(got) {
						t.Errorf("%s: resource %s include_ended=%q limit %d: grant-first %d pages, identity-first %d:\n%v\n%v",
							stage, id, ended, limit, len(want), len(got), want, got)
						continue
					}
					for i := range want {
						if want[i] != got[i] {
							t.Errorf("%s: resource %s include_ended=%q limit %d page %d:\ngrant-first    %s\nidentity-first %s",
								stage, id, ended, limit, i+1, want[i], got[i])
						}
					}
				}
			}
		}
	}
	// The member rows must be there to be compared.
	if n := len(digl(rdetailGet(t, l.api(), "/resources/"+rdetailResource(t, l, "arn:aws:s3:::ops-bucket/*")+"/access"),
		"data", "access")); n != 5 {
		t.Fatalf("fixture: ops-bucket/* has %d access rows, want 5 (auditor, deployer, ops, and ops's members bob and priya)", n)
	}
	compare("group, members and roles")

	// bob leaves ops; deployer's attachment is removed (its grant ends).
	a.iam.userGroups["bob"] = nil
	a.detach("deployer", opsRead)
	l.scanAndProject(a)
	// The state that makes the direct rows' state filter matter must be there:
	// on "*" deployer is listed by default with DeployWide's current row only,
	// and include_ended adds OpsRead's ended one.
	star := "/resources/" + rdetailResource(t, l, "*") + "/access"
	for _, c := range []struct {
		query string
		want  map[string]string // policy name -> row state
	}{
		{"", map[string]string{"DeployWide": "current"}},
		{"?include_ended=true", map[string]string{"DeployWide": "current", "OpsRead": "ended"}},
	} {
		got := map[string]string{}
		for _, row := range digl(rdetailGet(t, l.api(), star+c.query), "data", "access") {
			if digs(row, "holder", "name") == "deployer" {
				got[digs(row, "policy", "name")] = digs(row, "state")
			}
		}
		if len(got) != len(c.want) || got["DeployWide"] != c.want["DeployWide"] || got["OpsRead"] != c.want["OpsRead"] {
			t.Fatalf("fixture: deployer's rows on \"*\"%s = %v, want %v", c.query, got, c.want)
		}
	}
	compare("a member left, a policy detached")

	// A grant that begins after bob left never reaches him -- on later-bucket/*,
	// where he holds nothing else, and on "*", where OpsRead (whose period his
	// membership overlapped) keeps him a holder beside it.
	s3aGroupAttach(t, a, "ops", a.managed("LaterRead", `{"Version":"2012-10-17","Statement":[{"Sid":"LaterRead",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::later-bucket/*","*"]}]}`))
	l.scanAndProject(a)
	compare("a grant after the member left")
}

// loadAccessWalk reads every page of one reference's Access through r and
// renders each as JSON.
func loadAccessWalk(t *testing.T, r *igaread.Reader, ws, id uuid.UUID, includeEnded string, limit int) []string {
	t.Helper()
	var pages []string
	cursor := ""
	for n := 0; n < 100; n++ {
		vals := url.Values{"limit": {strconv.Itoa(limit)}}
		if includeEnded != "" {
			vals.Set("include_ended", includeEnded)
		}
		if cursor != "" {
			vals.Set("cursor", cursor)
		}
		out, err := r.ResourceAccess(context.Background(), ws, id.String(), vals)
		if err != nil {
			t.Fatalf("access %s: %v", id, err)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		pages = append(pages, string(raw))
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if cursor = digs(body, "meta", "next_cursor"); cursor == "" {
			return pages
		}
	}
	t.Fatalf("access %s did not end within 100 pages", id)
	return nil
}
