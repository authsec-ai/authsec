package integration

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

// fix/p3-tidy item 5: POST /proposals' recommendation reads the role's open
// unused_service findings the proposal addresses. A database error on that
// read used to be discarded (`_ = a.db.Raw(...)`), so the proposal was
// created WITHOUT its finding_ids. It is now an error: nothing is created.
// The fault is injected on that one statement of the real service path.
func TestP3TidyRecommendPropagatesDBError(t *testing.T) {
	l := newP3aLab(t, "p3-tidy-recommend")
	l.role("RecommendRole", "AROARECOMMEND01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()

	const name = "p3tidy:fail_recommend_findings"
	if err := l.db.Callback().Row().Before("gorm:row").Register(name, func(d *gorm.DB) {
		q := d.Statement.SQL.String()
		if strings.Contains(q, "FROM iga_gov_finding") && strings.Contains(q, "detail_key IN") {
			_ = d.AddError(errors.New("injected: the findings read failed"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	removed := false
	remove := func() {
		if !removed {
			removed = true
			_ = l.db.Callback().Row().Remove(name)
		}
	}
	defer remove()

	keys := []map[string]any{{"provider": "aws", "role_id": "AROARECOMMEND01"}}
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services", "keys": keys})
	if code < 500 {
		t.Fatalf("proposal with a failed findings read: %d %v, want a server error (never a proposal without its findings)", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_policy WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d policies created from a failed read", n)
	}

	// Without the fault the same proposal names the sqs finding it addresses.
	remove()
	code, body = l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services", "keys": keys})
	d := l.must(code, body, http.StatusCreated, "POST /proposals")
	intent, _ := d["version"].(map[string]any)["intent"].(map[string]any)
	if ids, _ := intent["finding_ids"].([]any); len(ids) == 0 {
		t.Fatalf("the proposal names no finding: %v", intent)
	}
}
