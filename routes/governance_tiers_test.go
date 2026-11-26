package routes

import (
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/services"
)

// W5: every write route of the tiered surfaces, as SetupIGARoutes mounts
// them in production, has a tier; every route the tier table names is
// mounted (no stale entry); every action the table names is in the tier map.
func TestEveryTieredWriteRouteHasATier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Mounting needs the auth configuration, never a request.
	t.Setenv("JWT_SDK_SECRET", "tier-test-sdk-secret")
	t.Setenv("JWT_DEF_SECRET", "tier-test-def-secret")
	eng := gin.New()
	ctl := platformCtrl.NewIGAGraphReadControllerWith(nil, services.NewGraphProjectionGate(false), []byte("tier-test-cursor-key-32-bytes!!!"))
	SetupIGARoutes(eng, platformCtrl.NewIGAController(nil), ctl)

	table := services.GovRouteTable()
	mounted := map[string]bool{}
	var missing []string
	writes := 0
	for _, r := range eng.Routes() {
		key := r.Method + " " + r.Path
		mounted[key] = true
		if !services.GovInTieredSurface(r.Path) || !services.GovIsWriteMethod(r.Method) {
			continue
		}
		writes++
		action, ok := services.GovRouteAction(r.Method, r.Path)
		if !ok {
			missing = append(missing, key)
			continue
		}
		if _, ok := services.GovActionFor(action); !ok {
			t.Errorf("%s maps to %q, which has no tier", key, action)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("write routes of the tiered surfaces without a tier:\n  %s", strings.Join(missing, "\n  "))
	}
	var stale []string
	for key := range table {
		if !mounted[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("tier table names routes that are not mounted:\n  %s", strings.Join(stale, "\n  "))
	}
	if writes < 90 {
		t.Fatalf("found only %d tiered write routes; the walk is not seeing the surfaces", writes)
	}
	for name, a := range services.GovActionTable() {
		if a.Tier < services.GovTier0 || a.Tier > services.GovTier4 {
			t.Errorf("%s: tier %d out of range", name, a.Tier)
		}
		if a.LoosensTo != 0 && a.LoosensTo <= a.Tier {
			t.Errorf("%s: loosens to tier %d, not above its tier %d", name, a.LoosensTo, a.Tier)
		}
	}
	// The anchors of the spec's tiers.
	for name, want := range map[string]services.GovTier{
		"agent_case.close": 0, "agent_case.export": 0, "agent_containment.create": 1, "agent_case.open": 1,
		services.GovActionContainIdentity: 2, "agent_alert.suppression.request": 3, "coverage.gap.declare": 3,
		"history.export.bulk": 3, "history.hold.release": 3, "pending_change.approve": 3,
		services.GovActionRemediationApply: 4,
	} {
		if a, _ := services.GovActionFor(name); a.Tier != want {
			t.Errorf("%s: tier %d, want %d", name, a.Tier, want)
		}
	}
}
