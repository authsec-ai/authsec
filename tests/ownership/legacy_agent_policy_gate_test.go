// IGA_LEGACY_AGENT_POLICY (disposition plan §3.2; SPEC-iga-phase3-policy.md
// §4.3, A56): off stops the two legacy agent-policy workers and nothing else;
// on (the default) and any unrecognised value start them as before.
//
// main cannot be run here, so the startup is proven in two halves: the
// function main calls (StartLegacyAgentPolicyWorkers) is driven with the gate
// in each state, and main's own source is checked to start the two workers
// only through it -- while ExpiryWorker and the lease reaper stay outside it.
package ownership

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/services"
)

func TestLegacyAgentPolicyGateParsing(t *testing.T) {
	for raw, want := range map[string]struct {
		on, unknown bool
	}{
		"":      {true, false},
		"on":    {true, false},
		"ON":    {true, false},
		" on ":  {true, false},
		"off":   {false, false},
		"Off":   {false, false},
		" OFF ": {false, false},
		"false": {true, true},
		"0":     {true, true},
		"no":    {true, true},
		"of":    {true, true},
	} {
		g := services.ParseLegacyAgentPolicyGate(raw)
		if g.On != want.on || g.Unknown != want.unknown {
			t.Errorf("%q: got on=%v unknown=%v, want on=%v unknown=%v",
				raw, g.On, g.Unknown, want.on, want.unknown)
		}
		if (g.Warning() != "") != want.unknown {
			t.Errorf("%q: an unrecognised value must warn and only it: %q", raw, g.Warning())
		}
		if !strings.Contains(g.Decision(), services.LegacyAgentPolicyEnv+"="+g.State()) {
			t.Errorf("%q: the startup decision must name the gate and its state: %q", raw, g.Decision())
		}
	}

	// Unset is on: a deployment that never heard of the gate behaves as before.
	t.Setenv(services.LegacyAgentPolicyEnv, "")
	if !services.LegacyAgentPolicyGateFromEnv().On {
		t.Error("unset must be on")
	}
	t.Setenv(services.LegacyAgentPolicyEnv, "off")
	if services.LegacyAgentPolicyGateFromEnv().On {
		t.Error("off must be off")
	}
}

type countingWorker struct{ starts int }

func (w *countingWorker) Start() { w.starts++ }

func TestLegacyWorkersStartOnlyWithTheGateOn(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"", []string{"PolicyReconcileWorker", "PolicyWarningWorker"}},
		{"on", []string{"PolicyReconcileWorker", "PolicyWarningWorker"}},
		{"bogus", []string{"PolicyReconcileWorker", "PolicyWarningWorker"}},
		{"off", nil},
	} {
		rec, warn := &countingWorker{}, &countingWorker{}
		got := services.StartLegacyAgentPolicyWorkers(services.ParseLegacyAgentPolicyGate(tc.raw),
			services.LegacyAgentPolicyWorkers{Reconcile: rec, Warning: warn})
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: started %v, want %v", tc.raw, got, tc.want)
		}
		wantStarts := 0
		if tc.want != nil {
			wantStarts = 1
		}
		if rec.starts != wantStarts || warn.starts != wantStarts {
			t.Errorf("%q: reconcile started %d, warning started %d; want %d each",
				tc.raw, rec.starts, warn.starts, wantStarts)
		}
	}

	// The production set is the two legacy workers, nothing else.
	w := services.NewLegacyAgentPolicyWorkers(nil)
	if _, ok := w.Reconcile.(*services.PolicyReconcileWorker); !ok {
		t.Errorf("Reconcile is %T, want *services.PolicyReconcileWorker", w.Reconcile)
	}
	if _, ok := w.Warning.(*services.PolicyWarningWorker); !ok {
		t.Errorf("Warning is %T, want *services.PolicyWarningWorker", w.Warning)
	}
}

// main starts the two legacy workers ONLY through StartLegacyAgentPolicyWorkers,
// with the gate read from the environment, and no gate decides anything else:
// ExpiryWorker and the lease reaper are started unconditionally as before.
func TestMainStartsLegacyWorkersOnlyThroughTheGate(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "main.go")
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	calls := map[string]int{}
	var gateArg string
	gateMentionedInIf := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name]++
				if sel.Sel.Name == "StartLegacyAgentPolicyWorkers" && len(x.Args) == 2 {
					if id, ok := x.Args[0].(*ast.Ident); ok {
						gateArg = id.Name
					}
				}
			}
		case *ast.IfStmt:
			ast.Inspect(x.Cond, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok && id.Name == "legacyAgentPolicyGate" {
					gateMentionedInIf = true
				}
				return true
			})
		}
		return true
	})

	for name, want := range map[string]int{
		"NewPolicyReconcileWorker":      0, // only via NewLegacyAgentPolicyWorkers
		"NewPolicyWarningWorker":        0,
		"StartLegacyAgentPolicyWorkers": 1,
		"NewLegacyAgentPolicyWorkers":   1,
		"LegacyAgentPolicyGateFromEnv":  1,
		"SetLegacyAgentPolicyGate":      1,
		"NewExpiryWorker":               1,
		"NewLeaseReaper":                1,
		"NewJMLWorker":                  1,
		"NewSoDScanWorker":              1,
		"ParseLegacyAgentPolicyGate":    0,
		"LegacyAgentPolicy":             0,
	} {
		if calls[name] != want {
			t.Errorf("cmd/main.go calls %s %d time(s), want %d", name, calls[name], want)
		}
	}
	if gateArg != "legacyAgentPolicyGate" {
		t.Errorf("StartLegacyAgentPolicyWorkers must be given the gate read from the environment, got %q", gateArg)
	}
	if gateMentionedInIf {
		t.Error("the gate must decide nothing in main beyond what StartLegacyAgentPolicyWorkers starts: " +
			"an if on it could stop a shared worker (ExpiryWorker, LeaseReaper)")
	}
}
