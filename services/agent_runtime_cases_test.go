package services

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestAgentAlertOutcomeClass(t *testing.T) {
	for d, want := range map[string]string{
		"D1": AgentAlertClassSuccess, "D2": AgentAlertClassSuccess, "D3": AgentAlertClassSuccess, "D4": AgentAlertClassSuccess,
		"D5": AgentAlertClassAttempt,
		"D6": AgentAlertClassSignal, "D7": AgentAlertClassSignal, "D8": AgentAlertClassSignal, "D10": AgentAlertClassSignal, "": AgentAlertClassSignal,
	} {
		if got := AgentAlertOutcomeClass(d); got != want {
			t.Errorf("%s: %s, want %s", d, got, want)
		}
	}
}

func TestAgentCaseIndicators(t *testing.T) {
	id, w1, w2 := uuid.New(), uuid.New(), uuid.New()
	got := AgentCaseIndicators(id, []uuid.UUID{w2, w1, w2, uuid.Nil})
	if len(got) != 3 {
		t.Fatalf("indicators: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not sorted / deduped: %v", got)
		}
	}
	if len(AgentCaseIndicators(uuid.Nil, nil)) != 0 {
		t.Fatal("no identity and no workload must give no indicator")
	}
	row := agentCaseAlertRow{IdentityID: id, WorkloadIDs: json.RawMessage(`["` + w1.String() + `"]`)}
	if ind := row.indicators(); len(ind) != 2 || ind[0] != "identity:"+id.String() {
		t.Fatalf("row indicators: %v", ind)
	}
	// Unreadable workload ids: the identity alone.
	row.WorkloadIDs = json.RawMessage(`{"x":1}`)
	if ind := row.indicators(); len(ind) != 1 {
		t.Fatalf("unreadable workloads: %v", ind)
	}
}

func TestAgentCaseOutcomesAndFilter(t *testing.T) {
	for _, o := range []string{"true_positive", "benign", "false_positive", "duplicate"} {
		if !ValidAgentCaseOutcome(o) {
			t.Errorf("%s refused", o)
		}
	}
	for _, o := range []string{"", "resolved", "TRUE_POSITIVE"} {
		if ValidAgentCaseOutcome(o) {
			t.Errorf("%q accepted", o)
		}
	}
	if err := (AgentCaseFilter{State: "open", Severity: "low"}).Validate(); err != nil {
		t.Error(err)
	}
	if err := (AgentCaseFilter{State: "resolved"}).Validate(); err == nil {
		t.Error("state resolved accepted")
	}
	if err := (AgentCaseFilter{Severity: "critical"}).Validate(); err == nil {
		t.Error("severity critical accepted")
	}
	if agentCaseSeverityRank("high") <= agentCaseSeverityRank("medium") || agentCaseSeverityRank("medium") <= agentCaseSeverityRank("low") ||
		agentCaseSeverityRank("x") != 0 {
		t.Error("severity order")
	}
}

func TestAgentCaseAlertIDsAndTitle(t *testing.T) {
	a := uuid.New()
	ids, err := validateAgentCaseAlertIDs([]uuid.UUID{a, a, uuid.Nil})
	if err != nil || len(ids) != 1 {
		t.Fatalf("dedupe: %v %v", ids, err)
	}
	if _, err := validateAgentCaseAlertIDs(nil); err == nil {
		t.Error("no alert accepted")
	}
	many := make([]uuid.UUID, agentCaseMaxAlerts+1)
	for i := range many {
		many[i] = uuid.New()
	}
	if _, err := validateAgentCaseAlertIDs(many); err == nil {
		t.Error("too many alerts accepted")
	}
	if got := truncateRunes("ééé", 2); got != "éé" {
		t.Errorf("truncateRunes: %q", got)
	}
}

func TestAgentCaseBundleHashStable(t *testing.T) {
	b := AgentCaseBundle{Format: AgentCaseExportFormat, Case: AgentCase{ID: uuid.New(), Number: 3, Title: "t <x>"},
		Alerts: []AgentCaseAlert{}, Evidence: []AgentCaseEvidence{}, Asks: []any{}, Stops: []AgentCaseStop{},
		Notes: []AgentCaseNote{}, Links: []AgentCaseLink{}, Log: []AgentCaseLogEntry{{ID: 1, Payload: json.RawMessage(`{"a":1}`)}}}
	r1, _ := json.Marshal(b)
	r2, _ := json.Marshal(b)
	if AgentCaseBundleHash(r1) != AgentCaseBundleHash(r2) || len(AgentCaseBundleHash(r1)) != 64 {
		t.Fatal("hash not stable")
	}
	b.Case.Title = "changed"
	r3, _ := json.Marshal(b)
	if AgentCaseBundleHash(r3) == AgentCaseBundleHash(r1) {
		t.Fatal("hash ignores content")
	}
}

func TestAgentCaseTiers(t *testing.T) {
	for a, want := range map[string]int{"close": 0, "export": 0, "open": 1, "assign": 1, "lower_severity": 3} {
		if got, ok := AgentCaseActionTier[a]; !ok || got != want {
			t.Errorf("tier of %s: %d %v, want %d", a, got, ok, want)
		}
	}
}

type countingPinner struct{ pins, unpins int }

func (p *countingPinner) Pin(_ *gorm.DB, _, _ uuid.UUID, r []AgentCaseEvidenceRef) error {
	p.pins += len(r)
	return nil
}
func (p *countingPinner) Unpin(_ *gorm.DB, _, _ uuid.UUID, r []AgentCaseEvidenceRef) error {
	p.unpins += len(r)
	return nil
}

func TestSetAgentCaseEvidencePinner(t *testing.T) {
	p := &countingPinner{}
	SetAgentCaseEvidencePinner(p)
	if agentCaseEvidencePinner != EvidencePinner(p) {
		t.Fatal("pinner not installed")
	}
	SetAgentCaseEvidencePinner(nil)
	if _, ok := agentCaseEvidencePinner.(noopEvidencePinner); !ok {
		t.Fatal("nil must restore the no-op pinner")
	}
}
