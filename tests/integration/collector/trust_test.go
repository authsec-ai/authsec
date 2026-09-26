package collector

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

func TestT02_LegacySightingCannotPoisonPolicyOrEnrollment(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	beforeAgents := countRows(t, "discovered_agents", ws)
	body := []byte(`{"workspace_id":"` + ws.String() + `","source":"k8s_webhook","fingerprint":"fp-` + uuid.NewString() + `","display_name":"invoice-worker"}`)
	got := do(http.MethodPost, "/authsec/discovery/sightings", "", "", "", body)
	if got.code != http.StatusCreated && got.code != http.StatusOK {
		t.Fatalf("T25 legacy sighting while ingress is on: %d %s", got.code, got.body)
	}
	if countRows(t, "discovered_agents", ws) != beforeAgents+1 {
		t.Fatal("sighting did not land in discovered_agents")
	}
	var trust string
	if err := db.Raw(`SELECT evidence_trust FROM discovered_agents WHERE workspace_id = ? AND display_name = ?`,
		ws, "invoice-worker").Scan(&trust).Error; err != nil {
		t.Fatal(err)
	}
	if trust != models.EvidenceTrustUnverifiedLegacy {
		t.Fatalf("trust %q", trust)
	}
	if services.AllowsAuthoritativeUse(trust) {
		t.Fatal("unverified sighting was treated as authoritative")
	}
	svc, err := services.NewCollectorEnrollmentService(db, func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := svc.PolicyInputs(ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range inputs {
		if in.Name == "invoice-worker" {
			t.Fatal("invoice-worker entered v2 policy input")
		}
	}
	if countRows(t, "collector_enrollments", ws) != 0 || countRows(t, "iga_agents", ws) != 0 || countRows(t, "iga_relationship", ws) != 0 {
		t.Fatal("forged sighting created enrollment, an agent, or a relationship")
	}
}

func TestLegacyIngress_DisableStopsWrites(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	off := do(http.MethodPut, "/authsec/discovery/settings/legacy-ingress", "", "discovery:admin", ws.String(),
		[]byte(`{"disabled":false}`))
	if off.code != http.StatusOK {
		t.Fatalf("set off: %d %s", off.code, off.body)
	}
	fp := uuid.NewString()
	okBody := []byte(`{"workspace_id":"` + ws.String() + `","source":"vm_sensor","fingerprint":"` + fp + `","display_name":"kept"}`)
	ok := do(http.MethodPost, "/authsec/discovery/sightings", "", "", "", okBody)
	if ok.code != http.StatusCreated && ok.code != http.StatusOK {
		t.Fatalf("ingress on: %d %s", ok.code, ok.body)
	}
	n := countRows(t, "discovered_agents", ws)
	on := do(http.MethodPut, "/authsec/discovery/settings/legacy-ingress", "", "discovery:admin", ws.String(),
		[]byte(`{"disabled":true}`))
	if on.code != http.StatusOK {
		t.Fatalf("set on: %d %s", on.code, on.body)
	}
	blocked := do(http.MethodPost, "/authsec/discovery/sightings", "", "", "",
		[]byte(`{"workspace_id":"`+ws.String()+`","source":"vm_sensor","fingerprint":"`+uuid.NewString()+`","display_name":"blocked"}`))
	if blocked.code != http.StatusGone {
		t.Fatalf("disabled ingress: %d %s", blocked.code, blocked.body)
	}
	if countRows(t, "discovered_agents", ws) != n {
		t.Fatal("disabled ingress still wrote a row")
	}
}

func TestLegacyIngress_GlobalFlag(t *testing.T) {
	t.Setenv("IGA_LEGACY_INGRESS_DISABLED", "1")
	ws := newWorkspace(t)
	body := &countingBody{}
	reqBody := []byte(`{"workspace_id":"` + ws.String() + `","source":"k8s_webhook","fingerprint":"x","display_name":"nope"}`)
	_ = reqBody
	got := doReader(http.MethodPost, "/authsec/discovery/sightings", "", body)
	if got.code != http.StatusGone {
		t.Fatalf("global flag: %d %s", got.code, got.body)
	}
	if body.reads != 0 {
		t.Fatalf("global flag read the body %d times", body.reads)
	}
	if countRows(t, "discovered_agents", ws) != 0 {
		t.Fatal("global flag wrote a row")
	}
}

func TestLegacyIngress_BodyCap(t *testing.T) {
	ws := newWorkspace(t)
	payload := bytes.Repeat([]byte("a"), (1<<20)+8)
	got := do(http.MethodPost, "/authsec/discovery/sightings", "", "", ws.String(), payload)
	if got.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize legacy body: %d %s", got.code, got.body)
	}
}
