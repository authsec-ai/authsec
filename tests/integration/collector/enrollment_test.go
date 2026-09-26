package collector

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

func TestEnrollment_HappyPathAndReadHasNoSecrets(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	got := enrollCollector(t, ws, "linux_collector", "", map[string]any{"machine_id": "box-1"})
	if got.RowVersion != 1 {
		t.Fatalf("row_version %d", got.RowVersion)
	}
	if !strings.HasPrefix(got.Credential, "authsec_col_") {
		t.Fatalf("credential prefix: %q", got.Credential)
	}
	want := []string{"ingest", "policy_read", "receipt_write"}
	if strings.Join(got.Scopes, ",") != strings.Join(want, ",") {
		t.Fatalf("scopes %v", got.Scopes)
	}
	if countRows(t, "discovery_sources", ws) != 1 || countRows(t, "collector_instances", ws) != 1 {
		t.Fatal("expected one source and one collector")
	}
	if countRows(t, "collector_integrations", ws) != 1 || countRows(t, "iga_estate_scopes", ws) != 1 {
		t.Fatal("expected one integration binding and one estate")
	}
	view := do(http.MethodGet, "/api/iga/v2/collectors/"+got.CollectorID.String(), "", "discovery:read", ws.String(), nil)
	text := string(view.body)
	for _, secret := range []string{got.Credential, "token_hash", "installation_public_key", "credential_hash", "authsec_enr_"} {
		if strings.Contains(text, secret) {
			t.Fatalf("GET leaked %q in %s", secret, text)
		}
	}
	self := do(http.MethodGet, "/api/iga/v2/collectors/self", got.Credential, "", "", nil)
	if self.code != http.StatusOK {
		t.Fatalf("self: %d %s", self.code, self.body)
	}
	if strings.Contains(string(self.body), got.Credential) {
		t.Fatal("self view leaked the credential")
	}
}

func TestEnrollment_ExpirySingleUseAndResponseLoss(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)

	issued := do(http.MethodPost, "/api/iga/v2/collector-enrollments", "", "discovery:admin", ws.String(),
		[]byte(`{"kind":"linux_collector"}`))
	if issued.code != http.StatusCreated {
		t.Fatalf("issue: %d %s", issued.code, issued.body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(issued.body, &tok)

	current = current.Add(16 * time.Minute)
	expired := do(http.MethodPost, "/api/iga/v2/collectors/enroll", tok.Token, "", "",
		[]byte(`{"installation_public_key":"AAAA","installation_nonce":"n1","kind":"linux_collector"}`))
	if expired.code != http.StatusUnauthorized {
		t.Fatalf("expired token: %d %s", expired.code, expired.body)
	}
	if countRows(t, "collector_instances", ws) != 0 {
		t.Fatal("expired enrollment created a collector")
	}

	resetClock(t)
	first := enrollCollector(t, ws, "linux_collector", "", nil)
	// Response-loss retry is covered by repeating the HTTP enroll with the same
	// key material. Re-issue is a different token; replay the stored recovery
	// by calling the service path through a second enroll on a fresh token,
	// then retrying that token.
	resetClock(t)
	issued = do(http.MethodPost, "/api/iga/v2/collector-enrollments", "", "discovery:admin", ws.String(),
		[]byte(`{"kind":"k8s_collector","namespace_allowlist":["payments"]}`))
	if issued.code != http.StatusCreated {
		t.Fatalf("issue2: %d %s", issued.code, issued.body)
	}
	_ = json.Unmarshal(issued.body, &tok)
	pub := first.Public // different collector; use a fresh key below
	_ = pub
	key := enrollOnce(t, tok.Token, "k8s_collector")
	again := enrollRaw(t, tok.Token, key.pub, key.nonce, "k8s_collector", nil, "", "")
	if again.code != http.StatusOK {
		t.Fatalf("retry: %d %s", again.code, again.body)
	}
	var a, b struct {
		CollectorID       uuid.UUID `json:"collector_id"`
		DiscoverySourceID uuid.UUID `json:"discovery_source_id"`
		Credential        string    `json:"credential"`
	}
	_ = json.Unmarshal(key.body, &a)
	_ = json.Unmarshal(again.body, &b)
	if a.CollectorID != b.CollectorID || a.DiscoverySourceID != b.DiscoverySourceID || a.Credential != b.Credential {
		t.Fatalf("retry changed identity: %+v vs %+v", a, b)
	}
	if countRows(t, "discovery_sources", ws) != 2 {
		t.Fatalf("sources = %d, want 2 (no duplicate on retry)", countRows(t, "discovery_sources", ws))
	}
	other := enrollRaw(t, tok.Token, key.pub, "other-nonce", "k8s_collector", nil, "", "")
	if other.code != http.StatusUnauthorized {
		t.Fatalf("second nonce: %d %s", other.code, other.body)
	}
	if countRows(t, "collector_instances", ws) != 2 {
		t.Fatal("second nonce created another collector")
	}
}

type issuedKey struct {
	pub   []byte
	nonce string
	body  []byte
}

func enrollOnce(t *testing.T, token, kind string) issuedKey {
	t.Helper()
	pub, _, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := uuid.NewString()
	got := enrollRaw(t, token, pub, nonce, kind, nil, "", "")
	if got.code != http.StatusOK {
		t.Fatalf("enroll once: %d %s", got.code, got.body)
	}
	return issuedKey{pub: pub, nonce: nonce, body: got.body}
}

func enrollRaw(t *testing.T, token string, pub []byte, nonce, kind string, hints map[string]any, workspaceID, estateID string) apiResp {
	t.Helper()
	body := map[string]any{
		"installation_public_key": b64(pub),
		"installation_nonce":      nonce,
		"kind":                    kind,
		"version":                 "0.1.0",
	}
	if hints != nil {
		body["native_hints"] = hints
	}
	if workspaceID != "" {
		body["workspace_id"] = workspaceID
	}
	if estateID != "" {
		body["estate_id"] = estateID
	}
	raw, _ := json.Marshal(body)
	return do(http.MethodPost, "/api/iga/v2/collectors/enroll", token, "", "", raw)
}

func TestEnrollment_WrongKindAndEstateRejected(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	estateA := uuid.New()
	estateB := uuid.New()
	for _, id := range []uuid.UUID{estateA, estateB} {
		if err := db.Exec(`INSERT INTO iga_estate_scopes
			(id, workspace_id, scope_kind, source_key, display_name, stage, created_at, updated_at)
			VALUES (?,?,'host',?,?,'unknown',NOW(),NOW())`,
			id, ws, "estate-"+id.String(), id.String()[:8]).Error; err != nil {
			t.Fatal(err)
		}
	}
	issued := do(http.MethodPost, "/api/iga/v2/collector-enrollments", "", "discovery:admin", ws.String(),
		[]byte(`{"kind":"linux_collector","estate_scope":{"kind":"host","id":"`+estateA.String()+`"}}`))
	if issued.code != http.StatusCreated {
		t.Fatalf("issue: %d %s", issued.code, issued.body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(issued.body, &tok)
	pub, _, _ := generateKey()
	wrongKind := enrollRaw(t, tok.Token, pub, "n-kind", "k8s_collector", nil, "", "")
	if wrongKind.code != http.StatusForbidden {
		t.Fatalf("wrong kind: %d %s", wrongKind.code, wrongKind.body)
	}
	wrongEstate := enrollRaw(t, tok.Token, pub, "n-estate", "linux_collector", nil, "", estateB.String())
	if wrongEstate.code != http.StatusForbidden {
		t.Fatalf("wrong estate: %d %s", wrongEstate.code, wrongEstate.body)
	}
	if countRows(t, "collector_instances", ws) != 0 {
		t.Fatal("rejected enrollment wrote a collector")
	}
}

func TestT01_EnrollmentTenantBoundary(t *testing.T) {
	resetClock(t)
	a := newWorkspace(t)
	b := newWorkspace(t)
	issued := do(http.MethodPost, "/api/iga/v2/collector-enrollments", "", "discovery:admin", a.String(),
		[]byte(`{"kind":"linux_collector"}`))
	if issued.code != http.StatusCreated {
		t.Fatalf("issue: %d %s", issued.code, issued.body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(issued.body, &tok)
	pub, _, _ := generateKey()
	spoof := enrollRaw(t, tok.Token, pub, "n-spoof", "linux_collector", nil, b.String(), "")
	if spoof.code != http.StatusForbidden {
		t.Fatalf("T01 enroll spoof: %d %s", spoof.code, spoof.body)
	}
	if countRows(t, "collector_instances", a) != 0 || countRows(t, "collector_instances", b) != 0 {
		t.Fatal("T01 wrote a collector")
	}
	if countRows(t, "discovery_sources", a) != 0 || countRows(t, "discovered_agents", b) != 0 {
		t.Fatal("T01 wrote inventory")
	}

	good := enrollCollector(t, a, "linux_collector", "", nil)
	rot := do(http.MethodPost, "/api/iga/v2/collectors/self/credentials/rotate", good.Credential, "", "",
		[]byte(`{"nonce":"n","requested_at":"2026-09-25T08:00:00Z","workspace_id":"`+b.String()+`","signature":"AA"}`))
	if rot.code != http.StatusForbidden {
		t.Fatalf("T01 rotate workspace: %d %s", rot.code, rot.body)
	}
	host := do(http.MethodPost, "/api/iga/v2/collectors/self/credentials/rotate", good.Credential, "", "",
		[]byte(`{"nonce":"n2","requested_at":"2026-09-25T08:00:00Z","host_id":"attacker-host","signature":"AA"}`))
	if host.code != http.StatusForbidden {
		t.Fatalf("T01 host_id: %d %s", host.code, host.body)
	}
	if countRows(t, "collector_credentials", a) != 1 {
		t.Fatalf("credentials %d", countRows(t, "collector_credentials", a))
	}
}

func TestCredential_ExpiredRevokedWrongScopeAndTokenSeparation(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	good := enrollCollector(t, ws, "linux_collector", "", nil)

	current = current.Add(25 * time.Hour)
	stale := do(http.MethodGet, "/api/iga/v2/collectors/self", good.Credential, "", "", nil)
	if stale.code != http.StatusUnauthorized {
		t.Fatalf("expired credential: %d %s", stale.code, stale.body)
	}
	resetClock(t)

	narrow := enrollCollector(t, ws, "node_sensor", `{"scopes":["actuation"]}`, map[string]any{"node_name": "node-a"})
	denied := do(http.MethodGet, "/api/iga/v2/collectors/self", narrow.Credential, "", "", nil)
	if denied.code != http.StatusForbidden {
		t.Fatalf("wrong scope: %d %s", denied.code, denied.body)
	}

	act, err := services.NewActuationManager(db).EnableActuation(ws, good.DiscoverySourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(act, "authsec_act_") {
		t.Fatalf("actuation token %q", act)
	}
	body := &countingBody{}
	rejected := doReader(http.MethodGet, "/api/iga/v2/collectors/self", act, body)
	if rejected.code != http.StatusUnauthorized {
		t.Fatalf("v1 token on v2: %d %s", rejected.code, rejected.body)
	}
	if body.reads != 0 {
		t.Fatalf("v2 route read the body %d times for a v1 token", body.reads)
	}
	v2onv1 := do(http.MethodGet, "/authsec/provisioning/instructions", good.Credential, "", "", nil)
	if v2onv1.code != http.StatusUnauthorized {
		t.Fatalf("v2 credential on v1 actuation: %d %s", v2onv1.code, v2onv1.body)
	}

	rev := do(http.MethodPost, "/api/iga/v2/collectors/"+good.CollectorID.String()+"/revoke", "", "discovery:admin", ws.String(),
		[]byte(`{"reason":"compromised","expected_version":1}`))
	if rev.code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rev.code, rev.body)
	}
	after := do(http.MethodGet, "/api/iga/v2/collectors/self", good.Credential, "", "", nil)
	if after.code != http.StatusUnauthorized {
		t.Fatalf("revoked credential: %d %s", after.code, after.body)
	}
	conflict := do(http.MethodPost, "/api/iga/v2/collectors/"+good.CollectorID.String()+"/revoke", "", "discovery:admin", ws.String(),
		[]byte(`{"reason":"again","expected_version":1}`))
	if conflict.code != http.StatusConflict {
		t.Fatalf("stale version: %d %s", conflict.code, conflict.body)
	}
}

func TestRotation_OverlapThenOldCredentialExpires(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	got := enrollCollector(t, ws, "linux_collector", "", nil)
	at := current.UTC().Format(time.RFC3339)
	nonce := uuid.NewString()
	msg := services.RotateSignedMessage(got.CollectorID.String(), nonce, at, "", "")
	sig := sign(got.Private, msg)
	raw, _ := json.Marshal(map[string]string{
		"nonce": nonce, "requested_at": at, "signature": sig,
	})
	rot := do(http.MethodPost, "/api/iga/v2/collectors/self/credentials/rotate", got.Credential, "", "", raw)
	if rot.code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rot.code, rot.body)
	}
	var next struct {
		Credential string `json:"credential"`
	}
	_ = json.Unmarshal(rot.body, &next)
	if next.Credential == "" || next.Credential == got.Credential {
		t.Fatal("rotation did not mint a new credential")
	}
	oldOK := do(http.MethodGet, "/api/iga/v2/collectors/self", got.Credential, "", "", nil)
	newOK := do(http.MethodGet, "/api/iga/v2/collectors/self", next.Credential, "", "", nil)
	if oldOK.code != http.StatusOK || newOK.code != http.StatusOK {
		t.Fatalf("overlap window old=%d new=%d", oldOK.code, newOK.code)
	}
	current = current.Add(16 * time.Minute)
	oldGone := do(http.MethodGet, "/api/iga/v2/collectors/self", got.Credential, "", "", nil)
	newStill := do(http.MethodGet, "/api/iga/v2/collectors/self", next.Credential, "", "", nil)
	if oldGone.code != http.StatusUnauthorized {
		t.Fatalf("old credential after overlap: %d", oldGone.code)
	}
	if newStill.code != http.StatusOK {
		t.Fatalf("new credential after overlap: %d %s", newStill.code, newStill.body)
	}
}

func TestMachineIDDoesNotKeyTheEstate(t *testing.T) {
	resetClock(t)
	ws := newWorkspace(t)
	a := enrollCollector(t, ws, "linux_collector", "", map[string]any{"machine_id": "same-box"})
	b := enrollCollector(t, ws, "linux_collector", "", map[string]any{"machine_id": "same-box"})
	if a.EstateID == b.EstateID {
		t.Fatal("same machine_id collapsed two enrollments onto one estate")
	}
	var keys []string
	if err := db.Raw(`SELECT source_key FROM iga_estate_scopes WHERE workspace_id = ? AND id IN (?, ?)`,
		ws, a.EstateID, b.EstateID).Scan(&keys).Error; err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "same-box" || !strings.HasPrefix(k, "collector-install:") {
			t.Fatalf("estate key %q is not the installation key", k)
		}
	}
}

func TestV2FlagOff_Is404(t *testing.T) {
	t.Setenv("IGA_V2_INGEST", "0")
	body := &countingBody{}
	got := doReader(http.MethodPost, "/api/iga/v2/collector-enrollments", "", body)
	if got.code != http.StatusNotFound {
		t.Fatalf("flag off: %d %s", got.code, got.body)
	}
	if body.reads != 0 {
		t.Fatalf("flag-off route read body %d times", body.reads)
	}
}

type countingBody struct{ reads int }

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (b *countingBody) Close() error { return nil }
