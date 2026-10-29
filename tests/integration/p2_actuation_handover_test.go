package integration

// Turning enforcement on from the console without a token to copy (UI-060):
// the connector turns pending, its agent offers the credential it generated on
// a registration its ingest token authenticates, and from then on discovery
// for that connector needs the credential. Until the hand-over, discovery
// keeps working under the ingest token -- turning enforcement on must never
// cut a cluster off (UI-058).

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/services"
)

const handoverToken = "authsec_act_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfG"

func handoverBody(l *ingestLab, offer string) map[string]any {
	b := regBody(l.wsA, "kh-a1")
	if offer != "" {
		b["actuation_token"] = offer
	}
	return b
}

func storedActuationHash(t *testing.T, l *ingestLab) string {
	t.Helper()
	var hash string
	if err := l.db.Raw(`SELECT actuation_token_hash FROM discovery_sources WHERE id = ?`, l.srcA1).Scan(&hash).Error; err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestP2ActuationHandover(t *testing.T) {
	l := newIngestLab(t)
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	ingest, _ := l.mint(l.wsA, nil)
	am := services.NewActuationManager(l.db)

	// Off: the agent learns enforcement is off; an offer is ignored.
	code, body := l.post("/agent-registration", ingest, handoverBody(l, handoverToken))
	if code != http.StatusOK || body["actuation"] != "off" {
		t.Fatalf("off: %d %v", code, body)
	}
	if storedActuationHash(t, l) != "" {
		t.Fatal("an offer while enforcement is off must not be taken")
	}

	if err := am.RequestActuation(l.wsA, l.srcA1); err != nil {
		t.Fatal(err)
	}

	// Pending: discovery still works under the ingest token.
	code, body = l.post("/agent-registration", ingest, handoverBody(l, ""))
	if code != http.StatusOK || body["actuation"] != "pending" {
		t.Fatalf("pending: %d %v", code, body)
	}
	if code, _ := l.post("/sightings", ingest, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Fatalf("a sighting while pending must be accepted under the ingest token, got %d", code)
	}

	// A malformed credential is refused and leaves the connector pending.
	_, body = l.post("/agent-registration", ingest, handoverBody(l, "authsec_act_short"))
	if body["actuation_error"] == nil || body["actuation"] != "pending" {
		t.Fatalf("malformed offer: %v", body)
	}

	// An unauthenticated offer (warn accepts the registration itself) is refused.
	t.Setenv(services.DiscoveryIngestAuthEnv, "warn")
	code, body = l.post("/agent-registration", "", handoverBody(l, handoverToken))
	if !is2xx(code) || body["actuation_error"] == nil {
		t.Fatalf("unauthenticated offer: %d %v", code, body)
	}
	if storedActuationHash(t, l) != "" {
		t.Fatal("an offer no ingest token authenticated must not be taken")
	}
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")

	// Another workspace's ingest token cannot make the offer.
	foreign, _ := l.mint(l.wsB, nil)
	if code, _ := l.post("/agent-registration", foreign, handoverBody(l, handoverToken)); code != http.StatusForbidden {
		t.Fatalf("a foreign workspace's token must be refused, got %d", code)
	}

	// The agent's offer is taken; only its hash is stored.
	_, body = l.post("/agent-registration", ingest, handoverBody(l, handoverToken))
	if body["actuation"] != "on" {
		t.Fatalf("offer: %v", body)
	}
	sum := sha256.Sum256([]byte(handoverToken))
	if storedActuationHash(t, l) != hex.EncodeToString(sum[:]) {
		t.Fatal("the stored hash is not the offered credential's")
	}

	// From now on the ingest token no longer speaks for the connector, so a
	// second offer cannot replace the credential.
	code, _ = l.post("/agent-registration", ingest, handoverBody(l, handoverToken+"x"))
	if code != http.StatusUnauthorized {
		t.Fatalf("the ingest token must be refused once the credential is taken, got %d", code)
	}
	code, body = l.post("/agent-registration", handoverToken, handoverBody(l, ""))
	if code != http.StatusOK || body["actuation"] != "on" {
		t.Fatalf("the credential must authenticate: %d %v", code, body)
	}
	if src, err := am.AuthenticateAgent(handoverToken); err != nil || src.ID != l.srcA1 {
		t.Fatalf("the actuation endpoints must take the credential: %v", err)
	}

	// Turning it on again rotates: the old credential stops at once, discovery
	// falls back to the ingest token, and a new offer is taken.
	if err := am.RequestActuation(l.wsA, l.srcA1); err != nil {
		t.Fatal(err)
	}
	if code, _ := l.post("/agent-registration", handoverToken, handoverBody(l, "")); code != http.StatusUnauthorized {
		t.Fatalf("the rotated credential must stop working, got %d", code)
	}
	next := strings.Replace(handoverToken, "AbCd", "ZyXw", 1)
	if _, body = l.post("/agent-registration", ingest, handoverBody(l, next)); body["actuation"] != "on" {
		t.Fatalf("rotation offer: %v", body)
	}

	// Turned off: back to the ingest token.
	if err := am.DisableActuation(l.wsA, l.srcA1); err != nil {
		t.Fatal(err)
	}
	if code, body = l.post("/agent-registration", ingest, handoverBody(l, "")); code != http.StatusOK || body["actuation"] != "off" {
		t.Fatalf("off again: %d %v", code, body)
	}
}

// A pending connector takes queued work: the agent leases it as soon as it
// has handed over its credential.
func TestP2ActuationPendingQueuesWork(t *testing.T) {
	l := newIngestLab(t)
	am := services.NewActuationManager(l.db)
	in := services.EnqueueInstructionInput{
		DiscoverySourceID: l.srcA1, Kind: "verify_uptake", Fingerprint: "kh-fp-pending",
		Payload: map[string]interface{}{"namespace": "default", "workload_name": "x"},
	}
	if _, _, err := am.Enqueue(l.wsA, in); err == nil {
		t.Fatal("work for a cluster with enforcement off must be refused")
	}
	if err := am.RequestActuation(l.wsA, l.srcA1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := am.Enqueue(l.wsA, in); err != nil {
		t.Fatalf("work for a pending cluster must queue: %v", err)
	}
	// Turning off is refused while that work is open, as it is when on.
	if err := am.DisableActuation(l.wsA, l.srcA1); err == nil {
		t.Fatal("turning off with open work must be refused")
	}
}
