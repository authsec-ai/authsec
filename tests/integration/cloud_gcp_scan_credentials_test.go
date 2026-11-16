package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GCP-2: identities and credentials, against a real database.
//
// What these pin down, in order of how much damage a regression would do:
//   - key material never reaches the database (HMAC secret, API key string, JWKS)
//   - a denied or skipped surface never deletes rows it did not look at
//   - one surface's failure never marks another not reached
//   - a service-disabled API is "nothing there", not a denial that blocks
//     reconciliation for the whole connector

const (
	hmacSecretLeak = "HMAC-SECRET-SHOULD-NEVER-BE-PERSISTED"
	apiKeyLeak     = "AIzaSy-API-KEY-STRING-SHOULD-NEVER-BE-PERSISTED"
	jwksLeak       = "JWKS-BODY-SHOULD-NEVER-BE-PERSISTED"
)

func gcp2Identities(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) []models.CloudIdentity {
	t.Helper()
	var rows []models.CloudIdentity
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Find(&rows).Error; err != nil {
		t.Fatalf("load identities: %v", err)
	}
	return rows
}

func gcp2Secrets(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID, kind string) []models.CloudSecret {
	t.Helper()
	var rows []models.CloudSecret
	q := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID)
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if err := q.Find(&rows).Error; err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	return rows
}

// nothingLeaked fails if any planted secret string is anywhere in the connector's
// identity or secret rows, in any column.
func nothingLeaked(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) {
	t.Helper()
	var dump []string
	if err := db.Raw(`SELECT to_jsonb(i)::text FROM cloud_identity i WHERE workspace_id = ? AND connector_id = ?
	                  UNION ALL
	                  SELECT to_jsonb(s)::text FROM cloud_secret s WHERE workspace_id = ? AND connector_id = ?
	                  UNION ALL
	                  SELECT to_jsonb(p)::text FROM cloud_permission p WHERE workspace_id = ? AND connector_id = ?
	                  UNION ALL
	                  SELECT to_jsonb(r)::text FROM cloud_resource r WHERE workspace_id = ? AND connector_id = ?`,
		ws, connectorID, ws, connectorID, ws, connectorID, ws, connectorID).Scan(&dump).Error; err != nil {
		t.Fatalf("dump rows: %v", err)
	}
	all := strings.Join(dump, "\n")
	for _, leak := range []string{hmacSecretLeak, apiKeyLeak, jwksLeak, "SHOULD-NEVER-BE-PERSISTED"} {
		if strings.Contains(all, leak) {
			t.Fatalf("key material %q reached the database", leak)
		}
	}
}

func TestGCP2_ClassifiesServiceAccounts(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-sa-class")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{
		account("1", "mine@proj-alpha.iam.gserviceaccount.com"),
		account("2", "123456789-compute@developer.gserviceaccount.com"),
		account("3", "proj-alpha@appspot.gserviceaccount.com"),
		account("4", "service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com"),
	}
	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	want := map[string]string{
		"mine@proj-alpha.iam.gserviceaccount.com":                  "user_managed",
		"123456789-compute@developer.gserviceaccount.com":          "default_compute",
		"proj-alpha@appspot.gserviceaccount.com":                   "default_appengine",
		"service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com": "service_agent",
	}
	got := map[string]string{}
	for _, i := range gcp2Identities(t, db, ws, connectorID) {
		a := i.GCPAttrs()
		got[a.Email] = a.SAClass
	}
	for email, class := range want {
		if got[email] != class {
			t.Errorf("%s: sa_class = %q, want %q", email, got[email], class)
		}
	}
}

func TestGCP2_HMACAndAPIKeys_MetadataOnly(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-creds")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{account("1", "old-key-sa@proj-alpha.iam.gserviceaccount.com")}
	f.hmacKeys["proj-alpha"] = []fakeGCPHMACKey{
		{accessID: "GOOG1EAAA", saEmail: "old-key-sa@proj-alpha.iam.gserviceaccount.com", state: "ACTIVE"},
		{accessID: "GOOG1EBBB", saEmail: "old-key-sa@proj-alpha.iam.gserviceaccount.com", state: "INACTIVE"},
	}
	f.apiKeys["proj-alpha"] = []fakeGCPAPIKey{
		{number: "555", uid: "k-restricted", display: "iga-restricted-key", keyString: apiKeyLeak,
			apiTargets: []string{"storage.googleapis.com"}, ips: []string{"203.0.113.10"}},
		{number: "555", uid: "k-open", display: "open-key", keyString: apiKeyLeak},
	}
	f.wifPools["proj-alpha"] = []fakeGCPPool{{id: "github", providers: []fakeGCPProvider{
		{id: "gh", issuer: "https://token.actions.githubusercontent.com", condition: "assertion.repository=='o/r'", jwks: jwksLeak},
	}}}
	// plant the HMAC secret too: the fake puts it on every item.
	_ = hmacSecretLeak

	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q, want complete: %+v", snapshot.Coverage.Status, snapshot.Coverage.Surfaces)
	}

	// HMAC: linked to the real service account, namespaced, status from state.
	hmacs := gcp2Secrets(t, db, ws, connectorID, models.CloudSecretGCPHMACKey)
	if len(hmacs) != 2 {
		t.Fatalf("hmac keys = %d, want 2", len(hmacs))
	}
	var sa models.CloudIdentity
	if err := db.Where("workspace_id = ? AND connector_id = ? AND kind = ?", ws, connectorID,
		models.CloudIdentityGCPServiceAccount).First(&sa).Error; err != nil {
		t.Fatalf("load service account: %v", err)
	}
	status := map[string]string{}
	for _, h := range hmacs {
		if h.IdentityID != sa.ID {
			t.Errorf("hmac %s owned by %s, want the real service account %s", h.NativeID, h.IdentityID, sa.ID)
		}
		if !strings.HasPrefix(h.NativeID, "//storage.googleapis.com/hmacKeys/") {
			t.Errorf("hmac native_id %q is not namespaced", h.NativeID)
		}
		status[h.NativeID] = h.Status
	}
	if status["//storage.googleapis.com/hmacKeys/GOOG1EAAA"] != models.CloudSecretActive ||
		status["//storage.googleapis.com/hmacKeys/GOOG1EBBB"] != models.CloudSecretInactive {
		t.Errorf("hmac status wrong: %v", status)
	}

	// API keys: hung off ONE synthetic project identity, restrictions kept.
	keys := gcp2Secrets(t, db, ws, connectorID, models.CloudSecretGCPAPIKey)
	if len(keys) != 2 {
		t.Fatalf("api keys = %d, want 2", len(keys))
	}
	var project models.CloudIdentity
	if err := db.Where("workspace_id = ? AND connector_id = ? AND kind = ?", ws, connectorID,
		models.CloudIdentityGCPProject).First(&project).Error; err != nil {
		t.Fatalf("api keys need a project owner row: %v", err)
	}
	if project.NativeID != "//cloudresourcemanager.googleapis.com/projects/555" {
		t.Errorf("project native_id = %q (number must come from the key's own name)", project.NativeID)
	}
	byUID := map[string]*models.CloudSecret{}
	for i := range keys {
		k := &keys[i]
		if k.IdentityID != project.ID {
			t.Errorf("api key %s not owned by the project row", k.NativeID)
		}
		byUID[k.GCPAttrs().DisplayName] = k
	}
	r := byUID["iga-restricted-key"].GCPAttrs().Restrictions
	if r == nil || r.Unrestricted || len(r.APITargets) != 1 || r.APITargets[0] != "storage.googleapis.com" || r.IPs[0] != "203.0.113.10" {
		t.Errorf("restricted key restrictions = %+v", r)
	}
	if o := byUID["open-key"].GCPAttrs().Restrictions; o == nil || !o.Unrestricted {
		t.Errorf("a key with no restrictions must read unrestricted, got %+v", o)
	}

	// Federation: snapshot only, nothing persisted for it.
	if len(snapshot.Providers) != 1 || snapshot.Providers[0].Pool != "github" ||
		snapshot.Providers[0].AttributeCondition == "" {
		t.Fatalf("providers = %+v", snapshot.Providers)
	}

	nothingLeaked(t, db, ws, connectorID)
}

func TestGCP2_AuthSecPoolIsSkipped(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-own-pool")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.wifPools["proj-alpha"] = []fakeGCPPool{
		{id: "authsec-0123456789abcdef", providers: []fakeGCPProvider{{id: "authsec-provider", issuer: "https://authsec.example"}}},
		{id: "customer-pool", providers: []fakeGCPProvider{{id: "p1", issuer: "https://idp.example"}}},
	}
	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(snapshot.Providers) != 1 || snapshot.Providers[0].Pool != "customer-pool" {
		t.Fatalf("AuthSec's own pool must not be reported: %+v", snapshot.Providers)
	}
	if got := snapshot.Coverage.Counters["federation_providers"]; got != 1 {
		t.Errorf("federation_providers = %d, want 1", got)
	}
}

// One denied surface marks only that surface, and blocks every reconcile (the
// existing rule), so a stale row survives.
func TestGCP2_HMACDenialAffectsOnlyThatSurface(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-hmac-denied")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{
		account("1", "a@proj-alpha.iam.gserviceaccount.com"),
		account("2", "b@proj-alpha.iam.gserviceaccount.com"),
	}
	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	f.accounts["proj-alpha"] = f.accounts["proj-alpha"][:1] // b is gone
	f.failHMAC["proj-alpha"] = 403
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	cov := snapshot.Coverage
	if cov.Surfaces["hmac_keys"].State != models.CloudCoverageDenied {
		t.Errorf("hmac_keys = %q, want denied", cov.Surfaces["hmac_keys"].State)
	}
	for _, s := range []string{"identities", "keys", "api_keys", "federation_config"} {
		if cov.Surfaces[s].State != models.CloudCoverageReached {
			t.Errorf("%s = %q: an HMAC denial must not touch it", s, cov.Surfaces[s].State)
		}
	}
	if cov.Status != models.ScanStatusPartial {
		t.Errorf("status = %q, want partial", cov.Status)
	}
	if got := countIdentities(t, db, ws, connectorID); got != 2 {
		t.Fatalf("identities = %d: a partial scan must delete nothing", got)
	}
}

// An API that is simply not enabled on the project is "nothing there", not a
// denial: otherwise every project that never turned on Cloud Storage or the API
// Keys API would block reconciliation for the whole connector.
func TestGCP2_ServiceDisabledIsReachedNotDenied(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-svc-disabled")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{account("1", "a@proj-alpha.iam.gserviceaccount.com")}
	f.failHMAC["proj-alpha"] = 403
	f.failAPIKeys["proj-alpha"] = 403
	f.failBody = "API has not been used in project 123 before or it is disabled. SERVICE_DISABLED"

	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("a disabled API blocked the scan: %q %+v", snapshot.Coverage.Status, snapshot.Coverage.Surfaces)
	}
	for _, s := range []string{"hmac_keys", "api_keys"} {
		if snapshot.Coverage.Surfaces[s].State != models.CloudCoverageReached {
			t.Errorf("%s = %q, want reached", s, snapshot.Coverage.Surfaces[s].State)
		}
	}
}

// The probe-gated decision: a surface the probe PROVED unreadable is not
// attempted, does not block the scan, and does not delete what an earlier scan
// (when it was readable) found -- including the owner row, whose deletion would
// cascade the key away.
func TestGCP2_ProbeUnreadableSurfaceIsSkippedAndItsRowsSurvive(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-probe-skip")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{account("1", "a@proj-alpha.iam.gserviceaccount.com")}
	f.hmacKeys["proj-alpha"] = []fakeGCPHMACKey{
		{accessID: "GOOG1EAAA", saEmail: "a@proj-alpha.iam.gserviceaccount.com", state: "ACTIVE"},
		// An HMAC key whose service account this scan does not read: its owner is
		// a member-prefixed placeholder identity, which must survive too.
		{accessID: "GOOG1EOTHER", saEmail: "elsewhere@other-proj.iam.gserviceaccount.com", state: "ACTIVE"},
	}
	f.apiKeys["proj-alpha"] = []fakeGCPAPIKey{{number: "555", uid: "k1", display: "key"}}

	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	if n := len(gcp2Secrets(t, db, ws, connectorID, models.CloudSecretGCPHMACKey)); n != 2 {
		t.Fatalf("seed: hmac keys = %d, want 2", n)
	}

	// The reader loses both permissions; the probe says so.
	if err := db.Exec(`UPDATE cloud_connector SET attrs = attrs || ?::jsonb WHERE id = ?`,
		`{"capability_profile":{
		    "hmac_keys":{"can":false,"missing":["storage.hmacKeys.list"]},
		    "api_keys":{"can":false,"missing":["apikeys.keys.list"]}}}`, connectorID).Error; err != nil {
		t.Fatalf("update probe: %v", err)
	}
	// Even if Google would now answer empty, a skipped surface must not be read.
	f.hmacKeys["proj-alpha"] = nil
	f.apiKeys["proj-alpha"] = nil

	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	cov := snapshot.Coverage
	for _, s := range []string{"hmac_keys", "api_keys"} {
		sc := cov.Surfaces[s]
		if sc.State != models.CloudCoverageNotSelected || !strings.HasPrefix(sc.Error, "not_readable") {
			t.Errorf("%s = %+v, want not_selected with a not_readable reason", s, sc)
		}
	}
	if cov.Status != models.ScanStatusComplete {
		t.Fatalf("a probe-skipped surface blocked the scan: %q %+v", cov.Status, cov.Surfaces)
	}
	if n := len(gcp2Secrets(t, db, ws, connectorID, models.CloudSecretGCPHMACKey)); n != 2 {
		t.Errorf("hmac keys = %d after skip, want 2: not looked at is not gone", n)
	}
	if n := len(gcp2Secrets(t, db, ws, connectorID, models.CloudSecretGCPAPIKey)); n != 1 {
		t.Errorf("api keys = %d after skip, want 1", n)
	}
	var projects int64
	db.Model(&models.CloudIdentity{}).Where("workspace_id = ? AND connector_id = ? AND kind = ?",
		ws, connectorID, models.CloudIdentityGCPProject).Count(&projects)
	if projects != 1 {
		t.Errorf("project owner rows = %d, want 1: deleting it cascades the API key away", projects)
	}
}

// And when the surface IS readable and the key is gone, a complete scan removes it.
func TestGCP2_VanishedKeysAreReconciledOnCompleteScan(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-vanished")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{account("1", "a@proj-alpha.iam.gserviceaccount.com")}
	f.hmacKeys["proj-alpha"] = []fakeGCPHMACKey{{accessID: "GOOG1EAAA", saEmail: "a@proj-alpha.iam.gserviceaccount.com", state: "ACTIVE"}}
	f.apiKeys["proj-alpha"] = []fakeGCPAPIKey{{number: "555", uid: "k1", display: "key"}}

	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	scanner := gcpScanner(t, db, f)
	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	f.hmacKeys["proj-alpha"] = nil
	f.apiKeys["proj-alpha"] = nil
	snapshot, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q", snapshot.Coverage.Status)
	}
	if n := len(gcp2Secrets(t, db, ws, connectorID, "")); n != 0 {
		t.Errorf("secrets = %d, want 0 after the keys vanished", n)
	}
}

// An HMAC key whose service account lies outside the scan gets a member-prefixed
// owner row, and a rescan reuses it rather than minting another.
func TestGCP2_HMACKeyOfUnreadServiceAccountGetsOnePlaceholderOwner(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-placeholder")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.hmacKeys["proj-alpha"] = []fakeGCPHMACKey{
		{accessID: "GOOG1EOTHER", saEmail: "Elsewhere@other-proj.iam.gserviceaccount.com", state: "ACTIVE"},
	}
	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	scanner := gcpScanner(t, db, f)
	for i := 0; i < 2; i++ {
		if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
	}
	var owners []models.CloudIdentity
	db.Where("workspace_id = ? AND connector_id = ? AND native_id LIKE ?", ws, connectorID, "//gcp/principal/%").Find(&owners)
	if len(owners) != 1 {
		t.Fatalf("placeholder owners = %d, want exactly 1 across two scans", len(owners))
	}
	a := owners[0].GCPAttrs()
	if a.Email != "elsewhere@other-proj.iam.gserviceaccount.com" || !a.IsExternal {
		t.Errorf("placeholder attrs = %+v: email must be lower-cased and the account marked external", a)
	}
}

// HMAC listing refused for TOKEN SCOPE (live: Google rejects the read-only
// scopes for storage hmacKeys.list). No role fixes that, so it is reported as
// not readable -- never denied -- and does not hold the scan back from
// reconciling everything else.
func TestGCP2_HMACScopeRefusalIsNotReadableNotDenied(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp2-hmac-scope")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{account("1", "a@proj-alpha.iam.gserviceaccount.com")}
	f.failHMAC["proj-alpha"] = 403
	f.failBody = "Provided scope(s) are not authorized"

	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	sc := snapshot.Coverage.Surfaces["hmac_keys"]
	if sc.State != models.CloudCoverageNotSelected || !strings.HasPrefix(sc.Error, "not_readable") {
		t.Fatalf("hmac_keys = %+v, want not_selected with a not_readable reason", sc)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("a scope refusal held the scan back: %q %+v", snapshot.Coverage.Status, snapshot.Coverage.Surfaces)
	}
}
