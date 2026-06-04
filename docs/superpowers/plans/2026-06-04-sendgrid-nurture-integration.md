# SendGrid Nurture Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate SendGrid Marketing Campaigns into authsec so new users are enrolled in a nurture sequence on first login, returning users keep their last-login date current, dormant users are moved to a re-engagement list nightly, PQL events update a custom field, and plan upgrades remove users from all nurture lists.

**Architecture:** A new `SendGridService` (mirroring the existing `HubSpotService` pattern) owns all SendGrid HTTP calls. It is constructed once in `routes.go` and injected into both `EndUserController` and `HubSpotController`. A `DormantWorker` service runs a nightly `robfig/cron` job that iterates all tenant DBs, moves inactive users to the dormant list, and updates a per-tenant `dormant_enrolled` column added via a tenant migration.

**Tech Stack:** Go 1.25, Gin, PostgreSQL (master + per-tenant DBs), SendGrid Marketing API v3, `github.com/robfig/cron/v3`

---

## File Map

| File | Change |
|---|---|
| `services/sendgrid_service.go` | New — `SendGridService`, `UpsertContact`, `RemoveFromLists` |
| `services/sendgrid_service_test.go` | New — httptest-based tests |
| `services/dormant_job.go` | New — `DormantWorker`, nightly cron job |
| `config/config.go` | Extend — 11 SendGrid fields in `Config` struct + `LoadConfig()` |
| `.env.example` | Extend — SendGrid env var stubs |
| `migrations/tenant/109_add_dormant_columns.sql` | New — adds `dormant_enrolled` + `dormant_enrolled_at` to `users` |
| `database/enduser_repository.go` | Extend — `GetDormantUsers`, `MarkDormantEnrolled`, `ResetDormantEnrolled` |
| `controllers/enduser/enduser_controller.go` | Extend — add `sg` field, constructor, update `NotifyOwnerNewRegistration`, add `NotifyPlanUpgrade` |
| `controllers/platform/hubspot_controller.go` | Extend — accept `sg` in constructor, fire SendGrid `is_pql` update in `SyncContact` |
| `routes/routes.go` | Extend — create `SendGridService`, update controller constructors, add plan-upgrade route |
| `cmd/main.go` | Extend — start `DormantWorker` after migrations |
| `go.mod` / `go.sum` | Extend — add `github.com/robfig/cron/v3` |

---

## Task 1: Add `robfig/cron/v3` dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1.1: Fetch the dependency**

```bash
cd /Users/souravdas/kloudone/authsec
go get github.com/robfig/cron/v3@latest
```

Expected: version line added to `go.mod`, no error.

- [ ] **Step 1.2: Verify it appears in go.mod**

```bash
grep "robfig/cron" go.mod
```

Expected: `github.com/robfig/cron/v3 v3.x.x`

- [ ] **Step 1.3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add robfig/cron/v3 for dormant user scheduler"
```

---

## Task 2: Config — add SendGrid env vars

**Files:**
- Modify: `config/config.go` (lines ~95–146 and ~256–375)
- Modify: `.env.example`

- [ ] **Step 2.1: Add fields to `Config` struct**

In `config/config.go`, after the `HubSpotAccessToken string` field (line ~96), add:

```go
	// SendGrid marketing integration
	SendGridAPIKey         string
	SendGridListNewSignups string
	SendGridListTrialUsers string
	SendGridListLeads      string
	SendGridListDormant    string
	SGFieldSegment         string
	SGFieldTenantID        string
	SGFieldFirstLoginAt    string
	SGFieldLastLoginAt     string
	SGFieldIsPQL           string
	SGFieldPlanType        string
```

- [ ] **Step 2.2: Load vars in `LoadConfig()`**

In `config/config.go`, after the `hubSpotAccessToken := getEnv(...)` line (~line 257), add:

```go
	// Load SendGrid configuration
	sendGridAPIKey         := getEnv("SENDGRID_API_KEY", "")
	sendGridListNewSignups := getEnv("SENDGRID_LIST_NEW_SIGNUPS", "")
	sendGridListTrialUsers := getEnv("SENDGRID_LIST_TRIAL_USERS", "")
	sendGridListLeads      := getEnv("SENDGRID_LIST_LEADS", "")
	sendGridListDormant    := getEnv("SENDGRID_LIST_DORMANT", "")
	sgFieldSegment         := getEnv("SG_FIELD_SEGMENT", "e1_T")
	sgFieldTenantID        := getEnv("SG_FIELD_TENANT_ID", "e2_T")
	sgFieldFirstLoginAt    := getEnv("SG_FIELD_FIRST_LOGIN_AT", "e3_D")
	sgFieldLastLoginAt     := getEnv("SG_FIELD_LAST_LOGIN_AT", "e4_D")
	sgFieldIsPQL           := getEnv("SG_FIELD_IS_PQL", "e5_T")
	sgFieldPlanType        := getEnv("SG_FIELD_PLAN_TYPE", "w6_T")
```

- [ ] **Step 2.3: Assign in `AppConfig = &Config{...}`**

After `HubSpotAccessToken: hubSpotAccessToken,` (~line 352), add:

```go
		SendGridAPIKey:         sendGridAPIKey,
		SendGridListNewSignups: sendGridListNewSignups,
		SendGridListTrialUsers: sendGridListTrialUsers,
		SendGridListLeads:      sendGridListLeads,
		SendGridListDormant:    sendGridListDormant,
		SGFieldSegment:         sgFieldSegment,
		SGFieldTenantID:        sgFieldTenantID,
		SGFieldFirstLoginAt:    sgFieldFirstLoginAt,
		SGFieldLastLoginAt:     sgFieldLastLoginAt,
		SGFieldIsPQL:           sgFieldIsPQL,
		SGFieldPlanType:        sgFieldPlanType,
```

- [ ] **Step 2.4: Add to `.env.example`**

Append to the end of `.env.example`:

```bash


# ─── SendGrid Marketing Campaigns ────────────────────────────────────────────
# API key with "Marketing" read/write permissions.
SENDGRID_API_KEY=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

# Contact list IDs (from SendGrid dashboard → Marketing → Lists)
SENDGRID_LIST_NEW_SIGNUPS=6341c397-1de5-43d2-b957-8c258cce12dc
SENDGRID_LIST_TRIAL_USERS=d205a4f4-aa63-43a3-b9e6-ab91d760de3f
SENDGRID_LIST_LEADS=1d672677-7c3f-48be-8bd7-1597eb488827
SENDGRID_LIST_DORMANT=24a16f32-9361-4714-9e68-309dfb789d1e

# Custom field IDs (from GET /v3/marketing/field_definitions)
# Note: plan_type is w6_T (not e6_T) — confirmed from live account.
SG_FIELD_SEGMENT=e1_T
SG_FIELD_TENANT_ID=e2_T
SG_FIELD_FIRST_LOGIN_AT=e3_D
SG_FIELD_LAST_LOGIN_AT=e4_D
SG_FIELD_IS_PQL=e5_T
SG_FIELD_PLAN_TYPE=w6_T
```

- [ ] **Step 2.5: Verify compilation**

```bash
go build ./config/...
```

Expected: no errors.

- [ ] **Step 2.6: Commit**

```bash
git add config/config.go .env.example
git commit -m "feat: add SendGrid config fields to AppConfig"
```

---

## Task 3: SendGrid service

**Files:**
- Create: `services/sendgrid_service.go`
- Create: `services/sendgrid_service_test.go`

- [ ] **Step 3.1: Write the failing tests first**

Create `services/sendgrid_service_test.go`:

```go
package services_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/services"
)

// newTestSendGridService creates a SendGridService pointed at a test server.
func newTestSendGridService(t *testing.T, handler http.Handler) (*services.SendGridService, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	svc := services.NewSendGridServiceWithBaseURL("test-key", srv.URL)
	return svc, srv
}

func TestUpsertContact_FirstLogin(t *testing.T) {
	var gotBody map[string]interface{}
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job_id":"test-job-123"}`))
	}))
	defer srv.Close()

	svc := services.NewSendGridServiceWithBaseURL("Bearer sg-key", srv.URL)

	jobID, err := svc.UpsertContact("user@example.com", "Alice", "list-id-abc", map[string]string{
		"e1_T": "new-signup",
		"e2_T": "tenant-xyz",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if jobID != "test-job-123" {
		t.Errorf("expected job_id test-job-123, got %s", jobID)
	}
	if gotAuth != "Bearer sg-key" {
		t.Errorf("expected auth header 'Bearer sg-key', got %s", gotAuth)
	}

	// Verify list_ids is set when listID is non-empty
	listIDs, ok := gotBody["list_ids"].([]interface{})
	if !ok || len(listIDs) == 0 || listIDs[0] != "list-id-abc" {
		t.Errorf("expected list_ids=[list-id-abc], got %v", gotBody["list_ids"])
	}
}

func TestUpsertContact_ReturningUser_NoListAssignment(t *testing.T) {
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job_id":"job-456"}`))
	}))
	defer srv.Close()

	svc := services.NewSendGridServiceWithBaseURL("key", srv.URL)

	_, err := svc.UpsertContact("user@example.com", "", "", map[string]string{"e4_D": "2026-06-04"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// list_ids must NOT be present when listID is empty
	if _, exists := gotBody["list_ids"]; exists {
		t.Errorf("list_ids must be absent for returning-user update, got %v", gotBody["list_ids"])
	}
}

func TestUpsertContact_Non202_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"invalid api key"}]}`))
	}))
	defer srv.Close()

	svc := services.NewSendGridServiceWithBaseURL("bad-key", srv.URL)
	_, err := svc.UpsertContact("x@y.com", "", "", nil)
	if err == nil {
		t.Fatal("expected error for non-202 response, got nil")
	}
}

func TestRemoveFromLists_ResolvesContactThenDeletes(t *testing.T) {
	var deletePaths []string

	mux := http.NewServeMux()
	mux.HandleFunc("/v3/marketing/contacts/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":[{"id":"contact-id-999","email":"user@example.com"}]}`))
	})
	mux.HandleFunc("/v3/marketing/lists/", func(w http.ResponseWriter, r *http.Request) {
		deletePaths = append(deletePaths, r.URL.Path+"?"+r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := services.NewSendGridServiceWithBaseURL("key", srv.URL)
	err := svc.RemoveFromLists("user@example.com", []string{"list-aaa", "list-bbb"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deletePaths) != 2 {
		t.Errorf("expected 2 DELETE calls, got %d: %v", len(deletePaths), deletePaths)
	}
}

func TestRemoveFromLists_ContactNotFound_Skips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()

	svc := services.NewSendGridServiceWithBaseURL("key", srv.URL)
	err := svc.RemoveFromLists("ghost@example.com", []string{"list-xyz"})
	if err != nil {
		t.Fatalf("expected no error for unknown contact, got %v", err)
	}
}
```

- [ ] **Step 3.2: Run to confirm tests fail**

```bash
go test ./services/... -run "TestUpsertContact|TestRemoveFromLists" -v 2>&1 | head -30
```

Expected: compilation error — `SendGridService`, `NewSendGridServiceWithBaseURL` undefined.

- [ ] **Step 3.3: Implement `services/sendgrid_service.go`**

Create `services/sendgrid_service.go`:

```go
package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const sendGridBaseURL = "https://api.sendgrid.com"

// SendGridService handles communication with the SendGrid Marketing Campaigns API.
type SendGridService struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewSendGridService creates a SendGridService using the provided API key and the
// default SendGrid base URL.
func NewSendGridService(apiKey string) *SendGridService {
	return &SendGridService{
		apiKey:     "Bearer " + apiKey,
		baseURL:    sendGridBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// NewSendGridServiceWithBaseURL is like NewSendGridService but targets a custom
// base URL. Used by tests to point at an httptest.Server.
func NewSendGridServiceWithBaseURL(apiKey, baseURL string) *SendGridService {
	return &SendGridService{
		apiKey:     apiKey,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// UpsertContact creates or updates a SendGrid marketing contact.
// Pass listID="" to perform a field-only update without assigning a list
// (required for returning-user last_login_at updates and PQL field updates,
// to avoid restarting automation sequences).
// Returns the async job_id from the 202 response.
func (s *SendGridService) UpsertContact(email, firstName, listID string, customFields map[string]string) (string, error) {
	type contact struct {
		Email        string            `json:"email"`
		FirstName    string            `json:"first_name,omitempty"`
		CustomFields map[string]string `json:"custom_fields,omitempty"`
	}
	type payload struct {
		ListIDs  []string  `json:"list_ids,omitempty"`
		Contacts []contact `json:"contacts"`
	}

	p := payload{
		Contacts: []contact{{Email: email, FirstName: firstName, CustomFields: customFields}},
	}
	if listID != "" {
		p.ListIDs = []string{listID}
	}

	body, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("sendgrid: marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, s.baseURL+"/v3/marketing/contacts", bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("sendgrid: build request: %w", err)
	}
	req.Header.Set("Authorization", s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sendgrid: PUT /v3/marketing/contacts: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("sendgrid: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(respBody, &result)
	return result.JobID, nil
}

// RemoveFromLists removes a contact from one or more SendGrid lists.
// If the contact is not found in SendGrid the call is a no-op (not an error).
func (s *SendGridService) RemoveFromLists(email string, listIDs []string) error {
	contactID, err := s.resolveContactID(email)
	if err != nil {
		return err
	}
	if contactID == "" {
		log.Printf("sendgrid: contact %s not found — skipping list removal", email)
		return nil
	}

	for _, listID := range listIDs {
		url := fmt.Sprintf("%s/v3/marketing/lists/%s/contacts?contact_ids=%s", s.baseURL, listID, contactID)
		req, err := http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			return fmt.Errorf("sendgrid: build DELETE request for list %s: %w", listID, err)
		}
		req.Header.Set("Authorization", s.apiKey)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sendgrid: DELETE from list %s: %w", listID, err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
			log.Printf("sendgrid: unexpected status %d removing contact %s from list %s", resp.StatusCode, email, listID)
		}
	}
	return nil
}

// resolveContactID looks up a contact by email and returns their SendGrid contact ID.
// Returns ("", nil) when the contact does not exist.
func (s *SendGridService) resolveContactID(email string) (string, error) {
	query := fmt.Sprintf(`{"query":"email = '%s'"}`, email)
	req, err := http.NewRequest(http.MethodPost, s.baseURL+"/v3/marketing/contacts/search", bytes.NewBufferString(query))
	if err != nil {
		return "", fmt.Errorf("sendgrid: build search request: %w", err)
	}
	req.Header.Set("Authorization", s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sendgrid: search contacts: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("sendgrid: decode search response: %w", err)
	}
	if len(result.Result) == 0 {
		return "", nil
	}
	return result.Result[0].ID, nil
}
```

- [ ] **Step 3.4: Run tests and confirm they pass**

```bash
go test ./services/... -run "TestUpsertContact|TestRemoveFromLists" -v
```

Expected output (all PASS):
```
--- PASS: TestUpsertContact_FirstLogin
--- PASS: TestUpsertContact_ReturningUser_NoListAssignment
--- PASS: TestUpsertContact_Non202_ReturnsError
--- PASS: TestRemoveFromLists_ResolvesContactThenDeletes
--- PASS: TestRemoveFromLists_ContactNotFound_Skips
PASS
```

- [ ] **Step 3.5: Commit**

```bash
git add services/sendgrid_service.go services/sendgrid_service_test.go
git commit -m "feat: add SendGridService with UpsertContact and RemoveFromLists"
```

---

## Task 4: Tenant DB migration — dormant columns

**Files:**
- Create: `migrations/tenant/109_add_dormant_columns.sql`

- [ ] **Step 4.1: Write the migration**

Create `migrations/tenant/109_add_dormant_columns.sql`:

```sql
-- Adds columns needed to track dormant-list enrollment state per user.
-- dormant_enrolled: true once the user has been added to the dormant re-engagement list.
-- dormant_enrolled_at: timestamp of the most recent dormant enrollment (used for 90-day cooloff).
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS dormant_enrolled    BOOLEAN   NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS dormant_enrolled_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_users_dormant_enrolled
    ON users (dormant_enrolled, last_login)
    WHERE active = true;
```

- [ ] **Step 4.2: Verify SQL parses (requires psql)**

```bash
psql --no-psqlrc -c "\i migrations/tenant/109_add_dormant_columns.sql" 2>&1 | head -5
```

If psql is not available locally, skip to 4.3 — the migration runner will validate at startup.

- [ ] **Step 4.3: Commit**

```bash
git add migrations/tenant/109_add_dormant_columns.sql
git commit -m "feat: add dormant_enrolled columns to tenant users table"
```

---

## Task 5: Enduser repository — dormant DB methods

**Files:**
- Modify: `database/enduser_repository.go`

The `EndUserRepository` uses `executeQuery` and `executeExec` helper methods that accept either a master `*DBConnection` or a tenant `*sql.DB`. These new methods follow that same pattern.

- [ ] **Step 5.1: Add the `DormantUserRow` type and three methods**

Append to the end of `database/enduser_repository.go`:

```go

// DormantUserRow holds the fields needed by the dormant enrollment job.
type DormantUserRow struct {
	Email     string
	FirstName string
	TenantID  string
}

// GetDormantUsers returns users who have not logged in since cutoff, are active,
// and either have never been enrolled in the dormant list or were enrolled before
// cooloffDate (90-day re-enrollment guard).
func (eur *EndUserRepository) GetDormantUsers(cutoff, cooloffDate time.Time) ([]DormantUserRow, error) {
	query := `
		SELECT COALESCE(email, ''), COALESCE(name, ''), COALESCE(tenant_id::text, '')
		FROM users
		WHERE last_login < $1
		  AND active = true
		  AND (
		        dormant_enrolled = false
		        OR (dormant_enrolled = true AND dormant_enrolled_at < $2)
		      )
	`
	rows, err := eur.executeQuery(query, cutoff, cooloffDate)
	if err != nil {
		return nil, fmt.Errorf("GetDormantUsers: %w", err)
	}
	defer rows.Close()

	var users []DormantUserRow
	for rows.Next() {
		var u DormantUserRow
		if err := rows.Scan(&u.Email, &u.FirstName, &u.TenantID); err != nil {
			return nil, fmt.Errorf("GetDormantUsers scan: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// MarkDormantEnrolled sets dormant_enrolled=true and records the current timestamp.
// Call this after successfully adding the user to the SendGrid dormant list.
func (eur *EndUserRepository) MarkDormantEnrolled(email string) error {
	query := `UPDATE users SET dormant_enrolled = true, dormant_enrolled_at = NOW(), updated_at = NOW() WHERE email = $1`
	_, err := eur.executeExec(query, email)
	if err != nil {
		return fmt.Errorf("MarkDormantEnrolled(%s): %w", email, err)
	}
	return nil
}

// ResetDormantEnrolled clears the dormant flag when a dormant user logs back in,
// so the nightly job can re-enroll them if they go quiet again.
func (eur *EndUserRepository) ResetDormantEnrolled(email string) error {
	query := `UPDATE users SET dormant_enrolled = false, dormant_enrolled_at = NULL, updated_at = NOW() WHERE email = $1`
	_, err := eur.executeExec(query, email)
	if err != nil {
		return fmt.Errorf("ResetDormantEnrolled(%s): %w", email, err)
	}
	return nil
}
```

- [ ] **Step 5.2: Compile the database package**

```bash
go build ./database/...
```

Expected: no errors.

- [ ] **Step 5.3: Commit**

```bash
git add database/enduser_repository.go
git commit -m "feat: add GetDormantUsers, MarkDormantEnrolled, ResetDormantEnrolled to EndUserRepository"
```

---

## Task 6: Extend `EndUserController` and update `NotifyOwnerNewRegistration`

**Files:**
- Modify: `controllers/enduser/enduser_controller.go`

The `EndUserController` struct is currently `struct{}`. We add a `sg *services.SendGridService` field and a constructor. The existing methods are value receivers on the empty struct and continue to work — only `NotifyOwnerNewRegistration` reads `sg`.

- [ ] **Step 6.1: Replace the empty struct and add constructor**

In `enduser_controller.go`, replace line 32:

```go
type EndUserController struct{}
```

with:

```go
// EndUserController handles end-user HTTP endpoints.
type EndUserController struct {
	sg *services.SendGridService // nil-safe: SendGrid calls are skipped if not configured
}

// NewEndUserController creates an EndUserController with a SendGrid service.
// Pass nil for sg to run without SendGrid (e.g., in unit tests).
func NewEndUserController(sg *services.SendGridService) *EndUserController {
	return &EndUserController{sg: sg}
}
```

- [ ] **Step 6.2: Replace `NotifyOwnerNewRegistration` with the new implementation**

Replace the entire `NotifyOwnerNewRegistration` function (lines ~2967–3019) with:

```go
// NotifyOwnerNewRegistration godoc
// @Summary Notify tenant owner about a new user registration and sync to SendGrid
// @Description Sends owner notification email on every login. On first_login=true enrolls the
// user in the SendGrid nurture sequence. On first_login=false updates last_login_at only.
// @Tags EndUser
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body object true "Login notification payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/auth/notify/new-user-registration [post]
func (euc *EndUserController) NotifyOwnerNewRegistration(c *gin.Context) {
	const ownerEmail = "a@authnull.com"

	var input struct {
		UserName     string `json:"user_name,omitempty"`
		TenantDomain string `json:"tenant_domain,omitempty"`
		FirstLogin   bool   `json:"first_login"`
		Segment      string `json:"segment,omitempty"`
	}
	_ = c.ShouldBindJSON(&input)

	userEmail := c.GetString("email_id")
	if userEmail == "" {
		userEmail = c.GetString("email")
	}
	if userEmail == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user email not found in authentication token"})
		return
	}

	tenantID, ok := amMiddlewares.GetTenantIDFromToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id not found in authentication token"})
		return
	}

	userName := input.UserName
	if userName == "" {
		userName = userEmail
	}
	tenantDomain := input.TenantDomain
	if tenantDomain == "" {
		tenantDomain = tenantID
	}

	// Existing behaviour: notify tenant owner.
	if err := utils.SendNewUserRegistrationNotificationEmail(ownerEmail, userName, userEmail, tenantDomain); err != nil {
		log.Printf("NotifyOwnerNewRegistration: failed to send notification email to %s: %v", ownerEmail, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send notification email"})
		return
	}

	// SendGrid sync — fire-and-forget; failures are logged but do not affect the response.
	if euc.sg != nil {
		euc.syncSendGrid(c, userEmail, tenantID, input.FirstLogin)
	}

	log.Printf("NotifyOwnerNewRegistration: notification sent to %s for new user %s in tenant %s", ownerEmail, userEmail, tenantID)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Owner notification email sent successfully",
		"owner_email": ownerEmail,
		"user_email":  userEmail,
	})
}

// syncSendGrid handles the SendGrid branch of NotifyOwnerNewRegistration.
// It is separated to keep the main handler readable.
func (euc *EndUserController) syncSendGrid(c *gin.Context, userEmail, tenantID string, firstLogin bool) {
	cfg := config.GetConfig()
	today := time.Now().UTC().Format("2006-01-02")

	if firstLogin {
		jobID, err := euc.sg.UpsertContact(userEmail, "", cfg.SendGridListNewSignups, map[string]string{
			cfg.SGFieldSegment:      "new-signup",
			cfg.SGFieldTenantID:     tenantID,
			cfg.SGFieldFirstLoginAt: today,
			cfg.SGFieldPlanType:     "trial",
			cfg.SGFieldIsPQL:        "false",
		})
		if err != nil {
			log.Printf("syncSendGrid: first-login upsert failed for %s: %v", userEmail, err)
			return
		}
		log.Printf(`{"sendgrid_job_id":%q,"list":"seg-new-signups","contact":%q}`, jobID, userEmail)
		return
	}

	// Returning user — check if they were dormant.
	isDormant, err := euc.isDormantEnrolled(c, userEmail, tenantID)
	if err != nil {
		log.Printf("syncSendGrid: dormant check failed for %s: %v", userEmail, err)
	}

	if isDormant {
		// Re-enroll in trial sequence and exit dormant.
		jobID, err := euc.sg.UpsertContact(userEmail, "", cfg.SendGridListTrialUsers, map[string]string{
			cfg.SGFieldLastLoginAt: today,
			cfg.SGFieldSegment:     "trial",
		})
		if err != nil {
			log.Printf("syncSendGrid: dormant re-enroll failed for %s: %v", userEmail, err)
		} else {
			log.Printf(`{"sendgrid_job_id":%q,"list":"seg-trial-users","contact":%q}`, jobID, userEmail)
		}
		if removeErr := euc.sg.RemoveFromLists(userEmail, []string{cfg.SendGridListDormant}); removeErr != nil {
			log.Printf("syncSendGrid: remove from dormant failed for %s: %v", userEmail, removeErr)
		}
		euc.resetDormantFlag(c, userEmail, tenantID)
		return
	}

	// Normal returning user — update last_login_at only, no list assignment.
	jobID, err := euc.sg.UpsertContact(userEmail, "", "", map[string]string{
		cfg.SGFieldLastLoginAt: today,
	})
	if err != nil {
		log.Printf("syncSendGrid: returning-user update failed for %s: %v", userEmail, err)
		return
	}
	log.Printf(`{"sendgrid_job_id":%q,"list":"none","contact":%q}`, jobID, userEmail)
}

// isDormantEnrolled queries the tenant DB to check whether the user has dormant_enrolled=true.
func (euc *EndUserController) isDormantEnrolled(c *gin.Context, email, tenantID string) (bool, error) {
	tenantDB, err := tenantConnectionProvider(config.DB, nil, &tenantID)
	if err != nil {
		return false, fmt.Errorf("isDormantEnrolled: get tenant db: %w", err)
	}

	var enrolled bool
	result := tenantDB.Raw(
		"SELECT dormant_enrolled FROM users WHERE LOWER(email) = LOWER($1) AND active = true LIMIT 1",
		email,
	).Scan(&enrolled)
	if result.Error != nil {
		return false, fmt.Errorf("isDormantEnrolled: query: %w", result.Error)
	}
	return enrolled, nil
}

// resetDormantFlag sets dormant_enrolled=false for the user in their tenant DB.
func (euc *EndUserController) resetDormantFlag(c *gin.Context, email, tenantID string) {
	tenantDB, err := tenantConnectionProvider(config.DB, nil, &tenantID)
	if err != nil {
		log.Printf("resetDormantFlag: get tenant db: %v", err)
		return
	}
	if err := tenantDB.Exec(
		"UPDATE users SET dormant_enrolled = false, dormant_enrolled_at = NULL, updated_at = NOW() WHERE LOWER(email) = LOWER($1)",
		email,
	).Error; err != nil {
		log.Printf("resetDormantFlag: update failed for %s: %v", email, err)
	}
}
```

- [ ] **Step 6.3: Add `NotifyPlanUpgrade` handler at the end of the file**

Append to `controllers/enduser/enduser_controller.go`:

```go

// NotifyPlanUpgrade godoc
// @Summary Record a plan upgrade in SendGrid and exit all nurture lists
// @Description Updates plan_type in SendGrid and removes the user from all four nurture lists,
// stopping the sequence. Call this when a user's subscription moves to a paid plan.
// @Tags EndUser
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body object true "Upgrade payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/auth/notify/plan-upgrade [post]
func (euc *EndUserController) NotifyPlanUpgrade(c *gin.Context) {
	var input struct {
		NewPlan string `json:"new_plan" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new_plan is required"})
		return
	}

	userEmail := c.GetString("email_id")
	if userEmail == "" {
		userEmail = c.GetString("email")
	}
	if userEmail == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user email not found in token"})
		return
	}

	if euc.sg == nil {
		c.JSON(http.StatusOK, gin.H{"message": "plan upgrade recorded (SendGrid not configured)", "new_plan": input.NewPlan})
		return
	}

	cfg := config.GetConfig()

	if _, err := euc.sg.UpsertContact(userEmail, "", "", map[string]string{
		cfg.SGFieldPlanType: input.NewPlan,
	}); err != nil {
		log.Printf("NotifyPlanUpgrade: field update failed for %s: %v", userEmail, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update SendGrid contact"})
		return
	}

	allNurtureLists := []string{
		cfg.SendGridListNewSignups,
		cfg.SendGridListTrialUsers,
		cfg.SendGridListLeads,
		cfg.SendGridListDormant,
	}
	if err := euc.sg.RemoveFromLists(userEmail, allNurtureLists); err != nil {
		log.Printf("NotifyPlanUpgrade: list removal failed for %s: %v", userEmail, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove contact from nurture lists"})
		return
	}

	log.Printf("NotifyPlanUpgrade: %s upgraded to %s — removed from all nurture lists", userEmail, input.NewPlan)
	c.JSON(http.StatusOK, gin.H{
		"message":  "plan upgrade recorded",
		"new_plan": input.NewPlan,
	})
}
```

- [ ] **Step 6.4: Compile the controller package**

```bash
go build ./controllers/enduser/...
```

Expected: no errors.

- [ ] **Step 6.5: Commit**

```bash
git add controllers/enduser/enduser_controller.go
git commit -m "feat: extend NotifyOwnerNewRegistration with SendGrid sync; add NotifyPlanUpgrade"
```

---

## Task 7: PQL hook in `HubSpotController`

**Files:**
- Modify: `controllers/platform/hubspot_controller.go`

- [ ] **Step 7.1: Add `sg` field and update constructor**

Replace the current `HubSpotController` struct and `NewHubSpotController`:

```go
// HubSpotController handles HubSpot integration endpoints
type HubSpotController struct {
	hubspotService *services.HubSpotService
	sg             *services.SendGridService
}

// NewHubSpotController creates a new HubSpot controller.
func NewHubSpotController(sg *services.SendGridService) *HubSpotController {
	cfg := config.GetConfig()
	return &HubSpotController{
		hubspotService: services.NewHubSpotService(cfg.HubSpotAccessToken),
		sg:             sg,
	}
}
```

- [ ] **Step 7.2: Extend `SyncContact` to fire the SendGrid PQL update**

In `SyncContact`, after the successful `hc.hubspotService.SyncContact(...)` call and before the final `c.JSON(http.StatusOK, ...)`, insert:

```go
	// Update is_pql in SendGrid for segmentation/reporting.
	// No list change — the nurture sequence continues until the user upgrades or unsubscribes.
	if hc.sg != nil {
		cfg := config.GetConfig()
		if _, err := hc.sg.UpsertContact(req.Email, "", "", map[string]string{
			cfg.SGFieldIsPQL: "true",
		}); err != nil {
			log.Printf("[HubSpot] SendGrid PQL field update failed for %s: %v", req.Email, err)
			// non-fatal — HubSpot sync succeeded
		}
	}
```

- [ ] **Step 7.3: Compile the platform controller package**

```bash
go build ./controllers/platform/...
```

Expected: no errors.

- [ ] **Step 7.4: Commit**

```bash
git add controllers/platform/hubspot_controller.go
git commit -m "feat: update SendGrid is_pql field when HubSpot PQL sync fires"
```

---

## Task 8: Dormant worker service

**Files:**
- Create: `services/dormant_job.go`

The dormant worker runs as a cron job (02:00 UTC daily). It reads all tenants from the master DB, opens a `*sql.DB` connection to each tenant's database, queries dormant users, and moves them to the SendGrid dormant list.

- [ ] **Step 8.1: Create `services/dormant_job.go`**

```go
package services

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/database"
	"github.com/robfig/cron/v3"
)

// DormantWorker runs a nightly job that moves inactive users to the SendGrid dormant list.
type DormantWorker struct {
	masterDB *database.DBConnection
	sg       *SendGridService
	cfg      dormantCfg
	cron     *cron.Cron
}

// dormantCfg holds the config values the worker needs, extracted at construction time.
type dormantCfg struct {
	dbHost, dbUser, dbPassword, dbPort string
	dbSSLMode                          string
	listNewSignups, listTrialUsers     string
	listLeads, listDormant             string
	fieldSegment                       string
}

// NewDormantWorker creates a DormantWorker.
// masterDB is the authsec master database (holds the tenants table).
// sg must not be nil.
func NewDormantWorker(masterDB *database.DBConnection, sg *SendGridService, dbHost, dbUser, dbPassword, dbPort, dbSSLMode string,
	listNewSignups, listTrialUsers, listLeads, listDormant, fieldSegment string) *DormantWorker {
	return &DormantWorker{
		masterDB: masterDB,
		sg:       sg,
		cfg: dormantCfg{
			dbHost: dbHost, dbUser: dbUser, dbPassword: dbPassword, dbPort: dbPort, dbSSLMode: dbSSLMode,
			listNewSignups: listNewSignups, listTrialUsers: listTrialUsers,
			listLeads: listLeads, listDormant: listDormant,
			fieldSegment: fieldSegment,
		},
	}
}

// Start registers the nightly cron (02:00 UTC) and begins the scheduler.
// The returned stop function should be called on server shutdown.
func (w *DormantWorker) Start() (stop func()) {
	w.cron = cron.New(cron.WithLocation(time.UTC))
	_, err := w.cron.AddFunc("0 2 * * *", func() {
		log.Println("dormant-worker: starting nightly run")
		w.run()
		log.Println("dormant-worker: nightly run complete")
	})
	if err != nil {
		log.Printf("dormant-worker: failed to schedule cron: %v", err)
		return func() {}
	}
	w.cron.Start()
	log.Println("dormant-worker: cron scheduler started (runs at 02:00 UTC)")
	return func() { <-w.cron.Stop().Done() }
}

// run executes one dormant sweep across all tenant databases.
func (w *DormantWorker) run() {
	tenants, err := w.listTenants()
	if err != nil {
		log.Printf("dormant-worker: failed to list tenants: %v", err)
		return
	}

	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	cooloff := time.Now().UTC().Add(-90 * 24 * time.Hour)

	for _, t := range tenants {
		if t.tenantDB == "" {
			continue
		}
		if err := w.processTenant(t, cutoff, cooloff); err != nil {
			log.Printf("dormant-worker: tenant %s: %v", t.tenantID, err)
		}
	}
}

type tenantRow struct {
	tenantID string
	tenantDB string
}

func (w *DormantWorker) listTenants() ([]tenantRow, error) {
	rows, err := w.masterDB.Query("SELECT tenant_id, COALESCE(tenant_db, '') FROM tenants WHERE status != 'deleted'")
	if err != nil {
		return nil, fmt.Errorf("query tenants: %w", err)
	}
	defer rows.Close()

	var tenants []tenantRow
	for rows.Next() {
		var t tenantRow
		if err := rows.Scan(&t.tenantID, &t.tenantDB); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}

func (w *DormantWorker) processTenant(t tenantRow, cutoff, cooloff time.Time) error {
	sslMode := w.cfg.dbSSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		w.cfg.dbHost, w.cfg.dbUser, w.cfg.dbPassword, t.tenantDB, w.cfg.dbPort, sslMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open tenant db %s: %w", t.tenantDB, err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping tenant db %s: %w", t.tenantDB, err)
	}

	users, err := w.queryDormantUsers(db, cutoff, cooloff)
	if err != nil {
		return fmt.Errorf("query dormant users: %w", err)
	}

	for _, u := range users {
		w.enrollDormant(db, u)
	}
	return nil
}

type dormantUser struct {
	email     string
	firstName string
}

func (w *DormantWorker) queryDormantUsers(db *sql.DB, cutoff, cooloff time.Time) ([]dormantUser, error) {
	query := `
		SELECT COALESCE(email, ''), COALESCE(name, '')
		FROM users
		WHERE last_login < $1
		  AND active = true
		  AND (
		        dormant_enrolled = false
		        OR (dormant_enrolled = true AND dormant_enrolled_at < $2)
		      )
	`
	rows, err := db.Query(query, cutoff, cooloff)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var users []dormantUser
	for rows.Next() {
		var u dormantUser
		if err := rows.Scan(&u.email, &u.firstName); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if u.email != "" {
			users = append(users, u)
		}
	}
	return users, rows.Err()
}

func (w *DormantWorker) enrollDormant(db *sql.DB, u dormantUser) {
	cfg := w.cfg

	// Remove from active nurture lists first.
	if err := w.sg.RemoveFromLists(u.email, []string{cfg.listNewSignups, cfg.listTrialUsers, cfg.listLeads}); err != nil {
		log.Printf("dormant-worker: remove from active lists failed for %s: %v", u.email, err)
	}

	// Add to dormant re-engagement sequence.
	jobID, err := w.sg.UpsertContact(u.email, u.firstName, cfg.listDormant, map[string]string{
		cfg.fieldSegment: "dormant",
	})
	if err != nil {
		log.Printf("dormant-worker: enroll in dormant list failed for %s: %v", u.email, err)
		return
	}
	log.Printf(`{"sendgrid_job_id":%q,"list":"seg-dormant","contact":%q}`, jobID, u.email)

	// Mark enrolled so the job doesn't re-enroll on the next run.
	if _, err := db.Exec(
		`UPDATE users SET dormant_enrolled = true, dormant_enrolled_at = NOW(), updated_at = NOW() WHERE LOWER(email) = LOWER($1)`,
		u.email,
	); err != nil {
		log.Printf("dormant-worker: mark enrolled failed for %s: %v", u.email, err)
	}
}
```

- [ ] **Step 8.2: Compile the services package**

```bash
go build ./services/...
```

Expected: no errors.

- [ ] **Step 8.3: Commit**

```bash
git add services/dormant_job.go
git commit -m "feat: add DormantWorker service for nightly dormant-user SendGrid enrollment"
```

---

## Task 9: Wire everything in `routes/routes.go`

**Files:**
- Modify: `routes/routes.go`

- [ ] **Step 9.1: Create the `SendGridService` and update controller constructors**

In `routes/routes.go`, find where `hubspotController` is created (~line 112):

```go
hubspotController := platformCtrl.NewHubSpotController()
```

Replace it with:

```go
sgSvc := services.NewSendGridService(config.GetConfig().SendGridAPIKey)
hubspotController := platformCtrl.NewHubSpotController(sgSvc)
```

Also find where `endUserController` is created (~line 101):

```go
endUserController := &userCtrl.EndUserController{}
```

Replace it with:

```go
endUserController := userCtrl.NewEndUserController(sgSvc)
```

Note: `sgSvc` must be defined before both controllers, so place the `sgSvc` line first (before `endUserController`).

- [ ] **Step 9.2: Add the `services` import if not already present**

In `routes/routes.go`, confirm `services` is in the import block. If missing, add:

```go
"github.com/authsec-ai/authsec/services"
```

- [ ] **Step 9.3: Register the plan-upgrade route**

Find the `notify` route group (~lines 556–560):

```go
notify := auth.Group("/notify")
notify.Use(middlewares.AuthMiddleware(), amMiddlewares.ValidateTenantFromToken())
{
    notify.POST("/new-user-registration", endUserController.NotifyOwnerNewRegistration)
}
```

Add the new route:

```go
notify := auth.Group("/notify")
notify.Use(middlewares.AuthMiddleware(), amMiddlewares.ValidateTenantFromToken())
{
    notify.POST("/new-user-registration", endUserController.NotifyOwnerNewRegistration)
    notify.POST("/plan-upgrade", endUserController.NotifyPlanUpgrade)
}
```

- [ ] **Step 9.4: Compile routes**

```bash
go build ./routes/...
```

Expected: no errors.

- [ ] **Step 9.5: Compile the whole project**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 9.6: Commit**

```bash
git add routes/routes.go
git commit -m "feat: wire SendGridService into controllers; register plan-upgrade route"
```

---

## Task 10: Start `DormantWorker` in `cmd/main.go`

**Files:**
- Modify: `cmd/main.go`

- [ ] **Step 10.1: Add the import for `_ "github.com/lib/pq"` if not already there**

Check `cmd/main.go` imports — `github.com/lib/pq` is already imported as `_ "github.com/lib/pq"` (required for `sql.Open("postgres", ...)`). Confirm with:

```bash
grep "lib/pq" cmd/main.go
```

Expected: line present. If missing add it to the import block.

- [ ] **Step 10.2: Start the dormant worker in Phase 4 (background workers)**

In `cmd/main.go`, find the Phase 4 comment block (~line 225). After the existing background workers, add before the Phase 5 comment:

```go
	// Dormant user re-engagement job (runs nightly at 02:00 UTC).
	// Moves users inactive for 30+ days into the SendGrid dormant list.
	if cfg.SendGridAPIKey != "" {
		sgSvcForCron := services.NewSendGridService(cfg.SendGridAPIKey)
		dormantWorker := services.NewDormantWorker(
			config.Database,
			sgSvcForCron,
			cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBPort, cfg.DBSSLMode,
			cfg.SendGridListNewSignups, cfg.SendGridListTrialUsers,
			cfg.SendGridListLeads, cfg.SendGridListDormant,
			cfg.SGFieldSegment,
		)
		stopDormant := dormantWorker.Start()
		defer stopDormant()
		log.Println("Dormant worker: scheduled (02:00 UTC daily)")
	} else {
		log.Println("Dormant worker: skipped (SENDGRID_API_KEY not set)")
	}
```

- [ ] **Step 10.3: Verify the full project builds**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 10.4: Run all tests**

```bash
go test ./... -timeout 60s 2>&1 | tail -20
```

Expected: all packages pass (or pre-existing failures only — no new failures).

- [ ] **Step 10.5: Commit**

```bash
git add cmd/main.go
git commit -m "feat: start DormantWorker cron job on server startup"
```

---

## Task 11: Populate `.env` with real values

**Files:**
- Modify: `.env` (local dev env only — never commit secrets)

- [ ] **Step 11.1: Add the SendGrid values to the live `.env`**

```bash
cat >> .env << 'EOF'

# SendGrid
SENDGRID_API_KEY=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
SENDGRID_LIST_NEW_SIGNUPS=6341c397-1de5-43d2-b957-8c258cce12dc
SENDGRID_LIST_TRIAL_USERS=d205a4f4-aa63-43a3-b9e6-ab91d760de3f
SENDGRID_LIST_LEADS=1d672677-7c3f-48be-8bd7-1597eb488827
SENDGRID_LIST_DORMANT=24a16f32-9361-4714-9e68-309dfb789d1e
SG_FIELD_SEGMENT=e1_T
SG_FIELD_TENANT_ID=e2_T
SG_FIELD_FIRST_LOGIN_AT=e3_D
SG_FIELD_LAST_LOGIN_AT=e4_D
SG_FIELD_IS_PQL=e5_T
SG_FIELD_PLAN_TYPE=w6_T
EOF
```

> `.env` is already in `.gitignore` — do NOT stage or commit it.

- [ ] **Step 11.2: Verify the server starts and logs the dormant worker**

```bash
go run ./cmd/main.go 2>&1 | grep -i "dormant\|sendgrid\|migration" | head -10
```

Expected lines like:
```
Master migrations completed successfully
Dormant worker: scheduled (02:00 UTC daily)
```

- [ ] **Step 11.3: Smoke-test the new endpoint (requires a running server and valid JWT)**

```bash
# Replace TOKEN and TENANT_ID with real values from a test login.
curl -s -X POST http://localhost:7468/authsec/uflow/auth/notify/new-user-registration \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"first_login":true,"segment":"new-signup"}' | jq .
```

Expected:
```json
{
  "message": "Owner notification email sent successfully",
  "owner_email": "a@authnull.com",
  "user_email": "<your test user email>"
}
```

Server log should contain a line matching:
```
{"sendgrid_job_id":"...","list":"seg-new-signups","contact":"<email>"}
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] Flow 1 (login enroll/update) — Tasks 6 + 9
- [x] Flow 2 (dormant cron) — Tasks 4 + 5 + 8 + 10
- [x] Flow 3 (PQL field update) — Task 7
- [x] Flow 4 (plan upgrade exit) — Task 6 (`NotifyPlanUpgrade`) + 9 (route)
- [x] Env vars with real IDs — Tasks 2 + 11
- [x] `robfig/cron` dependency — Task 1
- [x] Tenant migration — Task 4
- [x] `w6_T` for plan_type (not `e6_T`) — set as default in Task 2

**Placeholder scan:** No TBDs. All function signatures, SQL, and HTTP paths are exact.

**Type consistency:**
- `SendGridService.UpsertContact` returns `(string, error)` — matched in Tasks 3, 6, 7, 8
- `SendGridService.RemoveFromLists` returns `error` — matched in Tasks 6, 8
- `EndUserController.sg` is `*services.SendGridService` — nil-checked in every usage
- `DormantWorker.Start()` returns `func()` stop — called with `defer` in Task 10
- `NewHubSpotController(sg)` — constructor signature matches Task 9 call site
