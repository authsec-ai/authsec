package services_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/services"
)

func TestUpsertContact_FirstLogin(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job_id":"test-job-123"}`))
	}))
	defer srv.Close()

	svc := services.NewSendGridServiceWithBaseURL("sg-key", srv.URL)

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

	listIDs, ok := gotBody["list_ids"].([]any)
	if !ok || len(listIDs) == 0 || listIDs[0] != "list-id-abc" {
		t.Errorf("expected list_ids=[list-id-abc], got %v", gotBody["list_ids"])
	}
}

func TestUpsertContact_ReturningUser_NoListAssignment(t *testing.T) {
	var gotBody map[string]any

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
