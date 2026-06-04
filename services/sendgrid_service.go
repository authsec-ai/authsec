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
		apiKey:     "Bearer " + apiKey,
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
	type searchPayload struct {
		Query string `json:"query"`
	}
	searchBody, err := json.Marshal(searchPayload{Query: fmt.Sprintf("email = '%s'", email)})
	if err != nil {
		return "", fmt.Errorf("sendgrid: marshal search payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, s.baseURL+"/v3/marketing/contacts/search", bytes.NewReader(searchBody))
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

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("sendgrid: search contacts status %d: %s", resp.StatusCode, string(b))
	}

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
