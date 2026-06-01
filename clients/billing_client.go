package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MAUEntitlementResponse mirrors billing-service's EntitlementResponse.
type MAUEntitlementResponse struct {
	Allowed     bool   `json:"allowed"`
	Resource    string `json:"resource"`
	Current     int    `json:"current"`
	Limit       int    `json:"limit"`
	PlanID      string `json:"plan_id"`
	UpgradeHint string `json:"upgrade_hint,omitempty"`
}

// BillingClient is a thin HTTP client for the billing-service internal API.
// When baseURL is empty all methods are no-ops that return allowed=true (OSS / single-tenant mode).
type BillingClient struct {
	baseURL    string
	sdkSecret  string
	httpClient *http.Client
}

func NewBillingClient(baseURL, sdkSecret string) *BillingClient {
	return &BillingClient{
		baseURL:   baseURL,
		sdkSecret: sdkSecret,
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
}

// CheckTotalUsers checks whether the workspace can add one more user given currentCount.
// Returns allowed=true, limit=-1 when billing service is not configured (OSS mode).
// Fails open on network errors so a billing outage never blocks user registration.
func (c *BillingClient) CheckTotalUsers(ctx context.Context, workspaceID string, currentCount int) (*MAUEntitlementResponse, error) {
func (c *BillingClient) CheckTotalUsers(ctx context.Context, workspaceID string, currentCount int) (*MAUEntitlementResponse, error) {
	if c.baseURL == "" {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, nil
	}

	token, err := c.serviceToken()
	if err != nil {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, fmt.Errorf("billing: generate service token: %w", err)
	}

	body, _ := json.Marshal(map[string]any{"tenant_id": workspaceID, "current_count": currentCount})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/billing/entitlement/total-users", bytes.NewReader(body))
	if err != nil {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, fmt.Errorf("billing: http: %w", err)
	}
	defer resp.Body.Close()

	var result MAUEntitlementResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, fmt.Errorf("billing: decode: %w", err)
	}
	return &result, nil
}

func (c *BillingClient) serviceToken() (string, error) {
	claims := jwt.MapClaims{
		"service": "authsec",
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(c.sdkSecret))
}
