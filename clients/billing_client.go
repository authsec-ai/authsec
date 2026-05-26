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

// CheckAndIncrementMAU checks MAU entitlement and atomically increments if allowed.
// Returns allowed=true, limit=-1 when billing service is not configured.
// On network error it logs and returns allowed=true (fail-open) so a transient billing
// outage never blocks end-user authentication.
func (c *BillingClient) CheckAndIncrementMAU(ctx context.Context, tenantID string) (*MAUEntitlementResponse, error) {
	if c.baseURL == "" {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, nil
	}

	token, err := c.serviceToken()
	if err != nil {
		return &MAUEntitlementResponse{Allowed: true, Limit: -1}, fmt.Errorf("billing: generate service token: %w", err)
	}

	body, _ := json.Marshal(map[string]string{"tenant_id": tenantID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/billing/usage/mau/increment", bytes.NewReader(body))
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
