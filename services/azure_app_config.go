package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

// Submitting an App Registration, and checking it before anything depends on it.
//
// The flow this serves: someone creates the registration in the Azure portal,
// hands AuthSec its details, and AuthSec answers one question -- does this
// application actually have what onboarding needs? If not, it names exactly what
// is missing and how to grant it. Nothing else can start until that answers yes,
// because every later failure would be a confusing symptom of this one cause.
//
// WHERE THE SECRET GOES. Vault, and only Vault. Postgres gets the path. The
// value is never returned by any endpoint, never logged, and never serialised:
// after this function it exists in this process's memory and in Vault, nowhere
// else.

// azureAppSecretPath is where a workspace's client secret lives.
func azureAppSecretPath(workspaceID uuid.UUID) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/azure/app", workspaceID.String())
}

// AzureAppConfigInput is what an operator submits after creating the app.
type AzureAppConfigInput struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	HomeTenant   string `json:"homeTenant"`
	RedirectURI  string `json:"redirectUri"`
}

// AzureAppConfigResult is the answer to "did that work, and is the app correct".
type AzureAppConfigResult struct {
	Stored *models.AzureAppConfig `json:"stored"`

	// Check is the verdict on the submitted application, run immediately rather
	// than left for later. A registration missing a permission is the single
	// most common setup mistake and produces a consent that succeeds while
	// granting nothing -- discovering that here costs one call, discovering it
	// during a customer's onboarding costs an afternoon.
	Check *AppCheckResult `json:"check,omitempty"`

	// CheckError is set when the application could not be read at all: a wrong
	// secret, a wrong client id, or a home tenant that does not hold this app.
	// Distinct from a check that ran and found faults.
	CheckError string `json:"check_error,omitempty"`
}

// SetAppConfig stores a workspace's App Registration and immediately verifies it.
//
// Validation happens before anything is written. A rejected submission must not
// leave a half-configured workspace behind, and in particular must not leave a
// secret in Vault that no row points at.
func (s *AzureOnboardService) SetAppConfig(
	ctx context.Context, workspaceID uuid.UUID, actor string, in AzureAppConfigInput,
) (*AzureAppConfigResult, error) {
	clientID := strings.TrimSpace(in.ClientID)
	secret := strings.TrimSpace(in.ClientSecret)
	homeTenant := strings.TrimSpace(in.HomeTenant)
	redirectURI := strings.TrimSpace(in.RedirectURI)

	var missing []string
	if clientID == "" {
		missing = append(missing, "clientId")
	}
	if secret == "" {
		missing = append(missing, "clientSecret")
	}
	if homeTenant == "" {
		missing = append(missing, "homeTenant")
	}
	if redirectURI == "" {
		missing = append(missing, "redirectUri")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	// Both are GUIDs on a real registration, and both are interpolated into
	// URLs. A typo caught here is a 400; the same typo stored is a puzzling
	// AADSTS error on someone else's screen later.
	if err := azureonboard.ValidateTenantID(homeTenant); err != nil {
		return nil, fmt.Errorf("homeTenant: %w", err)
	}
	if _, err := uuid.Parse(clientID); err != nil {
		return nil, errors.New("clientId is not the Application (client) ID guid")
	}
	if !strings.HasPrefix(redirectURI, "https://") && !strings.HasPrefix(redirectURI, "http://localhost") {
		return nil, errors.New("redirectUri must be https, or http://localhost for local development")
	}

	if s.vault == nil {
		return nil, errors.New("vault is not configured; the client secret cannot be stored")
	}
	path := azureAppSecretPath(workspaceID)
	if err := s.vault.WriteSecret(path, map[string]interface{}{
		"client_secret": secret,
	}); err != nil {
		return nil, fmt.Errorf("store client secret: %w", err)
	}

	stored, err := s.appCfgRepo().Upsert(&models.AzureAppConfig{
		WorkspaceID: workspaceID,
		ClientID:    clientID,
		HomeTenant:  homeTenant,
		RedirectURI: redirectURI,
		AuthRef:     path,
		CreatedBy:   actor,
	})
	if err != nil {
		return nil, err
	}

	// Verify against Microsoft with what was just submitted, not with whatever
	// this process was started with.
	res := &AzureAppConfigResult{Stored: stored}
	bound := s.bindApp(clientID, secret, redirectURI, homeTenant)
	check, cErr := bound.CheckAppRegistration(ctx)
	if cErr != nil {
		res.CheckError = cErr.Error()
		return res, nil
	}
	res.Check = check
	_ = s.appCfgRepo().MarkChecked(workspaceID)
	return res, nil
}

// GetAppConfig reports the stored application without its secret.
func (s *AzureOnboardService) GetAppConfig(workspaceID uuid.UUID) (*models.AzureAppConfig, error) {
	return s.appCfgRepo().Get(workspaceID)
}

// DeleteAppConfig removes the stored application and its secret.
//
// Vault first: a row pointing at a secret that is gone fails loudly on the next
// use, while a secret with no row pointing at it is an orphan nothing will ever
// clean up.
func (s *AzureOnboardService) DeleteAppConfig(workspaceID uuid.UUID) error {
	if s.vault != nil {
		_ = s.vault.DeleteSecret(azureAppSecretPath(workspaceID))
	}
	return s.appCfgRepo().Delete(workspaceID)
}

/* ----------------------------- resolution ----------------------------- */

// ForWorkspace returns a view of this service bound to one workspace's
// application: the stored row if there is one, else the deployment-wide env
// vars this service was constructed with.
//
// Returns a COPY. The receiver is shared across requests, so mutating it here
// would let one workspace's credentials leak into another's request.
//
// A missing row is not an error. It is the documented fallback, and it is what
// every existing deployment relies on.
func (s *AzureOnboardService) ForWorkspace(workspaceID uuid.UUID) *AzureOnboardService {
	// A client injected for tests must win: WithClient exists precisely so the
	// service can be driven without Microsoft, and re-resolving would undo it.
	if s.clientFixed {
		return s
	}
	cfg, err := s.appCfgRepo().Get(workspaceID)
	if err != nil || cfg == nil {
		return s
	}
	if s.vault == nil {
		return s
	}
	data, err := s.vault.ReadSecret(cfg.AuthRef)
	if err != nil {
		return s
	}
	secret, _ := data["client_secret"].(string)
	if strings.TrimSpace(secret) == "" {
		return s
	}
	return s.bindApp(cfg.ClientID, secret, cfg.RedirectURI, cfg.HomeTenant)
}

// bindApp returns a copy of the service using one specific application.
func (s *AzureOnboardService) bindApp(clientID, clientSecret, redirectURI, homeTenant string) *AzureOnboardService {
	c := *s
	c.clientID = clientID
	c.redirectURI = redirectURI
	c.homeTenant = homeTenant
	c.azure = azureonboard.NewHTTPClient(clientID, clientSecret)
	return &c
}

func (s *AzureOnboardService) appCfgRepo() repositories.AzureAppConfigRepository {
	if s.appCfg == nil {
		s.appCfg = repositories.NewAzureAppConfigRepository(s.db)
	}
	return s.appCfg
}

var _ = time.Now
