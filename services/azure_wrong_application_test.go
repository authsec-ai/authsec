package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/google/uuid"
)

// A workspace that submitted its own Entra application must act as THAT
// application or as none at all.
//
// The failure this guards against is not an error message -- it is a silent
// wrong identity. ForWorkspace's bind-failure path returned a copy of the
// service that still held the deployment's own clientID, redirectURI and
// Microsoft client, and Ready() only mentioned bindProblem inside its
// "something is missing" branch. With AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and
// AZURE_REDIRECT_URI set -- the configuration .env.example ships -- nothing was
// missing, Ready() returned nil, and every call for that workspace ran as the
// deployment-wide application while the console displayed the workspace's own
// client id.
//
// The visible consequence: POST /api/azure/consent sends a customer's tenant
// administrator to grant admin consent to a DIFFERENT application in their own
// directory, and the resulting connector row is filed as though it were right.

const (
	deploymentClientID = "11111111-1111-1111-1111-111111111111"
	workspaceClientID  = "45ec9acc-c71c-4202-8203-603336648ce4"
)

// deploymentConfigured is the service as it exists when the deployment has its
// own AZURE_* variables set -- which is the case that hid the bug.
func deploymentConfigured(t *testing.T) *AzureOnboardService {
	t.Helper()
	return &AzureOnboardService{
		repo:        newFakeRepo(),
		clientID:    deploymentClientID,
		redirectURI: "http://localhost:8080/api/azure/callback",
		homeTenant:  testTenant,
		azure:       &fakeAzureClient{},
		vault:       failingVault{err: errors.New("route entry not found")},
		appCfg:      stubAppCfgRepo{cfg: storedApp()},
	}
}

func TestForWorkspace_UnreadableCredentialIsNotReadyEvenWithEnvConfigured(t *testing.T) {
	svc := deploymentConfigured(t)

	// Precondition: without a stored application this deployment IS ready.
	// If that stops being true the test proves nothing.
	bare := *svc
	bare.appCfg = stubAppCfgRepo{cfg: nil}
	if err := bare.ForWorkspace(uuid.New()).Ready(); err != nil {
		t.Fatalf("the deployment itself is not configured, so this proves nothing: %v", err)
	}

	err := svc.ForWorkspace(uuid.New()).Ready()
	if err == nil {
		t.Fatal("a workspace whose stored credential cannot be read reported itself ready, " +
			"so it would run as the deployment's application instead of its own")
	}
	if !errors.Is(err, azureonboard.ErrNotConfigured) {
		t.Errorf("not reported as a configuration failure: %v", err)
	}
	if !strings.Contains(err.Error(), "route entry not found") {
		t.Errorf("does not carry the reason: %q", err)
	}
}

// Belt and braces: even if a caller ignores Ready(), the bound copy must not be
// able to authenticate as anyone. Ready() is advisory; this is not.
func TestForWorkspace_ABindFailureLeavesNoUsableApplication(t *testing.T) {
	bound := deploymentConfigured(t).ForWorkspace(uuid.New())

	if bound.clientID != "" {
		t.Errorf("kept a client id (%q) after failing to bind -- and it is the "+
			"deployment's, not the workspace's", bound.clientID)
	}
	if bound.azure != nil {
		t.Error("kept a Microsoft client after failing to bind, so a caller that skips " +
			"Ready() still reaches Microsoft as the wrong application")
	}
	if bound.redirectURI != "" || bound.homeTenant != "" {
		t.Errorf("kept the deployment's redirect uri (%q) or home tenant (%q)",
			bound.redirectURI, bound.homeTenant)
	}
}

// The other side of the same rule: a workspace with NO stored application is a
// different situation, and must still fall back to the deployment's own
// configuration. Fixing the above by refusing everything would break the
// single-tenant deployment this product also supports.
func TestForWorkspace_NoStoredApplicationStillUsesTheDeployment(t *testing.T) {
	svc := deploymentConfigured(t)
	svc.appCfg = stubAppCfgRepo{cfg: nil}

	bound := svc.ForWorkspace(uuid.New())
	if bound.clientID != deploymentClientID {
		t.Fatalf("clientID = %q, want the deployment's %q", bound.clientID, deploymentClientID)
	}
	if err := bound.Ready(); err != nil {
		t.Fatalf("a deployment-configured workspace is not ready: %v", err)
	}
}

// A readable credential binds to the workspace's own application, which is the
// whole point. Guards against a fix that simply blanks everything.
func TestForWorkspace_AReadableCredentialBindsToTheWorkspacesOwnApplication(t *testing.T) {
	svc := deploymentConfigured(t)
	svc.vault = bundleVault{data: map[string]interface{}{
		"certificate_pem": string(testCertPEM(t)),
	}}

	bound := svc.ForWorkspace(uuid.New())
	if bound.clientID != workspaceClientID {
		t.Fatalf("clientID = %q, want the workspace's %q", bound.clientID, workspaceClientID)
	}
	if bound.clientID == deploymentClientID {
		t.Fatal("bound to the deployment's application")
	}
	if err := bound.Ready(); err != nil {
		t.Fatalf("a correctly configured workspace is not ready: %v", err)
	}
}
