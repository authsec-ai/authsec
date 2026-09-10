package services

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
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

// generatedCertLifetime is how long a certificate AuthSec makes stays valid.
//
// A year, matching what an operator would choose for a client secret, and short
// enough that rotating is a habit rather than an emergency. The check reports
// the expiry the same way it reports a secret's.
const generatedCertLifetime = 365 * 24 * time.Hour

// azureAppSecretPath is where a workspace's client secret lives.
func azureAppSecretPath(workspaceID uuid.UUID) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/azure/app", workspaceID.String())
}

// AzureAppConfigInput is what an operator submits after creating the app.
type AzureAppConfigInput struct {
	ClientID   string `json:"clientId"`
	HomeTenant string `json:"homeTenant"`

	// Exactly one of these. A client secret is a password that travels to
	// Microsoft on every token request; a certificate never travels at all --
	// the application signs a short-lived assertion with a key that can live in
	// an HSM. Both are accepted because refusing either refuses real customers,
	// but the check recommends the certificate.
	ClientSecret string `json:"clientSecret"`

	// GenerateCertificate asks AuthSec to make the key pair. This is the only
	// way to get a certificate credential, on purpose.
	//
	// There is deliberately no field for submitting one. A certificate is worth
	// having because the private key never travels -- and an operator pasting
	// one sends that key through a clipboard, a browser and a request body,
	// which is the path a client secret takes and the thing this exists to
	// avoid. An option that undoes the reason for the feature is not a choice
	// worth offering.
	//
	// If a customer's policy ever requires the key be born in their own HSM,
	// that is a real case and can be added then, with its own handling. It has
	// not been asked for, and building it now would mean maintaining a path
	// nobody uses that also happens to be the weaker one.
	GenerateCertificate bool `json:"generateCertificate"`

	// KeepCredential saves everything else and leaves the stored credential
	// exactly as it is.
	//
	// Without it there was no way to submit this form twice. A save demanded a
	// credential, and the only certificate this accepts is one it generates --
	// so correcting a redirect URI, or re-running the check after granting
	// consent, minted a new key pair and overwrote the old one. The certificate
	// already uploaded to the registration stopped matching, and the failure
	// was AADSTS700027 quoting a thumbprint nobody had seen. Each attempt to
	// fix it by saving again produced a third.
	//
	// So a credential is required only when there is not one already.
	KeepCredential bool `json:"keepCredential"`

	RedirectURI string `json:"redirectUri"`
}

// AzureAppConfigResult is the answer to "did that work, and is the app correct".
type AzureAppConfigResult struct {
	Stored *models.AzureAppConfig `json:"stored"`

	// CertificatePEM is set only when AuthSec generated the key pair, and it is
	// the CERTIFICATE -- the public half. The operator downloads this and
	// uploads it to the app registration.
	//
	// The private key is deliberately absent and has no field here at all, so
	// there is no way for it to reach a response by someone adding one line.
	// It went to the secrets store and stays there.
	CertificatePEM        string     `json:"certificate_pem,omitempty"`
	CertificateThumbprint string     `json:"certificate_thumbprint,omitempty"`
	CertificateExpires    *time.Time `json:"certificate_expires,omitempty"`

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

	// CheckProblem names that failure when it can be named. Set together with
	// CheckError and never instead of it: the raw message stays, because a
	// diagnosis that guesses wrong must not be the only thing on screen.
	CheckProblem *azureonboard.Diagnosis `json:"check_problem,omitempty"`
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
	var certPEM string
	keeping := false
	switch {
	case in.GenerateCertificate && secret != "":
		// Storing both would leave which one is in use decided by whichever
		// branch happens to read first -- and rotating one would silently do
		// nothing.
		return nil, errors.New(
			"send generateCertificate OR clientSecret, not both: an application " +
				"authenticates one way")
	case in.KeepCredential && (in.GenerateCertificate || secret != ""):
		return nil, errors.New(
			"keepCredential asks for the stored credential to be left alone, so do not " +
				"send a new one alongside it")
	case in.KeepCredential:
		// Only if there is something to keep. Otherwise this would store a row
		// pointing at an empty path, which reads as configured and fails at the
		// first token request.
		kept, kErr := s.storedCredentialBlob(workspaceID)
		if kErr != nil {
			return nil, kErr
		}
		keeping = true
		if pemStr, _ := kept["certificate_pem"].(string); pemStr != "" {
			certPEM = pemStr
		} else {
			secret, _ = kept["client_secret"].(string)
		}
	case in.GenerateCertificate:
		// Filled in below, after validation -- a key pair generated for a
		// request that is about to be rejected is a key pair nobody wanted.
	case secret == "":
		missing = append(missing, "clientSecret or generateCertificate")
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

	// Everything above validated, so it is now worth making a key pair.
	var generated *azureonboard.GeneratedCertificate
	if in.GenerateCertificate {
		g, gErr := azureonboard.GenerateCertificate("authsec-"+clientID, generatedCertLifetime)
		if gErr != nil {
			return nil, fmt.Errorf("generate certificate: %w", gErr)
		}
		generated = g
		certPEM = string(g.Bundle)
	}

	if s.vault == nil {
		return nil, errors.New("vault is not configured; the credential cannot be stored")
	}
	path := azureAppSecretPath(workspaceID)
	if !keeping {
		blob := map[string]interface{}{}
		if secret != "" {
			blob["client_secret"] = secret
		} else {
			blob["certificate_pem"] = certPEM
		}
		// Written, not merged: switching from a secret to a certificate must
		// leave the old one gone rather than sitting beside the new one.
		if err := s.vault.WriteSecret(path, blob); err != nil {
			return nil, fmt.Errorf("store credential: %w", err)
		}
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
	if generated != nil {
		// The certificate only. The private key stays in the secrets store and
		// is not in this struct, so it cannot reach a response by accident.
		res.CertificatePEM = string(generated.CertificatePEM)
		res.CertificateThumbprint = generated.Thumbprint
		res.CertificateExpires = &generated.NotAfter
	}

	// A certificate that was just generated cannot be on the registration yet,
	// so asking Microsoft about it can only fail -- with AADSTS700027, the very
	// error the upload is about to fix. Reporting that next to "your key pair
	// is ready" read as though generating had broken something. The check is a
	// separate step, run after the upload.
	if generated != nil {
		return res, nil
	}

	// Whichever form was submitted. Parsed again rather than carried from the
	// validation above so the check exercises exactly what was stored.
	cred := azureonboard.SecretCredential(secret)
	if certPEM != "" {
		parsed, cErr := azureonboard.CertificateCredential([]byte(certPEM))
		if cErr != nil {
			res.CheckError = cErr.Error()
			res.CheckProblem = azureonboard.Diagnose(cErr)
			return res, nil
		}
		cred = parsed
	}
	bound := s.bindCredential(clientID, cred, redirectURI, homeTenant)
	check, cErr := bound.CheckAppRegistration(ctx)
	if cErr != nil {
		res.CheckError = cErr.Error()
		res.CheckProblem = azureonboard.Diagnose(cErr)
		return res, nil
	}
	res.Check = check
	_ = s.appCfgRepo().MarkChecked(workspaceID)
	return res, nil
}

// storedCredentialBlob reads back the credential this workspace already has, and
// says plainly when there is not one -- "nothing to keep" is a different problem
// from "the store is unreachable", and they are fixed differently.
func (s *AzureOnboardService) storedCredentialBlob(
	workspaceID uuid.UUID,
) (map[string]interface{}, error) {
	if s.vault == nil {
		return nil, errors.New("vault is not configured; there is no stored credential to keep")
	}
	cfg, err := s.appCfgRepo().Get(workspaceID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New(
			"no application is stored for this workspace yet, so there is no credential to " +
				"keep: send generateCertificate or clientSecret")
	}
	data, err := s.vault.ReadSecret(cfg.AuthRef)
	if err != nil {
		return nil, fmt.Errorf("read stored credential from %s: %w", cfg.AuthRef, err)
	}
	pemStr, _ := data["certificate_pem"].(string)
	secret, _ := data["client_secret"].(string)
	if strings.TrimSpace(pemStr) == "" && strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf(
			"the secrets store holds no credential at %s, so there is nothing to keep: "+
				"send generateCertificate or clientSecret", cfg.AuthRef)
	}
	return data, nil
}

// GetAppConfig reports the stored application without its secret.
func (s *AzureOnboardService) GetAppConfig(workspaceID uuid.UUID) (*models.AzureAppConfig, error) {
	return s.appCfgRepo().Get(workspaceID)
}

// CurrentCertificatePEM returns the PUBLIC certificate of the stored credential,
// or "" when the workspace authenticates with a secret.
//
// It exists because offering the certificate only once was a trap. An operator
// who closed the page, or generated a second time before uploading the first,
// had no way back to it -- and the only route forward was to generate again,
// which replaces the key and orphans whatever they had already uploaded. That
// happened: a certificate was uploaded to the registration while the secrets
// store already held a different one, and every token request failed with
// AADSTS700027 pointing at a thumbprint the operator had never seen.
//
// Handing it back costs nothing. It is the public half: it verifies a signature
// and cannot make one. The private key stays where it is and has no accessor.
//
// The thumbprint comes back with it, as uppercase hex: that is the form the
// portal lists and the form AADSTS700027 quotes, so an operator staring at
// that error can compare the two strings without decoding anything.
func (s *AzureOnboardService) CurrentCertificatePEM(workspaceID uuid.UUID) (certPEM, thumbprint string) {
	if s.vault == nil {
		return "", ""
	}
	cfg, err := s.appCfgRepo().Get(workspaceID)
	if err != nil || cfg == nil {
		return "", ""
	}
	data, err := s.vault.ReadSecret(cfg.AuthRef)
	if err != nil || data == nil {
		return "", ""
	}
	bundle, _ := data["certificate_pem"].(string)
	if strings.TrimSpace(bundle) == "" {
		return "", ""
	}
	// Only the CERTIFICATE blocks. Returning the bundle would return the key.
	var out strings.Builder
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			// The LAST block, which is the one CertificateCredential signs
			// with. A reported thumbprint that named a different certificate
			// than the assertion carries would be worse than none.
			sum := sha1.Sum(block.Bytes)
			thumbprint = strings.ToUpper(hex.EncodeToString(sum[:]))
			_ = pem.Encode(&out, block)
		}
	}
	return out.String(), thumbprint
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
		// No stored application. Falling back to the environment is the whole
		// point, and there is nothing to explain.
		return s
	}

	// From here the workspace DID submit an application, so every failure below
	// is worth naming. Returning the unbound service silently sends the operator
	// an error about environment variables they were never asked to set, while
	// the values they did submit sit unused in the row.
	//
	// The copy is stripped of the deployment's own application. Keeping it was
	// worse than useless: with AZURE_CLIENT_ID / AZURE_CLIENT_SECRET /
	// AZURE_REDIRECT_URI set -- the configuration .env.example ships -- the copy
	// stayed fully usable, Ready() saw nothing missing and returned nil, and the
	// workspace went on acting as the DEPLOYMENT'S application while the console
	// showed its own client id. The visible outcome was a customer's
	// administrator granting admin consent to the wrong application in their own
	// directory, recorded as though it were right.
	//
	// A workspace that submitted an application either uses that one or none.
	withProblem := func(format string, args ...any) *AzureOnboardService {
		c := *s
		c.bindProblem = fmt.Sprintf(format, args...)
		c.clientID, c.redirectURI, c.homeTenant = "", "", ""
		c.azure = nil
		c.credKind, c.credThumbprint = "", ""
		return &c
	}

	if s.vault == nil {
		return withProblem("the secrets store is not configured on this deployment, " +
			"so the stored client secret cannot be read (VAULT_ADDR/VAULT_TOKEN)")
	}
	data, err := s.vault.ReadSecret(cfg.AuthRef)
	if err != nil {
		return withProblem("its client secret could not be read from the secrets store at %q: "+
			"%v. Re-submit the application with POST /api/azure/config", cfg.AuthRef, err)
	}
	secret, _ := data["client_secret"].(string)
	certPEM, _ := data["certificate_pem"].(string)

	switch {
	case strings.TrimSpace(certPEM) != "":
		cred, cErr := azureonboard.CertificateCredential([]byte(certPEM))
		if cErr != nil {
			// It parsed when it was submitted, so this is corruption or a
			// hand-edited secret rather than operator error. Say which.
			return withProblem("the certificate stored at %q can no longer be parsed: %v",
				cfg.AuthRef, cErr)
		}
		return s.bindCredential(cfg.ClientID, cred, cfg.RedirectURI, cfg.HomeTenant)
	case strings.TrimSpace(secret) != "":
		return s.bindCredential(cfg.ClientID, azureonboard.SecretCredential(secret),
			cfg.RedirectURI, cfg.HomeTenant)
	}
	return withProblem("the secrets store holds neither a client secret nor a certificate at "+
		"%q. Re-submit the application with POST /api/azure/config", cfg.AuthRef)
}

// bindApp returns a copy of the service using one specific application.
func (s *AzureOnboardService) bindCredential(
	clientID string, cred azureonboard.Credential, redirectURI, homeTenant string,
) *AzureOnboardService {
	c := *s
	c.clientID = clientID
	c.redirectURI = redirectURI
	c.homeTenant = homeTenant
	c.credKind = cred.Kind
	c.credThumbprint = cred.Thumbprint()
	c.azure = azureonboard.NewHTTPClientWithCredential(clientID, cred)
	return &c
}

func (s *AzureOnboardService) appCfgRepo() repositories.AzureAppConfigRepository {
	if s.appCfg == nil {
		s.appCfg = repositories.NewAzureAppConfigRepository(s.db)
	}
	return s.appCfg
}
