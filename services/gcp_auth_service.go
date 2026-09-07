package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/google/uuid"
	"google.golang.org/api/googleapi"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// GCP credential-resolution service: both onboarding auth paths (json_key,
// wif), converging on the same typed-client construction
// (internal/gcp/client.go) and the same connectivity proof
// (ResolveReaderIdentity), exactly as internal/awsdiscovery/onboarding.go and
// services/cloud_aws_onboarding.go split adapter from policy for AWS.
//
// json_key: the uploaded key is a real secret and lives in Vault, under a
// path shaped identically to AWS's ExternalId path
// (services/cloud_aws_onboarding.go's awsExternalIDPath), keyed by scope
// rather than by connector id for the same reason AWS's is keyed by account —
// re-onboarding the same scope overwrites its stored key instead of leaving
// an orphaned entry behind.
//
// wif: there is no secret anywhere in this path. The credential is rebuilt
// fresh, every time, from a token internal/tokens.NativeIssuer mints on
// demand — see gcp.ResolveWIFCredential's doc comment for why that token
// never needs caching or persistence.

// GCP connector auth methods. Mirror the JSON `auth.method` values
// prompt.md's GCP-D9 design and GCP-04's request shape use
// (auth:{method:"wif"|"json_key", ...}).
const (
	GCPAuthMethodJSONKey = "json_key"
	GCPAuthMethodWIF     = "wif"
)

// gcpKeyPath is where a workspace's uploaded GCP service-account key for one
// scope lives. Shape mirrors awsExternalIDPath exactly (see
// services/cloud_aws_onboarding.go), substituting "gcp" for "aws" — the same
// kv/data/secret/workspaces/<workspace_id>/cloud-discovery/<provider>/<scope>
// convention prompt.md's FACT list already confirms the landed
// internal/vault interface and path convention support without any change.
func gcpKeyPath(workspaceID uuid.UUID, scopeID string) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/cloud-discovery/gcp/%s",
		workspaceID.String(), scopeID)
}

// GCPAuthService owns credential resolution for both GCP onboarding auth
// paths. GCP-04 builds the connector lifecycle (the row, the onboarding
// package, the HTTP surface) on top of this; this ticket stops at "here is an
// authenticated, read-only-scoped GCP client and proof of which identity it
// resolves to."
type GCPAuthService struct {
	vault vault.VaultClient
	// issuer is narrowed to gcp.CloudOnboardingTokenIssuer (satisfied by
	// *internal/tokens.NativeIssuer) rather than depending on internal/tokens
	// directly, for the same reason internal/gcp/credentials.go does: this
	// service can be exercised in tests against a fake that mints a token
	// without a real signing keyset or database.
	issuer gcp.CloudOnboardingTokenIssuer
}

// NewGCPAuthService constructs the service. vault is required for the
// json_key path (StoreKey/LoadCredential/DeleteCredential fail explicitly,
// not silently, when it is nil — see AWSOnboardingService's own NewAWS...
// comment for the identical reasoning); issuer is required for the wif path.
// A deployment missing either can still onboard GCP connectors through
// whichever path it does have configured.
func NewGCPAuthService(vc vault.VaultClient, issuer gcp.CloudOnboardingTokenIssuer) *GCPAuthService {
	return &GCPAuthService{vault: vc, issuer: issuer}
}

/* -------------------------------- json_key --------------------------------- */

// StoreKey validates an uploaded service-account key's shape (never its
// content beyond structural checks — internal/gcp.ResolveJSONKeyCredential
// owns that) and writes it to Vault ONLY if valid. Returns the auth_ref to
// persist on the connector row.
//
// Ordering matters: validation happens before any Vault write, mirroring the
// plan's own rule that a credential AuthSec cannot use must leave nothing
// behind — a malformed key must never even reach the secrets store.
func (s *GCPAuthService) StoreKey(workspaceID uuid.UUID, scopeID string, keyJSON []byte) (string, error) {
	if _, err := gcp.ResolveJSONKeyCredential(keyJSON); err != nil {
		return "", err
	}
	if s.vault == nil {
		return "", errors.New("secrets store not configured; the service account key cannot be stored")
	}

	path := gcpKeyPath(workspaceID, scopeID)
	if err := s.vault.WriteSecret(path, map[string]interface{}{
		"key_json": string(keyJSON),
	}); err != nil {
		return "", fmt.Errorf("failed to store the service account key: %w", err)
	}
	return path, nil
}

// LoadCredential reads a json_key connector's stored key back from Vault and
// resolves it to the option.ClientOption that authenticates a client with it.
// The key bytes never leave this call as a return value — only the resolved
// ClientOption does.
func (s *GCPAuthService) LoadCredential(authRef string) (option.ClientOption, error) {
	if s.vault == nil {
		return nil, errors.New("secrets store not configured; the service account key cannot be read")
	}
	secret, err := s.vault.ReadSecret(authRef)
	if err != nil {
		return nil, fmt.Errorf("failed to read the service account key: %w", err)
	}
	keyJSON, _ := secret["key_json"].(string)
	if keyJSON == "" {
		return nil, fmt.Errorf("%w: no key stored for this connector", gcp.ErrKeyInvalid)
	}
	return gcp.ResolveJSONKeyCredential([]byte(keyJSON))
}

// DeleteCredential purges a json_key connector's stored key from Vault. A
// no-op (not an error) when there is nothing to delete, mirroring
// AWSOnboardingService.DeleteConnector's own "authRef == \"\"" guard.
func (s *GCPAuthService) DeleteCredential(authRef string) error {
	if authRef == "" || s.vault == nil {
		return nil
	}
	return s.vault.DeleteSecret(authRef)
}

/* ----------------------------------- wif ------------------------------------ */

// BuildWIFCredential builds the option.ClientOption for a WIF connector by
// deriving the deterministic wif_subject, minting a fresh cloud-onboarding
// token, and constructing a GCP external-account credential that impersonates
// readerSAEmail. NO Vault call anywhere in this path — there is nothing to
// store or read for WIF, by design (GCP-D9).
func (s *GCPAuthService) BuildWIFCredential(
	ctx context.Context, workspaceID uuid.UUID, scopeID, providerResource, readerSAEmail string,
) (option.ClientOption, error) {
	if s.issuer == nil {
		return nil, errors.New("no cloud onboarding token issuer configured; the wif path cannot mint a subject token")
	}
	return gcp.ResolveWIFCredential(ctx, s.issuer, workspaceID, scopeID, providerResource, readerSAEmail)
}

/* --------------------------- shared connectivity check ----------------------- */

// ResolveReaderIdentity proves a credential — from EITHER auth path — actually
// resolves to readerSAEmail: iam.serviceAccounts.get on the credential's own
// claimed identity, mirroring AWS onboarding's GetCallerIdentity probe (the
// call the plan's design flow names as "the GCP-03 connectivity primitive").
// Neither auth path is trusted to have landed on the right principal until
// this call proves it.
//
// authMethod (GCPAuthMethodJSONKey / GCPAuthMethodWIF) is used ONLY to
// classify a failure correctly — see classifyIAMError's doc comment.
func (s *GCPAuthService) ResolveReaderIdentity(
	ctx context.Context, client *iam.Service, readerSAEmail, authMethod string,
) (*iam.ServiceAccount, error) {
	sa, err := client.Projects.ServiceAccounts.Get("projects/-/serviceAccounts/" + readerSAEmail).Context(ctx).Do()
	if err != nil {
		return nil, classifyIAMError(err, authMethod)
	}
	return sa, nil
}

// classifyIAMError maps a raw error from the IAM call above to one of the
// four sanitized codes this ticket specifies, WITHOUT ever returning or
// logging the raw GCP/STS error text or any token material — only the
// static sentinel is ever propagated.
//
// authMethod disambiguates one genuinely ambiguous case: an "invalid_grant"
// response can come from either path's underlying OAuth2 token acquisition
// (json_key's service-account JWT-bearer grant, or wif's STS token exchange),
// but the two mean different things. On json_key it is a bad/revoked key —
// ErrInvalidGrant. On wif, GCP-04's own pre-flight cross-check of the pasted
// provider_resource against DeriveWIFParams already rules out an obviously
// wrong paste before this call is ever reached — so an invalid_grant surfacing
// HERE means the strings match what was derived, but GCP itself does not have
// the pool/provider/binding configured to match. That is exactly what
// ErrWIFPoolMissing represents per this ticket's error-handling section: a
// REAL failure mode now that WIF is fully implemented, not a stub-era
// placeholder.
func classifyIAMError(err error, authMethod string) error {
	// TEMPORARY DIAGNOSTIC LOGGING (GCP-OAuth 400 investigation): the code
	// below intentionally returns only a static sanitized sentinel from this
	// point on -- this is the one place the real GCP/STS error code+message
	// is still visible. googleapi.Error.Code/Message are GCP's own
	// descriptive text (e.g. "invalid_target", "Error connecting to the
	// given credential's issuer") -- never a token, key or credential -- so
	// this is safe to log. Remove once the 400 root cause is confirmed.
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		log.Printf("[gcp] classifyIAMError authMethod=%s code=%d message=%q", authMethod, gerr.Code, gerr.Message)
	} else {
		log.Printf("[gcp] classifyIAMError authMethod=%s non-googleapi error=%q", authMethod, err.Error())
	}
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case http.StatusForbidden, http.StatusNotFound:
			return gcp.ErrPermissionDenied
		}
	}
	// Checked before the broader invalid_grant branch below, on WIF only:
	// GCP's own error_description for an unreachable issuer is this exact
	// string, distinct from a genuine pool/provider/binding mismatch — see
	// gcp.ErrWIFIssuerUnreachable's doc comment for why conflating the two
	// was wrong (live-confirmed 2026-09-02).
	if authMethod == GCPAuthMethodWIF && strings.Contains(err.Error(), "Error connecting to the given credential's issuer") {
		return gcp.ErrWIFIssuerUnreachable
	}
	// A pool or provider that does not exist AT ALL (as opposed to one that
	// exists but is misconfigured/mismatched) makes GCP's STS reject the
	// token exchange with "invalid_target", not "invalid_grant" — live-
	// confirmed 2026-09-02 (see GCP-E2E-MANUAL-TEST-GUIDE.md §5g/§12 finding
	// #1). Both cases mean the same thing from the customer's side (their
	// WIF setup does not match what AuthSec derived), so both classify as
	// ErrWIFPoolMissing on WIF. json_key never performs a token-exchange
	// against a pool/provider, so this branch is WIF-only by construction.
	if authMethod == GCPAuthMethodWIF && strings.Contains(err.Error(), "invalid_target") {
		return gcp.ErrWIFPoolMissing
	}
	if strings.Contains(err.Error(), "invalid_grant") {
		if authMethod == GCPAuthMethodWIF {
			return gcp.ErrWIFPoolMissing
		}
		return gcp.ErrInvalidGrant
	}
	return gcp.ErrInvalidGrant
}

/* ---------------------------------- revoke ----------------------------------- */

// RevokeCredential purges stored credential material for a connector being
// revoked. For json_key this deletes the Vault secret. For wif this is a
// DOCUMENTED no-op: a WIF connector's auth_ref is "wif:"+provider_resource — a
// non-secret GCP resource name, never a Vault path — so there is nothing in
// Vault to purge. Written explicitly, as its own branch, rather than as a
// silent early-return buried in a shared helper, so a future reader tracing
// "why did revoking this connector make zero Vault calls" finds the answer
// here instead of having to re-derive it from the auth_ref convention.
func (s *GCPAuthService) RevokeCredential(authMethod, authRef string) error {
	if authMethod == GCPAuthMethodWIF {
		return nil
	}
	return s.DeleteCredential(authRef)
}
