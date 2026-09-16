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

// GCP credential resolution, converging on the same typed-client construction
// and the same connectivity proof (ResolveReaderIdentity), exactly as
// internal/awsdiscovery/onboarding.go and services/cloud_aws_onboarding.go
// split adapter from policy for AWS.
//
// wif is the only path a NEW connector can take, and there is no secret
// anywhere in it: the credential is rebuilt fresh on every call from a token
// internal/tokens.NativeIssuer mints on demand, so there is nothing to store,
// nothing to read back, and nothing that can outlive the customer removing
// their own binding.
//
// json_key survives in read-and-delete form only, for connectors created
// before the keyed path was closed. See the block above LoadCredential.

// GCP connector auth methods. These mirror the JSON `auth.method` values, and
// json_key remains a legal value on an EXISTING row even though Onboard now
// refuses it on a new one.
const (
	GCPAuthMethodJSONKey = "json_key"
	GCPAuthMethodWIF     = "wif"
)

// GCPAuthService owns credential resolution for both GCP onboarding auth
// paths. GCP-04 builds the connector lifecycle (the row, the onboarding
// package, the HTTP surface) on top of this; this ticket stops at "here is an
// authenticated, read-only-scoped GCP client and proof of which identity it
// resolves to."
type GCPAuthService struct {
	vault vault.VaultClient
	// issuer is narrowed to gcp.CloudOnboardingTokenIssuer (satisfied by
	// *internal/tokens.NativeIssuer) rather than depending on internal/tokens
	// directly, for the same reason internal/gcp/auth.go does: this
	// service can be exercised in tests against a fake that mints a token
	// without a real signing keyset or database.
	issuer gcp.CloudOnboardingTokenIssuer
}

// NewGCPAuthService constructs the service. vault is needed only to read or
// purge a legacy keyed connector (LoadCredential/DeleteCredential fail
// explicitly, not silently, when it is nil); issuer is required for wif, which
// is the only path new connectors take. A deployment with no Vault can still
// onboard.
func NewGCPAuthService(vc vault.VaultClient, issuer gcp.CloudOnboardingTokenIssuer) *GCPAuthService {
	return &GCPAuthService{vault: vc, issuer: issuer}
}

/* -------------------------------- json_key --------------------------------- */

// What remains of the json_key path, and why.
//
// No new connector can be created with a service-account key — Onboard refuses
// the method outright (ErrKeyedOnboardingClosed). The write side is therefore
// gone: there is no StoreKey, and nothing in this package can put key material
// into Vault any more.
//
// The read and delete sides stay, for connectors that already exist. A keyed
// connector must still be able to verify, so an operator can see whether it
// works before migrating it, and must still revoke cleanly with its secret
// purged. Removing these would strand exactly the connectors we most want
// people to retire, and would leave their key material in Vault with no code
// left to delete it.

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
// sanitized sentinels. Only the sentinel is ever RETURNED — no provider text
// reaches a response or the connector row.
//
// It does log the provider's own code and message, to an operator log, and
// only there. That is a deliberate exception to the "nothing raw escapes"
// rule and the reason is in the comment on the log line itself.
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
	// Every branch below collapses the failure into a static sentinel, which
	// is right for the customer-facing response and useless for working out
	// WHY a token exchange was refused. This log line is the one place the
	// real answer survives.
	//
	// It was removed once, on the assumption its investigation was closed, and
	// had to come back the first time a federation setup failed in a way none
	// of the specific branches matched — leaving nothing anywhere to say what
	// Google had actually objected to. googleapi.Error's Code and Message are
	// GCP's own descriptive text ("invalid_target", "Error connecting to the
	// given credential's issuer"), never a token, key or assertion: the
	// credential is not in the error, it is in the request that produced it.
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		log.Printf("[gcp] credential exchange refused: authMethod=%s code=%d message=%q", authMethod, gerr.Code, gerr.Message)
	} else {
		log.Printf("[gcp] credential exchange refused: authMethod=%s error=%q", authMethod, err.Error())
	}

	// Checked BEFORE the generic 403 below. A VPC Service Controls perimeter
	// and an organization policy both refuse with 403, and reporting either as
	// "permission denied" sends the customer to grant a role that will change
	// nothing — the fix is an access-level or policy change made by whoever
	// owns the constraint.
	if constrained := gcp.ClassifyConstraint(err); constrained != nil {
		return constrained
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
