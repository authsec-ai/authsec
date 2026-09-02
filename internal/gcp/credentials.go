package gcp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials/externalaccount"
	"github.com/google/uuid"
	"google.golang.org/api/option"
)

// wifSubjectTokenType is the RFC 8693 token-type URN for the subject token
// AuthSec presents to GCP's STS: IssueCloudOnboardingToken mints an ordinary
// signed JWT (not an OIDC id_token — there is no separate id_token/access_token
// distinction for a self-issued assertion like this one), and this is the URN
// that matches. Live-confirmed against sts.googleapis.com in
// authsec/docs/gcp/feasibility-validation.md (question e): a "jwt"-typed
// subject token was accepted as well-formed by a real STS call, which
// proceeded to the issuer-connectivity stage rather than rejecting the type.
const wifSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"

// audiencePrefix is prepended to a bare WIF provider resource name (the form
// gcloud prints, and the form stored in cloud_connector.auth_ref /
// GCPConnectorAttrs.WIFProviderResource per prompt.md's GCP-D9 design — e.g.
// "projects/123456789012/locations/global/workloadIdentityPools/authsec-.../providers/authsec-provider",
// with no scheme) to produce the STS `audience` value external_account
// credentials expect
// ("//iam.googleapis.com/projects/.../workloadIdentityPools/.../providers/...").
// Live-confirmed as the correct, accepted format via the direct STS curl call
// recorded in authsec/docs/gcp/feasibility-validation.md (question e) — that
// call used this exact prefix and reached the issuer-connectivity stage
// rather than being rejected for a malformed audience.
//
// NOT the same string as the "principal://iam.googleapis.com/.../subject/<v>"
// form used in the IAM policy BINDING (setup-reader.sh's
// iam.workloadIdentityUser grant) — that is a member string on a different
// resource (the impersonated service account's IAM policy), not an STS
// request parameter. The two are easy to conflate; they are not
// interchangeable.
const audiencePrefix = "//iam.googleapis.com/"

/* ------------------------------- json_key path ----------------------------- */

// jsonKeyShape is the minimal shape ResolveJSONKeyCredential checks. Only the
// fields the plan (§9) needs verified before anything is written to Vault or
// sent to Google — this is structural validation, not a full JSON Schema, and
// deliberately stops short of accepting or echoing anything beyond a
// yes/no verdict plus a sanitized error.
type jsonKeyShape struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

// ResolveJSONKeyCredential validates an uploaded service-account key's shape
// and builds the option.ClientOption that authenticates a client with it.
//
// Validation happens BEFORE the option is built and before any byte of the
// key is persisted anywhere — the caller (services/gcp_auth_service.go's
// StoreKey) must reject a malformed key ahead of any Vault write, mirroring
// the AWS onboarding rule that a connection AuthSec cannot use must leave
// nothing behind.
//
// The key bytes themselves are never logged: on failure this returns only
// ErrKeyInvalid, wrapped with a static reason string, never the input.
func ResolveJSONKeyCredential(keyJSON []byte) (option.ClientOption, error) {
	var shape jsonKeyShape
	if err := json.Unmarshal(keyJSON, &shape); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON", ErrKeyInvalid)
	}
	if shape.Type != "service_account" {
		return nil, fmt.Errorf("%w: type must be \"service_account\"", ErrKeyInvalid)
	}
	if shape.ProjectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrKeyInvalid)
	}
	if shape.ClientEmail == "" {
		return nil, fmt.Errorf("%w: missing client_email", ErrKeyInvalid)
	}
	if shape.PrivateKey == "" {
		return nil, fmt.Errorf("%w: missing private_key", ErrKeyInvalid)
	}
	if err := validatePrivateKeyPEM(shape.PrivateKey); err != nil {
		return nil, fmt.Errorf("%w: private_key is not a well-formed PEM private key", ErrKeyInvalid)
	}

	// option.WithAuthCredentialsJSON(option.ServiceAccount, ...), NOT the
	// simpler-looking option.WithCredentialsJSON: the latter is documented as
	// deprecated in this pinned version (google.golang.org/api v0.296.0)
	// specifically because it performs NO validation of the credential type it
	// is handed — exactly the risk this function exists to close by checking
	// the shape above FIRST. Passing option.ServiceAccount here tells the
	// library to accept only that type, which is a second, library-enforced
	// check on top of this function's own.
	return option.WithAuthCredentialsJSON(option.ServiceAccount, keyJSON), nil
}

// validatePrivateKeyPEM confirms private_key decodes to a PEM block containing
// a parseable private key. Structural only — it does not check the key
// against any known project or attempt to use it.
func validatePrivateKeyPEM(raw string) error {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return fmt.Errorf("no PEM block found")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("PEM block is not a parseable private key")
}

/* --------------------------------- WIF path -------------------------------- */

// CloudOnboardingTokenIssuer is the seam this package needs from
// internal/tokens.NativeIssuer, narrowed to exactly the one method used here.
// *tokens.NativeIssuer satisfies this interface structurally — this package
// never imports internal/tokens, which keeps the GCP adapter's dependency
// graph the same shape as internal/awsdiscovery's (an adapter that knows
// nothing about the rest of AuthSec beyond the one function signature it
// calls), and makes this file testable with a fake that mints a token without
// a real signing keyset or database.
type CloudOnboardingTokenIssuer interface {
	IssueCloudOnboardingToken(ctx context.Context, sub, audience string) (string, error)
}

// staticSubjectTokenProvider hands the external-account credential the ONE
// token IssueCloudOnboardingToken already minted. It is deliberately not a
// provider that mints on demand: a cloud-onboarding token is 5-minute-lived
// and single-use by design (see internal/tokens.IssueCloudOnboardingToken's
// doc comment), so there is nothing to refresh within the lifetime of one
// BuildWIFCredential call, and the external-account library's own contract
// ("the provider does not cache the returned subject token") is satisfied
// trivially by a provider with nothing to cache.
type staticSubjectTokenProvider struct{ token string }

func (p staticSubjectTokenProvider) SubjectToken(_ context.Context, _ *externalaccount.RequestOptions) (string, error) {
	return p.token, nil
}

// ResolveWIFCredential derives the deterministic wif_subject for
// (workspaceID, scopeID), mints a cloud-onboarding token via issuer, and
// builds the option.ClientOption for a GCP external-account credential that
// exchanges that token via STS and impersonates readerSAEmail.
//
// providerResource is the BARE resource name the customer pasted back
// (no "//iam.googleapis.com/" prefix — see audiencePrefix's doc comment); the
// caller (services/gcp_auth_service.go) is responsible for the pool_id/
// provider_id cross-check against DeriveWIFParams BEFORE calling this, so
// that a stale paste or wrong-project mistake is caught without any network
// call — this function does not repeat that check, it only uses
// providerResource as given.
//
// Library choice, recorded per this ticket's own instruction to verify it
// against the version actually pinned (go.mod: cloud.google.com/go/auth
// v0.23.2, confirmed via `go doc` against that exact resolved version, not
// assumed from memory — see authsec/docs/gcp/feasibility-validation.md's SDK
// section for the original research this reproduces):
// cloud.google.com/go/auth/credentials/externalaccount.Options with a
// programmatic SubjectTokenProvider (SubjectToken(ctx, *RequestOptions)
// (string, error)) is the CURRENT, actively-developed shape for a
// non-file, non-URL subject-token supplier, paired with
// option.WithAuthCredentials(*auth.Credentials) — NOT the older
// golang.org/x/oauth2/google/externalaccount.Config/SubjectTokenSupplier +
// option.WithTokenSource shape, which is functionally equivalent but one
// layer further from google.golang.org/api's current client constructors.
func ResolveWIFCredential(
	ctx context.Context,
	issuer CloudOnboardingTokenIssuer,
	workspaceID uuid.UUID,
	scopeID string,
	providerResource string,
	readerSAEmail string,
) (option.ClientOption, error) {
	if providerResource == "" {
		return nil, fmt.Errorf("%w: no provider resource given", ErrWIFPoolMissing)
	}
	if readerSAEmail == "" {
		return nil, fmt.Errorf("%w: no reader service account email given", ErrWIFPoolMissing)
	}

	_, _, subject := DeriveWIFParams(workspaceID, scopeID)
	audience := audiencePrefix + providerResource

	token, err := issuer.IssueCloudOnboardingToken(ctx, subject, audience)
	if err != nil {
		// The issuer is AuthSec's own signing path; a failure here is never the
		// customer's GCP configuration, so it is not wrapped as one of the four
		// sanitized GCP-facing codes. The caller maps this generically (authsec
		// fault), consistent with how services/cloud_aws_onboarding.go treats a
		// failure in its own ExternalId path versus a failure from AWS itself.
		return nil, fmt.Errorf("mint cloud onboarding token: %w", err)
	}

	creds, err := newExternalAccountCredentials(&externalaccount.Options{
		Audience:                       audience,
		SubjectTokenType:               wifSubjectTokenType,
		SubjectTokenProvider:           staticSubjectTokenProvider{token: token},
		ServiceAccountImpersonationURL: impersonationURL(readerSAEmail),
		// Scopes is set explicitly here, not left to the ClientOption ordering
		// in internal/gcp/client.go: option.WithScopes' own documentation says
		// scope settings from an already-resolved token source (which is what
		// WithAuthCredentials hands the client) take precedence, so pinning the
		// read-only scope has to happen on the credential itself for this path
		// to actually be least-privilege, not just documented as such.
		Scopes: []string{ReadOnlyScope},
	})
	if err != nil {
		// Everything NewCredentials can fail on here is a shape problem with
		// what THIS function built (bad audience, bad impersonation URL) rather
		// than something GCP said no to — those come later, at actual STS
		// exchange time, inside the client call itself. Still routed through
		// ErrInvalidGrant rather than a bare wrap: from the caller's point of
		// view this credential could not be established, which is the same
		// class of failure.
		return nil, fmt.Errorf("%w: %v", ErrInvalidGrant, "could not construct external account credential")
	}

	return option.WithAuthCredentials(creds), nil
}

// newExternalAccountCredentials is the one call site that turns an
// *externalaccount.Options into a *auth.Credentials. Factored out of
// ResolveWIFCredential so a test can supply Options with TokenURL and
// ServiceAccountImpersonationURL pointed at a mock STS/IAM-Credentials
// server, exercising the SAME construction path production uses (Options ->
// externalaccount.NewCredentials -> a *auth.Credentials whose .Token(ctx)
// actually performs the exchange) — never a real GCP call in this test tier,
// per this ticket's own instruction.
func newExternalAccountCredentials(opts *externalaccount.Options) (*auth.Credentials, error) {
	return externalaccount.NewCredentials(opts)
}

// impersonationURL is the IAM Credentials API endpoint an external-account
// credential calls to exchange its federated identity for a token AS
// readerSAEmail. Documented directly on
// cloud.google.com/go/auth/credentials/externalaccount.Options.ServiceAccountImpersonationURL:
// without it, the resulting credential would authenticate as the federated
// external principal itself, never as the reader service account —
// impersonation would silently not happen.
func impersonationURL(readerSAEmail string) string {
	return fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		readerSAEmail,
	)
}

// staticSubjectTokenProvider must satisfy externalaccount.SubjectTokenProvider.
var _ externalaccount.SubjectTokenProvider = staticSubjectTokenProvider{}
