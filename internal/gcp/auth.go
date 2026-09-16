// Package gcp is the GCP adapter for cloud discovery onboarding: it knows
// about Google's IAM, Cloud Asset and Resource Manager APIs and about GCP's
// workload identity federation mechanism, and nothing about AuthSec beyond
// the one narrow seam (CloudOnboardingTokenIssuer, in this file) it needs
// to mint the bearer it presents to GCP's own token exchange.
//
// Mirrors the internal/awsdiscovery split: policy (what to persist, when to
// call which function, the connector row) belongs in
// services/gcp_auth_service.go, not here.
package gcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials/externalaccount"
	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	cloudasset "google.golang.org/api/cloudasset/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

/* ============================== client factories ============================ */

// ReadOnlyScope is the ONLY OAuth scope any GCP client this package builds is
// ever granted. Every client-construction path below appends it explicitly
// rather than trusting the credential's own default scope, so a credential
// that could technically do more (a JSON key with broader IAM grants than the
// candidate role set, say) is still capped to read-only calls from AuthSec's
// side of the connection — least privilege enforced in the client, not just
// documented in the customer's role grants.
const ReadOnlyScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

// IAMScope is the OAuth scope the IAM client alone is granted. Live-testing
// this connector against real GCP proved ReadOnlyScope insufficient for the
// IAM Admin API: google.iam.admin.v1.IAM.GetServiceAccount rejects a
// cloud-platform.read-only token with 403 ACCESS_TOKEN_SCOPE_INSUFFICIENT,
// even though the identical token works for Resource Manager and Cloud Asset
// Inventory calls. Google's IAM Admin API does not publish a read-only scope
// of its own — its documented scope set is exactly {cloud-platform, iam} — so
// https://www.googleapis.com/auth/iam is the narrowest scope this specific
// client can be granted; it is not widened to full cloud-platform, and
// NewCloudAssetClient / NewResourceManagerClient below are untouched and stay
// on ReadOnlyScope, since both are live-confirmed to work with it.
const IAMScope = "https://www.googleapis.com/auth/iam"

// NewIAMClient builds the IAM client (projects.serviceAccounts.*,
// projects.serviceAccounts.keys.*, projects.roles.get — GCP-01's §5 "IAM
// service accounts" / "Service-account keys" / "Roles" surfaces).
func NewIAMClient(ctx context.Context, authOpt option.ClientOption) (*iam.Service, error) {
	svc, err := iam.NewService(ctx, authOpt, option.WithScopes(IAMScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: build iam client: %w", err)
	}
	return svc, nil
}

// NewCloudAssetClient builds the Cloud Asset Inventory client
// (searchAllIamPolicies, searchAllResources — the allow-policy and resource
// surfaces).
//
// quotaProject is REQUIRED, and is the reason this factory exists rather than
// callers constructing the client themselves. Every Cloud Asset call bills
// against the caller's quota project and the caller must hold
// serviceusage.services.use on it; a federated credential carries no default
// project of its own, so without this every call fails with a message that
// names neither the quota project nor the missing permission. It was
// previously left to callers as a per-call concern and, as a result, was never
// set by anyone.
//
// An empty quotaProject is refused outright. Building a client that is
// guaranteed to fail on first use, and failing then instead of here, would
// turn a configuration mistake into a mid-scan error.
func NewCloudAssetClient(ctx context.Context, authOpt option.ClientOption, quotaProject string) (*cloudasset.Service, error) {
	if quotaProject == "" {
		return nil, fmt.Errorf("gcp: build cloud asset client: no quota project; every Cloud Asset call bills against one")
	}
	svc, err := cloudasset.NewService(ctx, authOpt,
		option.WithScopes(ReadOnlyScope),
		option.WithQuotaProject(quotaProject),
	)
	if err != nil {
		return nil, fmt.Errorf("gcp: build cloud asset client: %w", err)
	}
	return svc, nil
}

// NewResourceManagerClient builds the Resource Manager client
// (organizations.get, folders.get/.list, projects.get/.list — GCP-01's §5
// "Scope hierarchy" surface, and this ticket's ResolveReaderIdentity /
// connection-validation calls).
func NewResourceManagerClient(ctx context.Context, authOpt option.ClientOption) (*cloudresourcemanager.Service, error) {
	svc, err := cloudresourcemanager.NewService(ctx, authOpt, option.WithScopes(ReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: build resource manager client: %w", err)
	}
	return svc, nil
}

/* ============================== credentials ================================= */

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
	// IssuerURL returns the exact issuer string every minted token's `iss`
	// claim carries — the same value the customer's setup script must have
	// configured its WIF provider to trust. ResolveWIFCredential reads this
	// to fail fast (ErrWIFIssuerNotHTTPS) when it's not HTTPS, before ever
	// minting a token GCP is guaranteed to reject.
	IssuerURL() string
}

// mintingSubjectTokenProvider mints a FRESH cloud-onboarding token on every
// call, rather than handing back one minted once at construction.
//
// WHY THIS IS NOT A STATIC TOKEN. A cloud-onboarding token lives 5 minutes
// (internal/tokens.CloudOnboardingTTL); the impersonated access token the
// external-account credential ultimately hands a client lives about an hour.
// When that access token expires, the library re-runs the whole exchange —
// and re-invokes this provider to get the subject assertion for it. A
// provider that returned a token captured at construction would hand back an
// assertion that expired ~55 minutes earlier, and Google's STS would reject
// it. A credential built that way works exactly once, for one refresh
// interval: fine for onboarding's single verify call, fatal for a scan that
// pages for hours. Minting per call is what makes refresh transparent to a
// long, resumable scan.
//
// This also satisfies the library's own contract ("the provider does not
// cache the returned subject token") the way it was meant to be satisfied —
// by minting, not by having nothing to cache.
//
// Minting is cheap and has no side effects: IssueCloudOnboardingToken is a
// pure signing operation over the active native key, writes no database row,
// and allocates a fresh jti per call, so nothing is reused across refreshes.
type mintingSubjectTokenProvider struct {
	issuer   CloudOnboardingTokenIssuer
	subject  string
	audience string
}

func (p mintingSubjectTokenProvider) SubjectToken(ctx context.Context, _ *externalaccount.RequestOptions) (string, error) {
	token, err := p.issuer.IssueCloudOnboardingToken(ctx, p.subject, p.audience)
	if err != nil {
		// Wrapped, not swallowed: the library surfaces this as the cause of a
		// failed refresh, and the issuer is AuthSec's own signing path — never
		// the customer's GCP configuration. See ResolveWIFCredential's own
		// handling of the same failure at construction time.
		return "", fmt.Errorf("mint cloud onboarding token: %w", err)
	}
	return token, nil
}

// ResolveWIFCredential derives the deterministic wif_subject for
// (workspaceID, scopeID) and builds the option.ClientOption for a GCP
// external-account credential that exchanges an AuthSec-signed cloud-
// onboarding token via STS and impersonates readerSAEmail.
//
// The subject token is minted ON DEMAND by mintingSubjectTokenProvider, once
// per exchange, rather than once here — see that type for why a credential
// built around a single captured token cannot outlive its first refresh.
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
	// Checked first, before the provider-resource/reader-SA-email guards
	// below: those are the CUSTOMER's mistakes to fix, this one is never
	// theirs to fix at all, regardless of what they pasted.
	if !IsHTTPSIssuer(issuer.IssuerURL()) {
		return nil, ErrWIFIssuerNotHTTPS
	}
	if providerResource == "" {
		return nil, fmt.Errorf("%w: no provider resource given", ErrWIFPoolMissing)
	}
	if readerSAEmail == "" {
		return nil, fmt.Errorf("%w: no reader service account email given", ErrWIFPoolMissing)
	}

	_, _, subject := DeriveWIFParams(workspaceID, scopeID)
	audience := audiencePrefix + providerResource

	provider := mintingSubjectTokenProvider{issuer: issuer, subject: subject, audience: audience}

	// One eager mint, whose result is deliberately discarded. The credential
	// itself mints on demand (see mintingSubjectTokenProvider), so this is not
	// how the subject token is obtained — it exists purely so a broken signing
	// path fails HERE, at onboarding, with a clear error, instead of surfacing
	// much later as an opaque refresh failure inside somebody's scan. Keeping
	// this check is what preserves the fail-fast behaviour callers already
	// depend on.
	if _, err := provider.SubjectToken(ctx, nil); err != nil {
		// The issuer is AuthSec's own signing path; a failure here is never the
		// customer's GCP configuration, so it is not wrapped as one of the four
		// sanitized GCP-facing codes. The caller maps this generically (authsec
		// fault), consistent with how services/cloud_aws_onboarding.go treats a
		// failure in its own ExternalId path versus a failure from AWS itself.
		return nil, err
	}

	creds, err := newExternalAccountCredentials(&externalaccount.Options{
		Audience:                       audience,
		SubjectTokenType:               wifSubjectTokenType,
		SubjectTokenProvider:           provider,
		ServiceAccountImpersonationURL: impersonationURL(readerSAEmail),
		// Scopes is set explicitly here, not left to the ClientOption ordering
		// in auth.go's client factories: option.WithScopes' own documentation says
		// scope settings from an already-resolved token source (which is what
		// WithAuthCredentials hands the client) take precedence, so pinning the
		// scope has to happen on the credential itself for this path to
		// actually be least-privilege, not just documented as such.
		//
		// BOTH read-only scopes this connector's clients ever need are
		// requested together, not just one: this credential is reused for the
		// IAM client (auth.go's NewIAMClient) AND the Resource
		// Manager / Cloud Asset clients (NewResourceManagerClient /
		// NewCloudAssetClient), and a WIF credential's scope is fixed at
		// construction — a client's own option.WithScopes call cannot widen it
		// afterward. Live-confirmed 2026-09-03: pinning ONLY ReadOnlyScope here
		// made the IAM Admin API reject iam.serviceAccounts.get with 403
		// ACCESS_TOKEN_SCOPE_INSUFFICIENT even though the underlying identity
		// held every IAM role it needed — IAMScope's own doc comment
		// already recorded that finding for the client-construction side, but
		// this credential-construction side still hardcoded the single
		// ReadOnlyScope value, silently overriding NewIAMClient's
		// option.WithScopes(IAMScope) for every WIF connection.
		// generateAccessToken (the impersonation call this credential drives)
		// accepts multiple scopes in one request and returns a token valid for
		// all of them, so requesting both here — rather than resolving a
		// separate WIF credential per client — costs nothing in privilege: the
		// reader SA's IAM roles (never write-capable) are what actually bound
		// what either scope can do, exactly as before. json_key is unaffected
		// by any of this — ResolveJSONKeyCredential never pins a scope, so
		// each client's own option.WithScopes already won for that path,
		// which is why only WIF ever hit this.
		Scopes: []string{ReadOnlyScope, IAMScope},
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

// mintingSubjectTokenProvider must satisfy externalaccount.SubjectTokenProvider.
var _ externalaccount.SubjectTokenProvider = mintingSubjectTokenProvider{}

/* ========================= wif derivation and issuer ======================== */

// wifDerivationSeparator matches the "." join services/cloud_aws_onboarding.go
// uses for its own HMAC inputs (workspace_id + "." + nonce). Consistency here
// is cosmetic — the two HMACs are computed with different keys-in-practice
// scoping (see hmacKey's doc comment) and are never compared to each other —
// but keeping the shape identical means a reader who already knows one
// convention reads the other for free.
const wifDerivationSeparator = "."

// poolIDPrefix and providerID are fixed per prompt.md's GCP-D9 design: AuthSec
// names the pool and provider deterministically, so the customer never invents
// or reports a name — the setup script and the backend derive the identical
// strings independently, and the console cross-checks the customer's pasted
// provider_resource against what it (re-)derives before ever calling GCP.
const (
	poolIDPrefix = "authsec-"
	// ProviderID is fixed, not derived — GCP-D9's design names exactly one
	// provider per pool, so there is nothing to disambiguate.
	ProviderID = "authsec-provider"
)

// wifSubjectPrefix marks a wif_subject as AuthSec-derived, matching the shape
// prompt.md's design shows in the WIF principal binding
// (principal://.../subject/<wif_subject>).
const wifSubjectPrefix = "authsec:"

// DeriveWIFParams computes the pool id, provider id and WIF subject for a
// (workspace, scope) pair — a PURE function of its inputs, no randomness, no
// I/O beyond reading the (already-resolved, effectively static) HMAC key.
// Called from both the onboarding-package renderer (GCP-04, which embeds
// these into setup-reader.sh) and the connector-create/verify path (GCP-03,
// GCP-04) so the two never compute them two different ways — that divergence
// is exactly what would make a customer-pasted provider_resource fail the
// cross-check for no reason a support engineer could explain.
//
// Per prompt.md's GCP-D9 design:
//
//	pool_id     = "authsec-" + hex(HMAC(key, workspace_id + "." + scope_id))[:16]
//	provider_id = "authsec-provider"                                  (fixed)
//	wif_subject = "authsec:" + hex(HMAC(key, workspace_id + "." + scope_id + ".subject"))[:32]
func DeriveWIFParams(workspaceID uuid.UUID, scopeID string) (poolID, providerID, subject string) {
	key := hmacKey()

	poolSum := hmacSum(key, workspaceID.String()+wifDerivationSeparator+scopeID)
	poolID = poolIDPrefix + hex.EncodeToString(poolSum)[:16]

	subjSum := hmacSum(key, workspaceID.String()+wifDerivationSeparator+scopeID+wifDerivationSeparator+"subject")
	subject = wifSubjectPrefix + hex.EncodeToString(subjSum)[:32]

	return poolID, ProviderID, subject
}

// hmacKey resolves the key used to derive WIF pool/provider/subject values.
//
// Deliberately a SEPARATE function from services.cloudDiscoveryHMACKey rather
// than an import of it: that function is unexported in package services, and
// services is the policy layer that depends on this adapter package (mirroring
// the awsdiscovery/cloud_aws_onboarding split) — this package importing
// services back would be a cycle, and exporting the AWS file's helper just to
// reach across that boundary was out of this ticket's scope (see GCP-03's
// validation list: no changes to services/cloud_aws_onboarding.go). The
// resolution order is copied verbatim from that function because it genuinely
// is provider-neutral, as services/cloud_aws_onboarding.go's own comment says:
//
//  1. AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY
//  2. config.AppConfig.JWTSecret (so a local deployment works out of the box)
//  3. a development constant
//
// If this drifts from services.cloudDiscoveryHMACKey in a future edit, GCP-04
// (which will also need to re-derive these values, server-side, from the same
// key) is the forcing function that will catch it — both sides compute the
// same three strings from the same inputs, or a customer's onboarding attempt
// fails its cross-check every time.
func hmacKey() []byte {
	if v := os.Getenv("AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY"); v != "" {
		return []byte(v)
	}
	if config.AppConfig != nil && config.AppConfig.JWTSecret != "" {
		return []byte(config.AppConfig.JWTSecret)
	}
	return []byte("authsec-cloud-discovery-dev-key")
}

func hmacSum(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

/* ------------------------- provider resource parsing ----------------------- */

// providerResourcePattern matches a bare WIF provider resource name (no
// "//iam.googleapis.com/" scheme prefix — see audiencePrefix
// doc comment for why the bare form is what's stored and pasted), capturing
// the pool id and provider id segments:
//
//	projects/<NUM>/locations/global/workloadIdentityPools/<pool_id>/providers/<provider_id>
var providerResourcePattern = regexp.MustCompile(
	`^projects/\d+/locations/global/workloadIdentityPools/([^/]+)/providers/([^/]+)$`)

// ParseProviderResource extracts the pool id and provider id segments from a
// bare WIF provider resource name. ok is false when providerResource does not
// match the expected shape at all (not this function's job to say why —
// the caller's cross-check against DeriveWIFParams's own output is what
// actually validates it; this only splits the string apart).
func ParseProviderResource(providerResource string) (poolID, providerID string, ok bool) {
	m := providerResourcePattern.FindStringSubmatch(providerResource)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

/* ------------------------------- wif issuer -------------------------------- */

// WIFIssuerEnv independently configures the OIDC issuer AuthSec presents to
// Google Cloud for Workload Identity Federation — separate from the general
// application base URL (BASE_URL / OAUTH_ISSUER_URL, config.Config.OAuthBaseURL).
// Google requires this specific value to be a real, HTTPS-reachable endpoint
// whose OIDC discovery document and JWKS resolve there — live-confirmed
// against a real GCP WIF provider-creation call: a non-HTTPS issuer is
// rejected outright ("Invalid OIDC issuer URI. The scheme must be https.").
// That is stricter than what the app's base URL needs to satisfy elsewhere
// (cookies, general OAuth redirects, etc.), so it gets its own setting
// rather than forcing the whole app onto HTTPS locally.
//
// Local development: leave BASE_URL at http://localhost:7001 for everything
// else, and set GCP_WIF_ISSUER_URL to a public HTTPS tunnel (e.g. a
// Cloudflare Tunnel or ngrok host) that forwards to that same local server —
// so the real WIF flow can be tested without ever making localhost itself a
// GCP OIDC issuer, and without touching production behavior.
//
// Production: leave unset. Falls back to whatever the caller's own
// OAuthBaseURL() already resolves to — already a real HTTPS URL there, so
// no new configuration is required in production, and production can never
// accidentally fall back to a localhost value this way.
const WIFIssuerEnv = "GCP_WIF_ISSUER_URL"

// ResolveWIFIssuerURL returns the OIDC issuer to use for GCP WIF: the
// explicit GCP_WIF_ISSUER_URL override if set, else defaultIssuerURL
// unchanged (trailing slash trimmed either way). Callers pass their own
// already-resolved app issuer (config.AppConfig.OAuthBaseURL()) as
// defaultIssuerURL — this function never reads that itself, so it has no
// opinion about, and cannot regress, anything unrelated to WIF.
func ResolveWIFIssuerURL(defaultIssuerURL string) string {
	if v := strings.TrimSpace(os.Getenv(WIFIssuerEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(strings.TrimSpace(defaultIssuerURL), "/")
}

// IsHTTPSIssuer reports whether issuerURL is HTTPS — the one thing Google
// Cloud unconditionally requires of a Workload Identity Federation OIDC
// issuer. A non-HTTPS issuer can never work for WIF in any environment, so
// callers check this BEFORE minting a token or handing the customer a setup
// script GCP is guaranteed to reject, rather than letting the failure
// surface only after a wasted round trip.
func IsHTTPSIssuer(issuerURL string) bool {
	return strings.HasPrefix(issuerURL, "https://")
}
