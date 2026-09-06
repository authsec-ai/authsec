package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	mrand "math/rand"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	serviceusage "google.golang.org/api/serviceusage/v1"
	"gorm.io/gorm"
)

// GCPOAuthProvisionService is the Google Authentication onboarding option:
// a human's one-time Google OAuth consent, used ONLY to auto-provision the
// same Workload Identity Federation resources the manual Cloud-Shell script
// creates, then handed off to the EXISTING, UNMODIFIED GCPOnboardingService
// for the actual connector row -- see Provision's doc comment.
//
// Deliberately independent of services/connector_oauth_service.go (the
// third-party connector broker's OAuth engine, which persists a long-lived
// Connection to Vault by design -- the wrong model for a credential that
// must be discarded after one use) and of models.ConnectorOAuthState (a
// Postgres table, which would need a migration). State and the resulting
// short-lived session live in Redis instead -- already a load-bearing,
// always-present runtime dependency in this codebase (see
// services/anti_replay_service.go), not a new one introduced for this
// feature.
//
// Two Redis-backed stages, deliberately not one:
//   - Stage A (gcpOAuthStateKey): the CSRF state + PKCE verifier, written at
//     Start, GETDEL'd exactly once at HandleCallback. Ties the OAuth
//     round-trip back to the workspace that started it.
//   - Stage B (gcpOAuthSessionKey): the short-lived access token, written at
//     HandleCallback, read (not deleted) by ListProjects/Preflight, and
//     GETDEL'd exactly once by Provision -- one-shot use of the token.
//
// The OAuth access token NEVER leaves this file's Redis calls and the
// in-process option.ClientOption Provision builds from it: it is never
// written to Postgres, Vault, a CloudConnector, a GCPConnectorAttrs field,
// an audit payload, a log line, or an API response.
type GCPOAuthProvisionService struct {
	db           *gorm.DB
	redis        *redis.Client
	onboardSvc   *GCPOnboardingService
	clientID     string
	clientSecret string
	redirectURI  string
	// issuerURL is resolved once by the caller (gcp.ResolveWIFIssuerURL),
	// exactly like CloudGCPController.service() and GetOnboardingPackage
	// already do, and passed in here rather than re-resolved -- so this
	// service never has to import config itself and can never compute a
	// different issuer value than the rest of the GCP onboarding surface.
	issuerURL string
}

// NewGCPOAuthProvisionService constructs the service. redisClient may be
// nil (Available reports false, every method fails with
// ErrGoogleOAuthUnavailable, and the existing WIF/JSON-key paths are
// entirely unaffected -- they never call anything in this file).
func NewGCPOAuthProvisionService(
	db *gorm.DB,
	redisClient *redis.Client,
	onboardSvc *GCPOnboardingService,
	clientID, clientSecret, redirectURI, issuerURL string,
) *GCPOAuthProvisionService {
	return &GCPOAuthProvisionService{
		db:           db,
		redis:        redisClient,
		onboardSvc:   onboardSvc,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		issuerURL:    issuerURL,
	}
}

/* --------------------------------- errors ---------------------------------- */

var (
	// ErrGoogleOAuthUnavailable means Redis, or the GCP_OAUTH_CLIENT_ID/
	// SECRET/REDIRECT_URI configuration, isn't available -- the
	// Google-Authentication option should be reported unavailable/hidden by
	// the frontend rather than half-starting a flow that would fail later.
	ErrGoogleOAuthUnavailable = errors.New("gcp: google authentication is not available in this deployment right now")

	// ErrGoogleOAuthStateInvalid means the state parameter Google redirected
	// back with does not correspond to a live, unexpired, not-already-used
	// Start call.
	ErrGoogleOAuthStateInvalid = errors.New("gcp: this google sign-in request could not be verified (missing, expired, or already used); please try again")

	// ErrGoogleOAuthSessionInvalid means the session_id does not correspond
	// to a live, unexpired, not-already-used HandleCallback result.
	ErrGoogleOAuthSessionInvalid = errors.New("gcp: this google authentication session has expired or was already used; please sign in again")

	// ErrGoogleOAuthWorkspaceMismatch means the authenticated caller's
	// workspace does not match the workspace that started this OAuth flow --
	// caught BEFORE any GCP call, on every method that accepts a session_id.
	ErrGoogleOAuthWorkspaceMismatch = errors.New("gcp: this google authentication session does not belong to your workspace")

	// ErrGoogleOAuthPermissionsMissing means testIamPermissions found the
	// signed-in Google account lacks one or more permissions this bootstrap
	// needs. Zero GCP writes have occurred when this is returned -- see
	// Provision's doc comment.
	ErrGoogleOAuthPermissionsMissing = errors.New("gcp: the signed-in google account does not have the permissions required to configure workload identity federation automatically")
)

/* ------------------------------ redis payloads ------------------------------ */

const (
	googleOAuthStateTTL = 10 * time.Minute
	// Long enough that a customer whose first Connect hit the IAM propagation
	// delay can simply click Connect again, instead of repeating the whole
	// Google consent round trip. One provisioning attempt is now worst-case
	// ~95s (see onboardWithVerificationRetry), so 5 minutes left barely enough
	// for one retry and none for a second.
	//
	// Still far shorter than the ~1h lifetime Google gives the access token
	// itself, and Redis expires the key with no further action.
	googleOAuthSessionTTL = 15 * time.Minute

	// Ceiling for the verification poll interval (see retryBackoff).
	maxRetryDelay = 10 * time.Second
)

func gcpOAuthStateKey(state string) string       { return "gcp:oauth:state:" + state }
func gcpOAuthSessionKey(sessionID string) string { return "gcp:oauth:session:" + sessionID }

// googleOAuthState is Stage A's Redis payload.
//
// Deliberately carries NO scope information: per the approved UX ("Sign in
// with Google" happens before "select project"), the human has not chosen a
// project yet when Start is called -- scope_kind/scope_id/reader_project_id
// are only known once ListProjects (after HandleCallback) lets them pick
// one, so Preflight/Provision take those as explicit parameters instead.
type googleOAuthState struct {
	WorkspaceID  string `json:"workspace_id"`
	CodeVerifier string `json:"code_verifier"`
	CreatedBy    string `json:"created_by"`
}

// googleOAuthSession is Stage B's Redis payload. AccessToken is the only
// sensitive field here, and this struct -- and the Redis value it is
// marshaled into -- is the ONLY place the access token exists outside a
// single in-flight request's memory. Also carries no scope information, for
// the same reason as googleOAuthState above.
type googleOAuthSession struct {
	WorkspaceID string `json:"workspace_id"`
	AccessToken string `json:"access_token"`
	GoogleEmail string `json:"google_email"`
	CreatedBy   string `json:"created_by"`
}

/* --------------------------------- pki utils --------------------------------- */

// gcpOAuthRandomToken and gcpOAuthPKCES256 are a small, independent PKCE/state
// implementation -- deliberately not imported from
// services/connector_oauth_service.go (a different subsystem this feature
// must stay decoupled from), even though the algorithm is the same
// (crypto/rand bytes, base64 raw-url-encoded; SHA-256 code challenge).
func gcpOAuthRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func gcpOAuthPKCES256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

/* --------------------------------- availability ------------------------------ */

// Available reports whether the Google Authentication option can be offered
// right now -- Redis reachable and the OAuth client configured. Called by
// the controller so the frontend can hide/disable the option cleanly instead
// of half-starting a flow that would fail at the callback.
func (s *GCPOAuthProvisionService) Available(ctx context.Context) bool {
	if s.redis == nil || s.clientID == "" || s.clientSecret == "" || s.redirectURI == "" {
		return false
	}
	return s.redis.Ping(ctx).Err() == nil
}

/* ----------------------------------- start ------------------------------------ */

// Start begins the OAuth flow: generates state + PKCE verifier, stores
// Stage A, and returns the URL to send the browser to. Takes no scope
// input -- the human has not chosen a project yet at this point (see
// googleOAuthState's doc comment).
func (s *GCPOAuthProvisionService) Start(ctx context.Context, workspaceID uuid.UUID, actor string) (authorizeURL, state string, err error) {
	if !s.Available(ctx) {
		return "", "", ErrGoogleOAuthUnavailable
	}

	state, err = gcpOAuthRandomToken(32)
	if err != nil {
		return "", "", fmt.Errorf("%w: generating state: %v", ErrGoogleOAuthUnavailable, err)
	}
	verifier, err := gcpOAuthRandomToken(48)
	if err != nil {
		return "", "", fmt.Errorf("%w: generating pkce verifier: %v", ErrGoogleOAuthUnavailable, err)
	}
	challenge := gcpOAuthPKCES256(verifier)

	payload, err := json.Marshal(googleOAuthState{
		WorkspaceID:  workspaceID.String(),
		CodeVerifier: verifier,
		CreatedBy:    actor,
	})
	if err != nil {
		return "", "", err
	}
	if err := s.redis.Set(ctx, gcpOAuthStateKey(state), payload, googleOAuthStateTTL).Err(); err != nil {
		return "", "", fmt.Errorf("%w: storing oauth state: %v", ErrGoogleOAuthUnavailable, err)
	}

	return gcp.GoogleAuthorizeURL(s.clientID, s.redirectURI, state, challenge), state, nil
}

/* --------------------------------- callback ------------------------------------ */

// HandleCallback validates and consumes the one-shot Stage A state, exchanges
// the code for a Google access token, and writes Stage B. Returns ONLY an
// opaque session id -- never the access token itself -- for the frontend to
// carry through the remaining steps. Does no provisioning and returns no
// workspace data: exactly the minimum an unauthenticated,
// provider-redirected endpoint should do.
func (s *GCPOAuthProvisionService) HandleCallback(ctx context.Context, code, state string) (sessionID string, err error) {
	if s.redis == nil {
		return "", ErrGoogleOAuthUnavailable
	}

	raw, err := s.redis.GetDel(ctx, gcpOAuthStateKey(state)).Result()
	if err != nil {
		return "", ErrGoogleOAuthStateInvalid
	}
	var st googleOAuthState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return "", ErrGoogleOAuthStateInvalid
	}

	accessToken, idToken, err := gcp.ExchangeGoogleCode(ctx, s.clientID, s.clientSecret, s.redirectURI, code, st.CodeVerifier)
	if err != nil {
		return "", err
	}

	sessionID, err = gcpOAuthRandomToken(32)
	if err != nil {
		return "", fmt.Errorf("%w: generating session id: %v", ErrGoogleOAuthUnavailable, err)
	}

	payload, err := json.Marshal(googleOAuthSession{
		WorkspaceID: st.WorkspaceID,
		AccessToken: accessToken,
		GoogleEmail: gcp.DecodeGoogleIDTokenEmail(idToken),
		CreatedBy:   st.CreatedBy,
	})
	if err != nil {
		return "", err
	}
	if err := s.redis.Set(ctx, gcpOAuthSessionKey(sessionID), payload, googleOAuthSessionTTL).Err(); err != nil {
		return "", fmt.Errorf("%w: storing oauth session: %v", ErrGoogleOAuthUnavailable, err)
	}
	return sessionID, nil
}

/* ------------------------------ session access ------------------------------- */

// loadSession reads Stage B WITHOUT consuming it (a plain GET, not GETDEL) --
// used by every method that only needs to READ with the token
// (ListProjects, Preflight), and by Provision's own initial check, so a
// workspace mismatch or a failed preflight NEVER burns the one-shot session
// a legitimate retry could still use.
func (s *GCPOAuthProvisionService) loadSession(ctx context.Context, sessionID string, callerWorkspaceID uuid.UUID) (*googleOAuthSession, error) {
	if s.redis == nil {
		return nil, ErrGoogleOAuthUnavailable
	}
	raw, err := s.redis.Get(ctx, gcpOAuthSessionKey(sessionID)).Result()
	if err != nil {
		return nil, ErrGoogleOAuthSessionInvalid
	}
	var sess googleOAuthSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return nil, ErrGoogleOAuthSessionInvalid
	}
	if sess.WorkspaceID != callerWorkspaceID.String() {
		// Deliberately does NOT delete the session -- a cross-tenant probe
		// must not be able to invalidate a legitimate workspace's live
		// session by guessing/replaying its id.
		return nil, ErrGoogleOAuthWorkspaceMismatch
	}
	return &sess, nil
}

func tokenClientOption(accessToken string) option.ClientOption {
	return option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken}))
}

/* --------------------------------- projects ------------------------------------ */

// GoogleProjectSummary is the minimal project shape the picker UI needs.
type GoogleProjectSummary struct {
	ProjectID   string `json:"project_id"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
}

// ListProjects returns the GCP projects the session's Google identity can
// see, for the frontend's project-picker step.
func (s *GCPOAuthProvisionService) ListProjects(ctx context.Context, sessionID string, callerWorkspaceID uuid.UUID) ([]GoogleProjectSummary, error) {
	sess, err := s.loadSession(ctx, sessionID, callerWorkspaceID)
	if err != nil {
		return nil, err
	}
	rmClient, err := newResourceManagerClientFunc(ctx, tokenClientOption(sess.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("%w: building resource manager client: %v", gcp.ErrGoogleOAuthProvisioningFailed, err)
	}
	projects, err := gcp.ListAccessibleProjects(ctx, rmClient)
	if err != nil {
		return nil, err
	}
	out := make([]GoogleProjectSummary, 0, len(projects))
	for _, p := range projects {
		out = append(out, GoogleProjectSummary{ProjectID: p.ProjectId, DisplayName: p.DisplayName, State: p.State})
	}
	return out, nil
}

/* --------------------------------- preflight ------------------------------------ */

// GoogleScope is the (scope_kind, scope_id, reader_project_id) triple the
// human picks AFTER signing in with Google (via ListProjects) -- passed
// explicitly to Preflight/Provision rather than carried in the OAuth
// session, since it isn't known yet when Start/HandleCallback run. Only
// "project" scope is supported for this option in this phase: Google's
// project-search API returns projects, not organizations or folders, so
// picking an org/folder scope via Google Authentication isn't offered by
// the frontend today -- WIF (Option 1) already supports org/folder scope
// unchanged, for anyone who needs it.
type GoogleScope struct {
	ScopeKind       string `json:"scope_kind"`
	ScopeID         string `json:"scope_id"`
	ReaderProjectID string `json:"reader_project_id"`
}

func (g GoogleScope) normalized() (GoogleScope, error) {
	n := GoogleScope{
		ScopeKind:       strings.TrimSpace(g.ScopeKind),
		ScopeID:         strings.TrimSpace(g.ScopeID),
		ReaderProjectID: strings.TrimSpace(g.ReaderProjectID),
	}
	if n.ScopeKind == "" {
		n.ScopeKind = models.CloudScopeProject
	}
	if !isSupportedGCPScopeKind(n.ScopeKind) {
		return n, fmt.Errorf("%w: scope_kind must be org, folder or project", ErrInvalidScopeID)
	}
	if n.ScopeID == "" {
		return n, fmt.Errorf("%w: scope_id is required", ErrInvalidScopeID)
	}
	if n.ReaderProjectID == "" {
		return n, fmt.Errorf("%w: reader_project_id is required", ErrInvalidScopeID)
	}
	return n, nil
}

// Preflight reports which required permissions the session's Google identity
// is missing for the given scope -- empty means every provisioning write
// below is expected to succeed. Called by the controller before showing
// "Allow AuthSec to configure access" as if it will succeed, AND re-run
// internally by Provision itself as defense-in-depth (a client must not be
// able to skip straight to Provision without ever calling this, and
// permissions could have changed since an earlier call).
func (s *GCPOAuthProvisionService) Preflight(ctx context.Context, sessionID string, callerWorkspaceID uuid.UUID, scope GoogleScope) ([]string, error) {
	sess, err := s.loadSession(ctx, sessionID, callerWorkspaceID)
	if err != nil {
		return nil, err
	}
	norm, err := scope.normalized()
	if err != nil {
		return nil, err
	}
	return s.preflightWithSession(ctx, sess, norm)
}

func (s *GCPOAuthProvisionService) preflightWithSession(ctx context.Context, sess *googleOAuthSession, scope GoogleScope) ([]string, error) {
	rmClient, err := newResourceManagerClientFunc(ctx, tokenClientOption(sess.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("%w: building resource manager client: %v", gcp.ErrGoogleOAuthProvisioningFailed, err)
	}

	missingReader, err := gcp.TestReaderProjectPermissions(ctx, rmClient, scope.ReaderProjectID)
	if err != nil {
		return nil, err
	}
	missingScope, err := gcp.TestScopePermission(ctx, rmClient, scope.ScopeKind, scope.ScopeID)
	if err != nil {
		return nil, err
	}

	missing := append([]string{}, missingReader...)
	for _, m := range missingScope {
		if !containsMissing(missing, m) {
			missing = append(missing, m)
		}
	}
	return missing, nil
}

func containsMissing(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

/* --------------------------------- provision ------------------------------------ */

// newServiceUsageClientFunc is a package-var seam (matching
// newIAMClientFunc/newResourceManagerClientFunc's own convention in
// services/cloud_gcp_onboarding.go, same package) so tests can point it at a
// fake server. There is no internal/gcp factory for this client -- adding
// one to internal/gcp/client.go was deliberately avoided to keep that file,
// which the WIF path also uses, completely untouched.
var newServiceUsageClientFunc = func(ctx context.Context, authOpt option.ClientOption) (*serviceusage.Service, error) {
	return serviceusage.NewService(ctx, authOpt)
}

// Provision is the Google Authentication bootstrap's orchestration:
//
//  1. Load the session (workspace-checked; no side effects).
//  2. Re-run Preflight. Any missing permission aborts here with ZERO GCP
//     writes attempted -- ErrGoogleOAuthPermissionsMissing, mapped by the
//     controller to a clean "use the existing WIF setup instead" response.
//  3. Only past this point does the session's access token get consumed
//     (GetDel) -- a workspace mismatch or a failed preflight never burns a
//     session a legitimate retry could still use.
//  4. Run the internal/gcp/provision.go steps, in the same order
//     setup-reader.sh performs them, against the reader project and the
//     requested scope. Every step is independently idempotent (see
//     provision.go's own doc comment) -- if one of these fails, whatever
//     was already created is INTENTIONALLY RETAINED, not rolled back, and a
//     retry of this whole call converges rather than erroring or
//     duplicating. No connector row exists yet at this point, so a partial
//     failure here never produces a connector that looks "connected".
//  5. Hand off to the EXISTING, UNMODIFIED GCPOnboardingService.Onboard with
//     Auth.Method="wif" -- the exact function a manual WIF paste-back
//     already calls, with the exact provider_resource/reader_sa_email a
//     human would have pasted back. This is what guarantees the resulting
//     row is indistinguishable in shape and behaviour from a manually
//     onboarded WIF connector: AuthMethod stays "wif", persistent
//     authentication is ResolveWIFCredential (untouched), and this function
//     never becomes a second implementation of WIF authentication -- it
//     only configures the GCP-side resources ResolveWIFCredential expects
//     to find.
//  6. Stamp two additive, non-secret provenance fields (ProvisionedVia,
//     ProvisionedBy=actor -- the same AuthSec principal identifier already
//     recorded as CreatedBy, not the Google account's email) onto the
//     connector's existing free-form Attrs jsonb. Best-effort: a failure
//     here does not fail the onboarding, since the connector is already
//     fully connected and correct without it.
func (s *GCPOAuthProvisionService) Provision(ctx context.Context, sessionID string, callerWorkspaceID uuid.UUID, scope GoogleScope, displayName, actor string) (*models.CloudConnector, bool, error) {
	sess, err := s.loadSession(ctx, sessionID, callerWorkspaceID)
	if err != nil {
		return nil, false, err
	}
	norm, err := scope.normalized()
	if err != nil {
		return nil, false, err
	}

	missing, err := s.preflightWithSession(ctx, sess, norm)
	if err != nil {
		return nil, false, err
	}
	if len(missing) > 0 {
		log.Printf("GCP-OAUTH-DEBUG: Provision aborted, missing permissions (scopeKind=%s scopeID=%s readerProject=%s): %s",
			norm.ScopeKind, norm.ScopeID, norm.ReaderProjectID, strings.Join(missing, ", "))
		return nil, false, fmt.Errorf("%w: missing %s", ErrGoogleOAuthPermissionsMissing, strings.Join(missing, ", "))
	}

	// The session is consumed only AFTER provisioning succeeds -- see the
	// deferred delete below. It used to be GetDel'd here, before the first GCP
	// write, which meant any failure downstream (most commonly the IAM
	// propagation delay onboardWithVerificationRetry exists to absorb) destroyed
	// the session too. The customer then could not simply click Connect again:
	// the retry returned "session expired" in milliseconds and the only way
	// forward was to repeat the entire Google consent round trip.
	//
	// The token is still used exactly once per successful Provision, and it is
	// still bounded -- googleOAuthSessionTTL caps how long a failed attempt
	// leaves it resumable, and Redis expires it with no further action.
	provisionOK := false
	defer func() {
		if !provisionOK {
			return
		}
		// Best-effort: the connector is already created and correct at this
		// point, so a Redis hiccup here must not fail the onboarding. The TTL
		// removes the key regardless.
		if err := s.redis.Del(context.WithoutCancel(ctx), gcpOAuthSessionKey(sessionID)).Err(); err != nil {
			log.Printf("gcp google-oauth: could not consume session after a successful provision (it will expire on its own): %v", err)
		}
	}()

	authOpt := tokenClientOption(sess.AccessToken)

	iamClient, err := newIAMClientFunc(ctx, authOpt)
	if err != nil {
		return nil, false, fmt.Errorf("%w: building iam client: %v", gcp.ErrGoogleOAuthProvisioningFailed, err)
	}
	rmClient, err := newResourceManagerClientFunc(ctx, authOpt)
	if err != nil {
		return nil, false, fmt.Errorf("%w: building resource manager client: %v", gcp.ErrGoogleOAuthProvisioningFailed, err)
	}
	suClient, err := newServiceUsageClientFunc(ctx, authOpt)
	if err != nil {
		return nil, false, fmt.Errorf("%w: building service usage client: %v", gcp.ErrGoogleOAuthProvisioningFailed, err)
	}

	// TEMPORARY DIAGNOSTIC LOGGING (GCP-OAuth 400 investigation): stage
	// markers only -- project ids/emails/pool ids are non-secret. Remove
	// once root cause is confirmed.
	if err := gcp.EnableServices(ctx, suClient, norm.ReaderProjectID); err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at EnableServices (readerProject=%s): %v", norm.ReaderProjectID, err)
		return nil, false, err
	}

	readerSAEmail, err := gcp.EnsureReaderServiceAccount(ctx, iamClient, norm.ReaderProjectID)
	if err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at EnsureReaderServiceAccount (readerProject=%s): %v", norm.ReaderProjectID, err)
		return nil, false, err
	}

	poolID, providerID, wifSubject := gcp.DeriveWIFParams(callerWorkspaceID, norm.ScopeID)

	if err := gcp.EnsureWIFPool(ctx, iamClient, norm.ReaderProjectID, poolID); err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at EnsureWIFPool (readerProject=%s poolID=%s): %v", norm.ReaderProjectID, poolID, err)
		return nil, false, err
	}

	issuerURL := gcp.ResolveWIFIssuerURL(s.issuerURL)
	if err := gcp.EnsureWIFProvider(ctx, iamClient, norm.ReaderProjectID, poolID, providerID, issuerURL); err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at EnsureWIFProvider (readerProject=%s poolID=%s providerID=%s issuerURL=%s): %v", norm.ReaderProjectID, poolID, providerID, issuerURL, err)
		return nil, false, err
	}

	projectNumber, err := gcp.ProjectNumber(ctx, rmClient, norm.ReaderProjectID)
	if err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at ProjectNumber (readerProject=%s): %v", norm.ReaderProjectID, err)
		return nil, false, err
	}

	if err := gcp.EnsureWorkloadIdentityBinding(ctx, iamClient, norm.ReaderProjectID, readerSAEmail, projectNumber, poolID, wifSubject); err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at EnsureWorkloadIdentityBinding (readerSAEmail=%s poolID=%s): %v", readerSAEmail, poolID, err)
		return nil, false, err
	}

	if err := gcp.EnsureReaderRoles(ctx, rmClient, norm.ScopeKind, norm.ScopeID, readerSAEmail, gcp.CandidateReaderRoles); err != nil {
		log.Printf("GCP-OAUTH-DEBUG: Provision failed at EnsureReaderRoles (scopeKind=%s scopeID=%s readerSAEmail=%s): %v", norm.ScopeKind, norm.ScopeID, readerSAEmail, err)
		return nil, false, err
	}

	providerResource := fmt.Sprintf(
		"projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, poolID, providerID,
	)

	log.Printf("GCP-OAUTH-DEBUG: Provision GCP-side resources ready, handing off to Onboard (providerResource=%s readerSAEmail=%s scopeKind=%s scopeID=%s)",
		providerResource, readerSAEmail, norm.ScopeKind, norm.ScopeID)

	connector, created, err := s.onboardWithVerificationRetry(ctx, callerWorkspaceID, GCPOnboardInput{
		ScopeKind:       norm.ScopeKind,
		ScopeID:         norm.ScopeID,
		ReaderProjectID: norm.ReaderProjectID,
		DisplayName:     displayName,
		Auth: GCPAuthInput{
			Method:           GCPAuthMethodWIF,
			ProviderResource: providerResource,
			ReaderSAEmail:    readerSAEmail,
		},
	}, actor)
	if err != nil {
		return nil, false, err
	}

	// The connector exists and has been verified against GCP. Only now is the
	// Google access token safe to discard -- everything below this line is
	// additive metadata that cannot fail the onboarding.
	provisionOK = true

	if serr := s.stampProvenance(callerWorkspaceID, connector.ID, actor); serr == nil {
		connector.Attrs = reloadAttrsOrKeep(s.db, callerWorkspaceID, connector.ID, connector.Attrs)
	}

	return connector, created, nil
}

// onboardWithVerificationRetry hands off to the existing, unmodified
// GCPOnboardingService.Onboard, retrying ONLY the transient WIF-verification
// failures (ErrWIFPoolMissing / ErrInvalidGrant from the STS token exchange
// inside Onboard's ResolveReaderIdentity step).
//
// Why this exists only here, never in the manual WIF flow: the manual flow
// has minutes of human latency between running setup-reader.sh and clicking
// "connect", which masks GCP's propagation window for a just-created
// pool/provider/binding. This option provisions and verifies back-to-back in
// one request, so a just-configured trust relationship can be rejected as
// invalid_target/invalid_grant for a short window even though every
// provisioning write succeeded -- surfacing that as an immediate 400 tells
// the user their (correct) setup is wrong. A bounded retry rides out that
// window; a genuinely misconfigured trust relationship still fails after the
// last attempt with the same error as before.
//
// Safe to retry: for Method="wif", Onboard performs zero GCP writes (no
// Vault interaction, only IAM/Resource-Manager reads plus the connector
// Upsert, which is idempotent per (workspace, scope)), so a retry never
// duplicates or mutates customer-side resources.
func (s *GCPOAuthProvisionService) onboardWithVerificationRetry(ctx context.Context, workspaceID uuid.UUID, in GCPOnboardInput, actor string) (*models.CloudConnector, bool, error) {
	// Sized for what Google actually does, not for an optimistic guess.
	//
	// The failure this retries is a freshly-written roles/iam.workloadIdentityUser
	// binding on a service account created seconds earlier. Google reports that as
	// 403 "Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or
	// it may not exist)" until IAM propagates it, which routinely takes 60s or
	// more -- so the previous budget (3 attempts, fixed 5s, ~15s total) expired
	// long before the grant went live and EVERY first-time connect failed.
	//
	// Backoff grows then caps at maxRetryDelay (see retryBackoff) so the poll
	// stays frequent enough to notice the moment the grant goes live, and is
	// jittered so several connectors provisioned at once do not poll in lockstep.
	//
	// Curve: ~3s, 5s, 8s, then 10s repeatedly -- ~65s of waiting across 8 sleeps,
	// ~75s including the STS round trip each attempt costs. Provisioning's GCP
	// writes take ~20s before this point, so the whole request stays inside the
	// 120s server timeout (middlewares.TimeoutMiddleware in cmd/main.go) and
	// inside the client's own 120s cap (GOOGLE_PROVISION_TIMEOUT_MS).
	const maxAttempts = 9
	const baseRetryDelay = 3 * time.Second

	var connector *models.CloudConnector
	var created bool
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		connector, created, err = s.onboardSvc.Onboard(ctx, workspaceID, in, actor)
		if err == nil {
			return connector, created, nil
		}
		if !isTransientWIFVerificationError(err) || attempt == maxAttempts {
			return nil, false, err
		}
		log.Printf("GCP-OAUTH-DEBUG: Onboard verification attempt %d/%d not yet accepted by GCP, retrying: %v",
			attempt, maxAttempts, err)
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-time.After(retryBackoff(baseRetryDelay, attempt)):
		}
	}
	return nil, false, err
}

// retryBackoff returns the wait before the next verification attempt: it grows
// quickly at first, then flattens at maxRetryDelay -- roughly 3s, 5s, 8s, then
// 10s repeatedly, with +/-20% jitter.
//
// Capped rather than purely exponential on purpose. Exponential backoff is the
// right shape when the far side is rate-limiting you and each call is
// expensive. This is the opposite: a cheap poll waiting for a fact to become
// true (Google applying an IAM binding), where the only cost of checking is one
// STS round trip. Doubling forever means that once the grant does go live the
// next probe can be a full minute away -- a live provision spent ~90s waiting
// when the propagation underneath had almost certainly finished far earlier.
// Capping keeps the same ceiling but detects completion within maxRetryDelay of
// it actually happening.
//
// Jitter stays, so several connectors provisioned at once do not poll in
// lockstep. math/rand (aliased mrand, since crypto/rand already holds the plain
// name in this file) is deliberate -- this is scheduling, not a security
// decision, and nothing about the delay needs to be unpredictable.
func retryBackoff(base time.Duration, attempt int) time.Duration {
	d := float64(base) * math.Pow(1.6, float64(attempt-1))
	if d > float64(maxRetryDelay) {
		d = float64(maxRetryDelay)
	}
	jitter := 1 + (mrand.Float64()*0.4 - 0.2) // [0.8, 1.2)
	return time.Duration(d * jitter)
}

// isTransientWIFVerificationError reports whether err is the STS-exchange
// rejection class that follows a just-provisioned trust relationship while
// GCP is still propagating it (see onboardWithVerificationRetry). Only these
// two sentinels are retried -- every other Onboard failure (bad input, missing
// permissions, unreachable issuer, scope not readable) is returned
// immediately, exactly as before.
func isTransientWIFVerificationError(err error) bool {
	return errors.Is(err, gcp.ErrWIFPoolMissing) || errors.Is(err, gcp.ErrInvalidGrant)
}

// stampProvenance records that this connector was auto-provisioned via
// Google Authentication and by which AuthSec actor -- additive metadata
// only (the connector already has everything it needs to function without
// it). Deliberately does NOT persist the Google account's email or any
// other Google identity detail: ProvisionedBy reuses the same AuthSec actor
// identifier already recorded as CreatedBy, the repository's existing
// audit/actor convention, per the minimum-necessary-persistence instruction
// this feature was built under. A failure here is swallowed by the caller.
func (s *GCPOAuthProvisionService) stampProvenance(workspaceID, id uuid.UUID, actor string) error {
	var c models.CloudConnector
	if err := s.db.Where("workspace_id = ? AND id = ?", workspaceID, id).First(&c).Error; err != nil {
		return err
	}
	attrs := c.GCPAttrs()
	attrs.ProvisionedVia = "google_oauth"
	attrs.ProvisionedBy = actor
	if err := c.SetGCPAttrs(attrs); err != nil {
		return err
	}
	return s.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Update("attrs", c.Attrs).Error
}

// reloadAttrsOrKeep re-reads the just-stamped Attrs so the connector this
// call returns to its caller reflects ProvisionedVia/ProvisionedBy rather
// than the pre-stamp snapshot Onboard returned. Falls back to the original
// value on any read error -- the stamp already succeeded in the database
// either way, so this only affects what this one response body shows.
func reloadAttrsOrKeep(db *gorm.DB, workspaceID, id uuid.UUID, fallback []byte) []byte {
	var c models.CloudConnector
	if err := db.Where("workspace_id = ? AND id = ?", workspaceID, id).First(&c).Error; err != nil {
		return fallback
	}
	return c.Attrs
}
