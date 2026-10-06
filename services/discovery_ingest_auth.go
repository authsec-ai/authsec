package services

import (
	"log"
	"os"
	"strings"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DiscoveryIngestAuthMode is how the discovery ingress treats a call's
// `Authorization: Bearer <ingest token>`. Set by IGA_DISCOVERY_INGEST_AUTH.
type DiscoveryIngestAuthMode string

const (
	// IngestAuthOff checks nothing: the workspace in the body is trusted, as
	// it was before ingest tokens existed.
	IngestAuthOff DiscoveryIngestAuthMode = "off"
	// IngestAuthWarn (the default) attributes a call with a valid token and
	// ACCEPTS one without (logged and counted), so agents installed before
	// tokens existed keep working while they are rolled out. A valid token for
	// another workspace is still refused.
	IngestAuthWarn DiscoveryIngestAuthMode = "warn"
	// IngestAuthEnforce refuses every call without a valid, unrevoked token for
	// the body's workspace (and, for a bound token, the call's source).
	IngestAuthEnforce DiscoveryIngestAuthMode = "enforce"
)

// DiscoveryIngestAuthEnv names the mode's environment variable.
const DiscoveryIngestAuthEnv = "IGA_DISCOVERY_INGEST_AUTH"

// DiscoveryIngestAuthModeFromEnv reads IGA_DISCOVERY_INGEST_AUTH. Unset or
// empty is warn. An unrecognised value is ENFORCE: a typo in a setting that
// exists to close the ingress must not quietly leave it open.
func DiscoveryIngestAuthModeFromEnv() DiscoveryIngestAuthMode {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(DiscoveryIngestAuthEnv)))
	switch DiscoveryIngestAuthMode(raw) {
	case "":
		return IngestAuthWarn
	case IngestAuthOff, IngestAuthWarn, IngestAuthEnforce:
		return DiscoveryIngestAuthMode(raw)
	default:
		log.Printf("discovery ingest auth: %s=%q is not off|warn|enforce; enforcing", DiscoveryIngestAuthEnv, raw)
		return IngestAuthEnforce
	}
}

// IngestAuthOutcome is what the ingress does with a call.
type IngestAuthOutcome int

const (
	// IngestAccept: proceed. Token is set when the call authenticated.
	IngestAccept IngestAuthOutcome = iota
	// IngestAcceptUnauthenticated: proceed, but the call carried no valid
	// token for its workspace/source (warn mode). Log and count it.
	IngestAcceptUnauthenticated
	// IngestRejectUnauthenticated: 401 (enforce mode).
	IngestRejectUnauthenticated
	// IngestRejectForeignWorkspace: 403. A valid token of ANOTHER workspace,
	// in every mode but off.
	IngestRejectForeignWorkspace
)

// Reasons an ingress call is not authenticated.
const (
	IngestReasonMissing     = "missing"      // no bearer token
	IngestReasonInvalid     = "invalid"      // unknown, malformed or revoked
	IngestReasonWrongSource = "wrong_source" // bound token, call resolves to another (or no) source
)

// IngestAuthDecision is the outcome of authorising one ingress call.
type IngestAuthDecision struct {
	Outcome IngestAuthOutcome
	Mode    DiscoveryIngestAuthMode
	// Reason is set for the two unauthenticated outcomes.
	Reason string
	// Token is the verified token, for an accepted authenticated call and for
	// a foreign-workspace refusal. Its hash is never populated.
	Token *models.DiscoveryIngestToken
}

// DiscoveryIngestTokens mints, lists and revokes discovery ingest tokens and
// authorises ingress calls with them.
type DiscoveryIngestTokens struct {
	repo repositories.DiscoveryIngestTokenRepository
}

// NewDiscoveryIngestTokens constructs the service over a database handle.
func NewDiscoveryIngestTokens(db *gorm.DB) *DiscoveryIngestTokens {
	return &DiscoveryIngestTokens{repo: repositories.NewDiscoveryIngestTokenRepository(db)}
}

// Mint creates a token for workspaceID and returns the row and the plaintext.
// The workspace is always the caller's; sourceID, when set, must be one of its
// sources (repositories.ErrIngestTokenSourceNotFound otherwise).
func (s *DiscoveryIngestTokens) Mint(workspaceID uuid.UUID, sourceID *uuid.UUID, label, createdBy string) (*models.DiscoveryIngestToken, string, error) {
	return s.repo.Mint(workspaceID, sourceID, label, createdBy)
}

// List returns the workspace's tokens without their hashes.
func (s *DiscoveryIngestTokens) List(workspaceID uuid.UUID) ([]models.DiscoveryIngestToken, error) {
	return s.repo.List(workspaceID)
}

// Revoke revokes one of the workspace's tokens.
func (s *DiscoveryIngestTokens) Revoke(workspaceID, id uuid.UUID) (*models.DiscoveryIngestToken, error) {
	return s.repo.Revoke(workspaceID, id)
}

// Authorize decides one ingress call.
//
// presented is the bearer token ("" when absent). workspaceID is the workspace
// the BODY asserts. resolveSource returns the discovery source the call
// resolves to (nil when it names none); it is consulted only for a token bound
// to a source, so an unbound token costs no extra query.
//
// The order is the contract:
//  1. off: accept, nothing is read.
//  2. no token, or not a live token: 401 in enforce, accept-and-count in warn.
//  3. a live token of ANOTHER workspace: 403 in warn and enforce. A token
//     never authorises another workspace, and in warn this is what turns a
//     mis-pasted secret into an error instead of a silent cross-tenant write.
//  4. a bound token whose source is not the call's: not valid for this call,
//     so 401 in enforce, accept-and-count in warn.
//  5. otherwise: accept, attributed to the token.
//
// An error is a database failure; the caller decides how to fail (closed in
// enforce).
func (s *DiscoveryIngestTokens) Authorize(mode DiscoveryIngestAuthMode, presented string, workspaceID uuid.UUID,
	resolveSource func() (*uuid.UUID, error)) (IngestAuthDecision, error) {
	d := IngestAuthDecision{Mode: mode}
	if mode == IngestAuthOff {
		d.Outcome = IngestAccept
		return d, nil
	}
	unauthenticated := func(reason string) (IngestAuthDecision, error) {
		d.Reason = reason
		if mode == IngestAuthEnforce {
			d.Outcome = IngestRejectUnauthenticated
		} else {
			d.Outcome = IngestAcceptUnauthenticated
		}
		return d, nil
	}

	if presented == "" {
		return unauthenticated(IngestReasonMissing)
	}
	tok, err := s.repo.Verify(presented)
	if err != nil {
		return d, err
	}
	if tok == nil {
		return unauthenticated(IngestReasonInvalid)
	}
	d.Token = tok
	if tok.WorkspaceID != workspaceID {
		d.Outcome = IngestRejectForeignWorkspace
		return d, nil
	}
	if tok.DiscoverySourceID != nil {
		src, err := resolveSource()
		if err != nil {
			return d, err
		}
		if src == nil || *src != *tok.DiscoverySourceID {
			return unauthenticated(IngestReasonWrongSource)
		}
	}
	d.Outcome = IngestAccept
	return d, nil
}
