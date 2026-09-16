package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"gorm.io/gorm"
)

/* cloud_gcp_scan.go is the GCP discovery scan runner.

   SHAPE. It mirrors the AWS runner's shape on purpose -- a controller-triggered
   goroutine, 202, poll the connector row -- because that is the contract the
   GCP plan's section 11.3 says to copy and because two cloud connectors that
   behave differently for no reason are worse than one imperfect pattern applied
   twice. It deliberately does NOT copy four things the AWS runner does, each
   noted at the point it matters:

     1. Generation is allocated atomically, up front, by the repository, rather
        than computed in Go from an earlier read.
     2. Every phase has its own deadline, derived from one scan-wide parent,
        rather than a single budget that is cancelled before the later phases
        even start.
     3. Coverage is built from the surfaces this scan ATTEMPTED, and is written
        before the scan returns on every path including failure.
     4. A capped or truncated read marks its surface not-reached. There is no
        path here on which a bounded read reports as complete.

   WHAT IT DOES NOT DO YET. No checkpointing and no resume: an interrupted scan
   restarts from the beginning. That is a decision (D-15), not an oversight --
   the shared cloud_scan_checkpoint mechanism cannot currently resume anything,
   which AWS's own test records at tests/integration/cloud_aws_resume_test.go:169-186,
   and fixing it changes reconciliation timing for both providers. Nothing here
   writes a checkpoint row.

   PHASE 1 SURFACES. identities and keys, and nothing else. The onboarding
   coverage skeleton lists all thirteen probed surfaces, but a scan's coverage
   must describe what the SCAN did: ScanCoverage.Complete() requires every
   surface in the map to be reached, so inheriting eight surfaces this phase
   never looks at would hold Complete() false forever and silently disable
   reconciliation for GCP permanently. See buildCoverage. */

/* --------------------------------- errors ----------------------------------- */

var (
	// ErrScanAlreadyRunning means this connector already has a scan in flight.
	ErrScanAlreadyRunning = errors.New("gcp: a scan is already running for this connector")

	// ErrScanNotReady means onboarding's own probe concluded this connector
	// cannot be scanned -- typically an unusable quota project, where every
	// Cloud Asset call would fail no matter how correct the permissions are.
	//
	// Checked rather than discovered the hard way: DiscoveryReadiness is
	// computed on every onboard and verify (services/cloud_gcp_readiness.go:89)
	// and until now nothing read it.
	ErrScanNotReady = errors.New("gcp: this connector is not ready for discovery")
)

/* -------------------------------- timeouts ---------------------------------- */

// Per-phase budgets, all derived from one scan-wide parent so cancelling the
// scan cancels every phase.
//
// Explicitly not the AWS arrangement, where the 20-minute budget is created in
// the identity scanner and cancelled by its own defer before the permission and
// workload scanners start -- those then receive a fresh context.Background()
// from the controller and run unbounded.
const (
	gcpScanTimeout       = 30 * time.Minute
	gcpEnumerateTimeout  = 2 * time.Minute
	gcpIdentitiesTimeout = 15 * time.Minute
	gcpKeysTimeout       = 15 * time.Minute
)

// gcpScanLocks is the in-process half of the in-flight guard: one mutex per
// connector id.
//
// ADVISORY, NOT A LOCK. It stops the common case -- an operator double-clicking
// Scan against one replica -- and does nothing across replicas. The durable
// half is the running coverage blob checked in guardInFlight. Neither is a
// distributed lock and neither is claimed to be one. What actually makes
// concurrency safe is that two scans can never share a generation, because
// AllocateGeneration is a single atomic statement: the worst a slipped guard
// costs is duplicated work and one refused commit, never interleaved writes at
// one generation.
var gcpScanLocks sync.Map // connectorID -> *sync.Mutex

/* -------------------------------- the scanner ------------------------------- */

// GCPScanSnapshot is what one scan produced, carried between phases so every
// later phase stamps the same generation. The analogue of AWS's IAMSnapshot.
type GCPScanSnapshot struct {
	ConnectorID uuid.UUID
	Generation  int
	ScopeKind   string
	ScopeID     string
	// Projects is the set this scan enumerated and read.
	Projects []gcpProject
	// Coverage is the report, as committed.
	Coverage models.ScanCoverage
}

// gcpProject is the minimum a collector needs to address a project.
type gcpProject struct {
	// ProjectID is the human-readable id, and what the IAM API addresses.
	ProjectID string
	// Number is the immutable identifier, recorded on every row this project
	// produces. A project id string can be reused after deletion; the number
	// cannot.
	Number string
}

// GCPScanner reads a GCP estate into the shared cloud_* tables.
type GCPScanner struct {
	connectors repositories.CloudConnectorRepository
	scans      repositories.CloudGCPScanRepository
	identities repositories.CloudIdentityRepository
	authSvc    *GCPAuthService

	// Client factories, overridable in tests. Package-level vars are already
	// how cloud_gcp_onboarding.go does this; these are fields so two scanners
	// in one test binary cannot fight over a global.
	newIAMClient func(context.Context, option.ClientOption) (*iam.Service, error)
	newRMClient  func(context.Context, option.ClientOption) (*cloudresourcemanager.Service, error)

	// newCredential resolves the reader credential. A field for the same reason
	// as the factories above: it is the other half of the GCP boundary, and a
	// test that fakes the API but not the credential cannot reach the code
	// under test at all.
	newCredential func(context.Context, uuid.UUID, *models.CloudConnector, models.GCPConnectorAttrs) (option.ClientOption, error)
}

// NewGCPScanner constructs the scanner. authSvc is the same service onboarding
// uses -- the credential path is reused wholesale, never reimplemented.
func NewGCPScanner(db *gorm.DB, authSvc *GCPAuthService) *GCPScanner {
	s := &GCPScanner{
		connectors:   repositories.NewCloudConnectorRepository(db),
		scans:        repositories.NewCloudGCPScanRepository(db),
		identities:   repositories.NewCloudIdentityRepository(db),
		authSvc:      authSvc,
		newIAMClient: gcp.NewIAMClient,
		newRMClient:  gcp.NewResourceManagerClient,
	}
	s.newCredential = s.credentialFor
	return s
}

// WithClientFactories replaces the GCP client constructors.
//
// A test seam, mirroring awsdiscovery.ActivityReader.WithSleep: the GCP
// boundary is the only part of a scan a test cannot run for real, and
// everything downstream of it -- the governor, the retry, the upserts, the
// coverage aggregation and the reconciliation gate -- is then exercised as
// shipped rather than mocked past. Production never calls this.
func (s *GCPScanner) WithClientFactories(
	iamFn func(context.Context, option.ClientOption) (*iam.Service, error),
	rmFn func(context.Context, option.ClientOption) (*cloudresourcemanager.Service, error),
) *GCPScanner {
	if iamFn != nil {
		s.newIAMClient = iamFn
	}
	if rmFn != nil {
		s.newRMClient = rmFn
	}
	return s
}

// WithCredentialFactory replaces the reader-credential resolver. The other
// half of the GCP boundary seam; production never calls this.
func (s *GCPScanner) WithCredentialFactory(
	fn func(context.Context, uuid.UUID, *models.CloudConnector, models.GCPConnectorAttrs) (option.ClientOption, error),
) *GCPScanner {
	if fn != nil {
		s.newCredential = fn
	}
	return s
}

// Scan reads service accounts and their keys for one connector.
//
// Returns the snapshot on every path where a generation was allocated, so a
// caller can report what happened even when the scan failed -- the outcome is
// never computed and then dropped.
func (s *GCPScanner) Scan(ctx context.Context, workspaceID, connectorID uuid.UUID) (*GCPScanSnapshot, error) {
	connector, err := s.connectors.Get(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	if connector.Provider != models.CloudProviderGCP {
		return nil, fmt.Errorf("connector %s is a %s connector", connectorID, connector.Provider)
	}
	if connector.Status == models.CloudConnectorRevoked {
		return nil, fmt.Errorf("%w: the connection was revoked", ErrScanNotPermitted)
	}
	attrs := connector.GCPAttrs()
	if attrs.DiscoveryReadiness == models.GCPReadinessBlocked {
		return nil, fmt.Errorf("%w: %v", ErrScanNotReady, attrs.DiscoveryReadinessReasons)
	}

	unlock, err := s.guardInFlight(connector)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Atomic, and before any GCP call: nothing this scan writes can be stamped
	// with a number another scan also holds.
	generation, err := s.scans.AllocateGeneration(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}

	snapshot := &GCPScanSnapshot{
		ConnectorID: connectorID,
		Generation:  generation,
		ScopeKind:   connector.ScopeKind,
		ScopeID:     connector.ScopeID,
	}

	authOpt, err := s.newCredential(ctx, workspaceID, connector, attrs)
	if err != nil {
		// Could not even authenticate. Recorded as a failed scan rather than
		// left showing the previous report, which would let a broken connection
		// keep displaying a stale all-clear. Nothing is reconciled.
		snapshot.Coverage = s.commitFailed(workspaceID, connectorID, generation, err)
		return snapshot, err
	}

	scanCtx, cancelScan := context.WithTimeout(ctx, gcpScanTimeout)
	defer cancelScan()

	started := time.Now()
	running := models.ScanCoverage{
		Generation: generation,
		Status:     models.ScanStatusRunning,
		StartedAt:  &started,
		Surfaces:   map[string]models.SurfaceCoverage{},
		Counters:   map[string]int{},
	}
	if err := s.writeCoverage(workspaceID, connectorID, generation, running, s.scans.BeginScan); err != nil {
		// Superseded before we read anything. Better to find out here than
		// after a scan window spent calling GCP on a generation that no longer
		// owns the connector.
		return snapshot, err
	}

	governor := gcp.NewGovernor()

	identityAcc := newGCPSurfaceAcc()
	keyAcc := newGCPSurfaceAcc()

	// ---- project set -------------------------------------------------------
	//
	// iam.serviceAccounts.list is PROJECT-SCOPED and has no organization-wide
	// form, so an org or folder connector has to enumerate before it can read.
	// A connector that cannot enumerate has not found an empty estate; it has
	// failed to look, and both surfaces say so.
	projects, enumErr := s.resolveProjects(scanCtx, connector, attrs, authOpt, governor)
	if enumErr != nil {
		identityAcc.fail(enumErr)
		keyAcc.fail(enumErr)
	}
	snapshot.Projects = projects

	if enumErr == nil {
		iamClient, clientErr := s.newIAMClient(scanCtx, authOpt)
		if clientErr != nil {
			identityAcc.fail(clientErr)
			keyAcc.fail(clientErr)
		} else {
			s.runIdentityPhases(scanCtx, workspaceID, snapshot, iamClient, governor, identityAcc, keyAcc)
		}
	}

	coverage := s.buildCoverage(generation, started, identityAcc, keyAcc, governor, len(projects))

	// ---- reconcile, and only behind two proofs -----------------------------
	//
	// Complete() proves the scan was allowed to look everywhere it attempted.
	// The generation check proves nothing has started since -- a slow scan that
	// was overtaken has no standing to delete against a generation it no longer
	// owns.
	if coverage.Complete() && s.stillOwnsGeneration(workspaceID, connectorID, generation) {
		removedIdentities, removedSecrets, recErr := s.identities.ReconcileGeneration(
			workspaceID, connectorID, generation)
		if recErr != nil {
			return snapshot, recErr
		}
		coverage.Counters["identities_removed"] = int(removedIdentities)
		coverage.Counters["secrets_removed"] = int(removedSecrets)
		coverage.Status = models.ScanStatusComplete
	} else {
		// The rule the whole schema exists for: unreached is not missing. A
		// denied serviceAccounts.list and a project with no service accounts
		// are identical in the database, so a scan that could not look must
		// never conclude that anything is gone.
		coverage.Counters["identities_removed"] = 0
		coverage.Counters["secrets_removed"] = 0
		coverage.Status = models.ScanStatusPartial
	}

	finished := time.Now()
	coverage.FinishedAt = &finished
	if ids, secrets, err := s.identities.CountsForConnector(workspaceID, connectorID); err == nil {
		coverage.Counters["identities_total"] = int(ids)
		coverage.Counters["secrets_total"] = int(secrets)
	}

	snapshot.Coverage = coverage
	if err := s.writeCoverage(workspaceID, connectorID, generation, coverage, s.scans.CommitCoverage); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

/* ------------------------------- phase driver ------------------------------- */

// runIdentityPhases reads service accounts, then their keys, each under its own
// deadline derived from the scan-wide context.
func (s *GCPScanner) runIdentityPhases(
	scanCtx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	iamClient *iam.Service, governor *gcp.Governor,
	identityAcc, keyAcc *gcpSurfaceAcc,
) {
	identityCtx, cancelIdentities := context.WithTimeout(scanCtx, gcpIdentitiesTimeout)
	defer cancelIdentities()
	written := s.collectIdentities(identityCtx, workspaceID, snapshot, iamClient, governor, identityAcc)

	keyCtx, cancelKeys := context.WithTimeout(scanCtx, gcpKeysTimeout)
	defer cancelKeys()
	// Whether the keys surface can be called vacuously covered when there are
	// no accounts depends on whether the identity phase actually saw the whole
	// estate. Computed here, where both accumulators are in view.
	s.collectKeys(keyCtx, workspaceID, snapshot, iamClient, governor, keyAcc,
		written, identityAcc.reachedEverything())
}

/* ------------------------------- guards ------------------------------------- */

// guardInFlight refuses a second concurrent scan of one connector.
//
// Two halves, neither a distributed lock. The in-process mutex catches the
// common case on one replica. The durable half reads the connector's own
// coverage: a report still marked running, whose started_at is inside the scan
// budget, means someone is already doing this.
//
// A running report OLDER than the budget is treated as dead and the scan
// proceeds. A crashed process must not wedge a connector forever, which is
// exactly what a lock with no expiry would do.
func (s *GCPScanner) guardInFlight(connector *models.CloudConnector) (func(), error) {
	raw, _ := gcpScanLocks.LoadOrStore(connector.ID, &sync.Mutex{})
	mu := raw.(*sync.Mutex)
	if !mu.TryLock() {
		return nil, ErrScanAlreadyRunning
	}

	cov := models.DecodeScanCoverage(connector.Coverage)
	if cov.Status == models.ScanStatusRunning && cov.StartedAt != nil &&
		time.Since(*cov.StartedAt) < gcpScanTimeout {
		mu.Unlock()
		return nil, ErrScanAlreadyRunning
	}
	return mu.Unlock, nil
}

// stillOwnsGeneration reports whether this scan is still the current one.
//
// A read error answers NO. The question this gates is whether deletion is
// permitted, and the safe answer to "I could not tell" is to keep the data.
func (s *GCPScanner) stillOwnsGeneration(workspaceID, connectorID uuid.UUID, generation int) bool {
	current, err := s.scans.CurrentGeneration(workspaceID, connectorID)
	if err != nil {
		log.Printf("gcp scan: connector=%s could not confirm generation ownership, skipping reconciliation: %v",
			connectorID, err)
		return false
	}
	return current == generation
}

/* ------------------------------ credentials --------------------------------- */

// credentialFor reuses onboarding's credential path exactly -- a fresh WIF
// exchange per scan, or the legacy Vault-held key for a connector onboarded
// before keys were closed off.
//
// The WIF path mints a subject token per exchange rather than caching one
// (internal/gcp/auth.go:260-276), which is what makes these credentials usable
// for a long scan rather than a single verify call.
func (s *GCPScanner) credentialFor(
	ctx context.Context, workspaceID uuid.UUID,
	connector *models.CloudConnector, attrs models.GCPConnectorAttrs,
) (option.ClientOption, error) {
	switch attrs.AuthMethod {
	case GCPAuthMethodJSONKey:
		return s.authSvc.LoadCredential(connector.AuthRef)
	case GCPAuthMethodWIF:
		return s.authSvc.BuildWIFCredential(
			ctx, workspaceID, connector.ScopeID, attrs.WIFProviderResource, attrs.ReaderSAEmail)
	default:
		return nil, fmt.Errorf("%w: unknown auth method %q", gcp.ErrInvalidGrant, attrs.AuthMethod)
	}
}

/* --------------------------- coverage accumulation -------------------------- */

// gcpSurfaceAcc accumulates one surface's outcome across many projects.
//
// A surface is read once per project, and those reads can disagree: three
// projects fine, one denied. The single state recorded must be the WORST of
// them, because any non-reached project makes the count a floor rather than a
// total -- and Complete() must not be true when part of the estate was not
// seen. Per-project detail that the one state cannot carry goes to counters.
// Every method takes mu: projects are read concurrently, so observations land
// from several goroutines at once. The accumulator is the one piece of shared
// mutable state in a fan-out, and an unsynchronised worst-outcome-wins merge
// would be exactly the kind of race that loses a `denied` and lets a partial
// scan reconcile.
type gcpSurfaceAcc struct {
	mu          sync.Mutex
	state       string
	count       int
	reason      string
	total       int
	reached     int
	denied      int
	throttled   int
	constrained int
}

func newGCPSurfaceAcc() *gcpSurfaceAcc {
	// Starts unknown: a surface nothing touched must never read as an empty
	// success.
	return &gcpSurfaceAcc{state: models.CloudCoverageUnknown}
}

// surfaceStateRank orders outcomes worst-first. Higher wins.
func surfaceStateRank(state string) int {
	switch state {
	case models.CloudCoverageDenied:
		return 4
	case models.CloudCoverageConstrained:
		return 3
	case models.CloudCoverageThrottled:
		return 2
	case models.CloudCoverageReached:
		return 1
	default: // unknown
		return 0
	}
}

// observe records one project's outcome for this surface.
func (a *gcpSurfaceAcc) observe(err error, found int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.total++
	a.count += found

	state := classifyGCPSurfaceError(err)
	switch state {
	case models.CloudCoverageReached:
		a.reached++
	case models.CloudCoverageDenied:
		a.denied++
	case models.CloudCoverageThrottled:
		a.throttled++
	case models.CloudCoverageConstrained:
		a.constrained++
	}
	if err != nil && a.reason == "" {
		a.reason = sanitizedSurfaceReason(err)
	}
	if surfaceStateRank(state) > surfaceStateRank(a.state) {
		a.state = state
	} else if a.state == models.CloudCoverageUnknown {
		a.state = state
	}
}

// reachedEverything reports whether every observation this surface made came
// back reached. Behind the lock because the fan-out is still able to be writing
// when the key phase asks.
func (a *gcpSurfaceAcc) reachedEverything() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == models.CloudCoverageReached
}

// snapshotCounters returns the per-project tallies, behind the lock.
func (a *gcpSurfaceAcc) snapshotCounters() (reached, denied, throttled, constrained int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reached, a.denied, a.throttled, a.constrained
}

// observeVacuous records that a surface was fully covered by virtue of having
// nothing to read -- there were no service accounts, so there were no keys.
//
// Distinct from observe(nil, 0), which would also be correct here but reads as
// "one project answered with zero". This is "there was nothing to ask about",
// and naming it keeps the two apart for anyone reading the counters.
func (a *gcpSurfaceAcc) observeVacuous() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == models.CloudCoverageUnknown {
		a.state = models.CloudCoverageReached
	}
}

// fail records a whole-surface failure that happened before any project was
// attempted -- enumeration refused, a client that would not build.
func (a *gcpSurfaceAcc) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state := classifyGCPSurfaceError(err)
	if surfaceStateRank(state) > surfaceStateRank(a.state) || a.state == models.CloudCoverageUnknown {
		a.state = state
	}
	if a.reason == "" {
		a.reason = sanitizedSurfaceReason(err)
	}
}

func (a *gcpSurfaceAcc) coverage() models.SurfaceCoverage {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := models.SurfaceCoverage{State: a.state, Count: a.count}
	if a.state != models.CloudCoverageReached {
		out.Error = a.reason
	}
	return out
}

// classifyGCPSurfaceError turns one read's outcome into a coverage state.
//
// The distinctions are the point. A constraint is the customer's own deliberate
// policy and asking them to grant a role would be the wrong conversation; a
// denial is a missing grant and is fixed by granting it; a throttle is neither
// and will likely succeed later. Collapsing them into one "failed" would make
// the report useless for the only decision anyone makes from it.
func classifyGCPSurfaceError(err error) string {
	switch {
	case err == nil:
		return models.CloudCoverageReached
	case gcp.ClassifyConstraint(err) != nil:
		return models.CloudCoverageConstrained
	case gcp.IsThrottle(err):
		return models.CloudCoverageThrottled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// A phase that ran out of budget did not finish reading. It is not a
		// permission problem, and it is certainly not an empty result.
		return models.CloudCoverageThrottled
	default:
		return models.CloudCoverageDenied
	}
}

// sanitizedSurfaceReason is what goes into the coverage blob for a failed read.
//
// A constraint is reduced to its reason code rather than the provider's
// sentence, because that sentence can name resources inside the customer's
// estate and coverage is read in places that should not carry them.
func sanitizedSurfaceReason(err error) string {
	if err == nil {
		return ""
	}
	if code := gcp.ConstraintReasonCode(gcp.ClassifyConstraint(err)); code != "" {
		return code
	}
	return err.Error()
}

// buildCoverage assembles the report from the surfaces this scan ATTEMPTED.
//
// It deliberately does not start from the connector's onboarding coverage
// skeleton. That skeleton lists all thirteen surfaces the capability probe
// asks about (services/cloud_gcp_readiness.go:56-73), and it is right for what
// it is: a pre-scan statement that nothing has been looked at yet. But
// Complete() requires EVERY surface in the map to be reached, and this phase
// reads two of the thirteen -- so inheriting it would leave eleven surfaces
// permanently unknown, hold Complete() false forever, and disable GCP
// reconciliation for good in a way nothing would ever surface as a bug.
//
// Complete() therefore means "every surface this scan attempted was reached",
// which is the same meaning it has for AWS and the only one that is sound.
//
// Nothing is lost by not inheriting it: the durable capability record is
// connector attrs.CapabilityProfile, which this scan never touches. Onboarding
// and verify own attrs; scans own coverage.
func (s *GCPScanner) buildCoverage(
	generation int, started time.Time,
	identityAcc, keyAcc *gcpSurfaceAcc, governor *gcp.Governor, projectCount int,
) models.ScanCoverage {
	reached, denied, throttled, constrained := identityAcc.snapshotCounters()
	cov := models.ScanCoverage{
		Generation: generation,
		Status:     models.ScanStatusRunning,
		StartedAt:  &started,
		Surfaces: map[string]models.SurfaceCoverage{
			gcp.SurfaceIdentities: identityAcc.coverage(),
			gcp.SurfaceKeys:       keyAcc.coverage(),
		},
		Counters: map[string]int{
			"projects_total":       projectCount,
			"projects_reached":     reached,
			"projects_denied":      denied,
			"projects_throttled":   throttled,
			"projects_constrained": constrained,
			"project_concurrency":  governor.ProjectConcurrency(),
			"identities_upserted":  identityAcc.count,
			"secrets_upserted":     keyAcc.count,
		},
	}
	return cov
}

/* ------------------------------ coverage writes ----------------------------- */

func (s *GCPScanner) writeCoverage(
	workspaceID, connectorID uuid.UUID, generation int, coverage models.ScanCoverage,
	write func(uuid.UUID, uuid.UUID, int, json.RawMessage) error,
) error {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return err
	}
	return write(workspaceID, connectorID, generation, raw)
}

// commitFailed records a scan that could not start, and returns what it wrote.
//
// Best-effort on the write itself: a scan that already failed should surface
// the original error, not a secondary one from trying to report it.
func (s *GCPScanner) commitFailed(
	workspaceID, connectorID uuid.UUID, generation int, cause error,
) models.ScanCoverage {
	now := time.Now()
	cov := models.ScanCoverage{
		Generation: generation,
		Status:     models.ScanStatusFailed,
		StartedAt:  &now,
		FinishedAt: &now,
		Error:      sanitizedSurfaceReason(cause),
		// No surfaces. An empty surface map is not Complete(), so nothing
		// downstream can mistake a scan that never ran for one that found
		// nothing.
		Surfaces: map[string]models.SurfaceCoverage{},
		Counters: map[string]int{},
	}
	if err := s.writeCoverage(workspaceID, connectorID, generation, cov, s.scans.CommitCoverage); err != nil {
		log.Printf("gcp scan: connector=%s could not record failed coverage for generation %d: %v",
			connectorID, generation, err)
	}
	return cov
}
