package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Worker timings. The lease is long relative to the progress interval so a
// worker that is merely slow on one large repository does not lose its run to a
// peer; it is short relative to a human's patience so a worker that actually
// died releases its run quickly.
const (
	scanWorkerPollInterval = 5 * time.Second
	scanWorkerLease        = 5 * time.Minute
)

// EnqueueGitHubScan validates a source and queues a scan for it.
//
// Validation happens HERE, synchronously, not in the worker. A request that can
// be known-bad up front — a disabled source, a plan that selects nothing —
// must fail as a 4xx the admin sees immediately. Accepting it with a 202 and
// failing asynchronously would turn a typo into something they have to go and
// discover in a run history.
func EnqueueGitHubScan(db *gorm.DB, workspaceID, sourceID uuid.UUID, actor string) (*models.DiscoveryScanRun, error) {
	discovery := NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	src, err := discovery.GetSource(workspaceID, sourceID)
	if err != nil {
		return nil, err
	}
	if src.Kind != models.DiscoverySourceRepoScan {
		return nil, fmt.Errorf("source %s is kind %q; GitHub scanning requires %q",
			sourceID, src.Kind, models.DiscoverySourceRepoScan)
	}
	if !src.Enabled {
		return nil, fmt.Errorf("discovery source %s is disabled", sourceID)
	}

	var cfg githubScannerConfig
	if len(src.Config) > 0 {
		_ = json.Unmarshal(src.Config, &cfg)
	}
	mode := cfg.Repositories.Mode
	if mode == "" {
		mode = "all"
	}
	// The same guard the scanner applies, applied earlier so the admin gets a
	// straight answer. Scanning nothing would report scanned=0 complete=true,
	// which reads as "your organisation is clean".
	if mode == "selected" && len(cfg.Repositories.Include) == 0 {
		return nil, errors.New("no repositories selected: choose repositories for this source before scanning")
	}
	branchMode, maxBranches := cfg.Branches.resolve()

	runs := repositories.NewDiscoveryScanRunRepository(db)
	return runs.Enqueue(&models.DiscoveryScanRun{
		WorkspaceID: workspaceID,
		SourceID:    sourceID,
		// The plan is snapshotted so the finished report describes what was
		// actually run, even if an admin edits the selection meanwhile.
		SelectionMode: mode,
		BranchMode:    branchMode,
		MaxBranches:   maxBranches,
		RequestedBy:   actor,
	})
}

// DiscoveryScanWorker drains the GitHub scan queue.
//
// It exists because the scan used to run inside the HTTP request that asked for
// it, which meant an org-wide scan raced the proxy's idle timeout and its
// result was never written down. Moving the work here makes the scan's duration
// irrelevant to the caller and gives every scan a durable record.
type DiscoveryScanWorker struct {
	runs repositories.DiscoveryScanRunRepository
	// newScanner is resolved per run rather than once at construction, so a
	// backend that started before Vault was reachable recovers by itself instead
	// of needing a restart.
	newScanner func() (*GitHubRepoScanner, error)
	name       string
	poll       time.Duration
	lease      time.Duration
}

// NewDiscoveryScanWorker builds the worker against the live GitHub provider.
func NewDiscoveryScanWorker(db *gorm.DB) *DiscoveryScanWorker {
	host, _ := os.Hostname()
	if host == "" {
		host = "worker"
	}
	return &DiscoveryScanWorker{
		runs: repositories.NewDiscoveryScanRunRepository(db),
		newScanner: func() (*GitHubRepoScanner, error) {
			addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
			if addr == "" || token == "" {
				return nil, errors.New("VAULT_ADDR/VAULT_TOKEN not configured; the GitHub App private key cannot be read")
			}
			vc, verr := vault.NewClient(addr, token)
			if verr != nil {
				return nil, verr
			}
			return NewGitHubRepoScanner(db, vc), nil
		},
		name:  fmt.Sprintf("%s/%s", host, uuid.NewString()[:8]),
		poll:  scanWorkerPollInterval,
		lease: scanWorkerLease,
	}
}

// NewDiscoveryScanWorkerWithScanner injects a scanner directly, so the queue can
// be exercised against recorded fixtures without a tenant or a Vault.
func NewDiscoveryScanWorkerWithScanner(db *gorm.DB, scanner *GitHubRepoScanner) *DiscoveryScanWorker {
	w := NewDiscoveryScanWorker(db)
	w.newScanner = func() (*GitHubRepoScanner, error) { return scanner, nil }
	w.poll = 50 * time.Millisecond
	return w
}

// Run drains the queue until ctx is cancelled.
func (w *DiscoveryScanWorker) Run(ctx context.Context) {
	log.Printf("[discovery-scan-worker] started as %s", w.name)
	for {
		if ctx.Err() != nil {
			log.Printf("[discovery-scan-worker] %s stopping", w.name)
			return
		}
		worked, err := w.RunOnce(ctx)
		if err != nil && !errors.Is(err, repositories.ErrScanRunNotFound) {
			log.Printf("[discovery-scan-worker] %s: %v", w.name, err)
		}
		if worked {
			continue // drain greedily while there is work
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.poll):
		}
	}
}

// RunOnce claims at most one run and executes it. Reports whether it found work.
func (w *DiscoveryScanWorker) RunOnce(ctx context.Context) (bool, error) {
	run, err := w.runs.ClaimNext(w.name, w.lease)
	if err != nil {
		if errors.Is(err, repositories.ErrScanRunNotFound) {
			return false, nil // queue empty
		}
		return false, err
	}

	scanner, err := w.newScanner()
	if err != nil {
		// Nothing is wrong with the run itself, but nothing can execute it
		// either. Fail it outright rather than retrying: three attempts against
		// an absent Vault produce the same answer three times, and a failed run
		// naming the missing configuration is more useful than a queued one.
		_ = w.runs.Finish(run, models.ScanRunFailed, err.Error())
		return true, err
	}

	res, scanErr := scanner.ScanWithOptions(ctx, run.WorkspaceID, run.SourceID, w.actorFor(run),
		ScanOptions{
			Done:   cursorSet(run),
			OnUnit: w.progressFn(run),
			Base:   baseFrom(run),
		})

	if res != nil {
		applyResult(run, res)
	}

	switch {
	case scanErr == nil:
		return true, w.runs.Finish(run, models.ScanRunSucceeded, "")

	case errors.Is(scanErr, repositories.ErrScanRunNotClaimable):
		// Our lease was taken over mid-scan. The run belongs to another worker
		// now; writing a terminal state would clobber its work.
		return true, nil

	case errors.Is(scanErr, context.Canceled), errors.Is(scanErr, context.DeadlineExceeded):
		// Shutting down. Put the run back with its cursor intact so the next
		// worker resumes rather than restarting the whole organisation.
		return true, w.runs.Requeue(run, "interrupted; will resume")

	default:
		// A genuine failure. Requeue gives it its remaining attempts and then
		// marks it failed, keeping the cursor so retries make progress.
		return true, w.runs.Requeue(run, scanErr.Error())
	}
}

// actorFor attributes sightings to whoever asked for the scan, not to the
// worker. A finding's provenance should name the human who triggered it.
func (w *DiscoveryScanWorker) actorFor(run *models.DiscoveryScanRun) string {
	if run.RequestedBy != "" {
		return run.RequestedBy
	}
	return "system"
}

// progressFn persists progress after each unit and doubles as the abort signal:
// if the lease is gone, the scan stops instead of finishing work it cannot
// record.
func (w *DiscoveryScanWorker) progressFn(run *models.DiscoveryScanRun) func(*GitHubScanResult) error {
	return func(res *GitHubScanResult) error {
		applyResult(run, res)
		return w.runs.SaveProgress(run, w.lease)
	}
}

// cursorSet reads the resume state: units a previous attempt already finished.
func cursorSet(run *models.DiscoveryScanRun) map[string]bool {
	out := map[string]bool{}
	if len(run.Cursor) == 0 {
		return out
	}
	var c models.ScanCursor
	if err := json.Unmarshal(run.Cursor, &c); err != nil {
		// An unreadable cursor means we cannot prove anything was done, so the
		// safe reading is that nothing was: rescanning a repository is wasteful,
		// skipping one silently is wrong.
		return out
	}
	for _, u := range c.Done {
		out[u] = true
	}
	return out
}

// baseFrom reconstructs what earlier attempts of this run achieved, so a resume
// continues the totals instead of restarting them.
func baseFrom(run *models.DiscoveryScanRun) *GitHubScanResult {
	if run.Attempts <= 1 {
		return nil // first attempt: nothing to carry
	}
	base := &GitHubScanResult{
		ReposFailed:     run.ReposFailed,
		ReposTruncated:  run.ReposTruncated,
		FilesFetched:    run.FilesFetched,
		SightingsNew:    run.SightingsNew,
		SightingsBumped: run.SightingsBumped,
		// Derived, not read from `complete`: that column stays false until the
		// run finishes, so it cannot carry this.
		Complete: !run.Degraded,
	}
	if len(run.Warnings) > 0 {
		_ = json.Unmarshal(run.Warnings, &base.Warnings)
	}
	return base
}

// applyResult copies the scanner's running totals onto the run row.
//
// Two fields are DERIVED from the cursor rather than copied. The scanner counts
// repositories and branches per attempt, so on a resume — where most units are
// skipped as already done — its counts describe only the new work. The cursor
// holds every finished unit across all attempts, which is exactly the quantity
// the console is asking for when it shows "42 of 60 repositories".
func applyResult(run *models.DiscoveryScanRun, res *GitHubScanResult) {
	run.ReposSelected = res.ReposSelected
	run.ReposFailed = res.ReposFailed
	run.ReposExcluded = res.ReposExcluded
	run.ReposTruncated = res.ReposTruncated
	run.BranchesSkipped = res.BranchesSkipped
	run.FilesFetched = res.FilesFetched
	run.SightingsNew = res.SightingsNew
	run.SightingsBumped = res.SightingsBumped
	run.SelectionMode = res.SelectionMode
	run.BranchMode = res.BranchMode

	// Monotonic: a gap seen by any attempt is a gap in the run.
	if !res.Complete {
		run.Degraded = true
	}
	run.Complete = !run.Degraded

	if res.Excluded != nil {
		if b, err := json.Marshal(res.Excluded); err == nil {
			run.ExcludedRepositories = b
		}
	}
	if res.Warnings != nil {
		if b, err := json.Marshal(res.Warnings); err == nil {
			run.Warnings = b
		}
	}

	// Union the cursor across attempts, then derive the unit counts from it.
	prior := cursorSet(run)
	for _, u := range res.Done {
		prior[u] = true
	}
	done := make([]string, 0, len(prior))
	repos := map[string]bool{}
	for u := range prior {
		done = append(done, u)
		if at := strings.LastIndex(u, "@"); at > 0 {
			repos[u[:at]] = true
		}
	}
	sort.Strings(done) // stable cursor: map order must not churn the stored JSON
	run.BranchesScanned = len(done)
	run.ReposScanned = len(repos)
	if b, err := json.Marshal(models.ScanCursor{Done: done}); err == nil {
		run.Cursor = b
	}
}
