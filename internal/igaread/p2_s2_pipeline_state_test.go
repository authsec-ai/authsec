package igaread

// Pure derivations behind GET /pipeline and GET /coverage (T2.3): §2.14.7's
// per-account state table, D-59's retrying job, and D-58's prevents mapping,
// over the WHOLE vocabulary -- so a state added to models.CloudCoverage* or a
// row of the table dropped from the switch shows up here, not in a console.

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

func s2Run(status string, job *string, attempts int) *pipelineRun {
	r := &pipelineRun{JobStatus: job}
	r.Status = status
	if job != nil {
		r.JobAttempts = &attempts
	}
	return r
}

func s2Str(s string) *string { return &s }

func TestS2AccountStateTable(t *testing.T) {
	belowCeiling := repositories.MaxProjectionAttempts - 1
	for _, c := range []struct {
		name      string
		connector string
		run       *pipelineRun
		published bool
		want      string
	}{
		// D-89: a revoked connector is revoked whatever its runs say.
		{"revoked", models.CloudConnectorRevoked, s2Run(models.CloudScanRunQueued, nil, 0), true, PipelineRevoked},
		{"connected, never scanned", models.CloudConnectorActive, nil, false, PipelineNeverScanned},
		// A connector whose last verification failed still scans.
		{"error connector, never scanned", models.CloudConnectorError, nil, false, PipelineNeverScanned},
		{"queued", models.CloudConnectorActive, s2Run(models.CloudScanRunQueued, nil, 0), false, PipelineQueued},
		{"collecting", models.CloudConnectorActive, s2Run(models.CloudScanRunRunning, nil, 0), true, PipelineCollecting},
		{"run failed", models.CloudConnectorActive, s2Run(models.CloudScanRunFailed, nil, 0), true, PipelineFailed},
		{"run abandoned", models.CloudConnectorActive, s2Run(models.CloudScanRunAbandoned, nil, 0), false, PipelineFailed},
		{"projection queued", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str(models.ProjectionQueued), 0), false, PipelineProjecting},
		{"projection running", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str(models.ProjectionRunning), 1), true, PipelineProjecting},
		// D-59: failed below the ceiling is retried and still holds the barrier.
		{"projection failed, retrying", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str(models.ProjectionFailed), belowCeiling), false, PipelineProjecting},
		{"projection failed at the ceiling", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str(models.ProjectionFailed), repositories.MaxProjectionAttempts), true, PipelineFailed},
		{"projection abandoned", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str(models.ProjectionAbandoned), 1), true, PipelineFailed},
		{"projected", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str(models.ProjectionComplete), 1), true, PipelinePublished},
		// Published with no job: scanned while the switch was off. The graph
		// holds an earlier run of the account, or nothing of it yet.
		{"published, no job, graph holds the account", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, nil, 0), true, PipelinePublished},
		{"published, no job, first publication pending", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, nil, 0), false, PipelineFirstPublication},
		// A status this build does not know is never reported as fine.
		{"unknown run status", models.CloudConnectorActive, s2Run("paused", nil, 0), true, PipelineFailed},
		{"unknown job status", models.CloudConnectorActive,
			s2Run(models.CloudScanRunPublished, s2Str("paused"), 1), true, PipelineFailed},
	} {
		if got := accountState(c.connector, c.run, c.published); got != c.want {
			t.Errorf("%s: state = %q, want %q", c.name, got, c.want)
		}
	}
}

// D-59 on the projection object itself: retrying only while failed below the
// ceiling, never for a queued, running, complete or abandoned job.
func TestS2ProjectionRetrying(t *testing.T) {
	for _, c := range []struct {
		job      string
		attempts int
		want     bool
	}{
		{models.ProjectionFailed, 1, true},
		{models.ProjectionFailed, repositories.MaxProjectionAttempts - 1, true},
		{models.ProjectionFailed, repositories.MaxProjectionAttempts, false},
		{models.ProjectionQueued, 0, false},
		{models.ProjectionRunning, 1, false},
		{models.ProjectionComplete, 1, false},
		{models.ProjectionAbandoned, 1, false},
	} {
		v := projectionView(s2Run(models.CloudScanRunPublished, s2Str(c.job), c.attempts))
		if v["retrying"] != c.want || v["status"] != c.job || v["attempts"] != c.attempts {
			t.Errorf("%s at %d attempts: projection = %v, want retrying=%v", c.job, c.attempts, v, c.want)
		}
	}
	if v := projectionView(s2Run(models.CloudScanRunQueued, nil, 0)); v != nil {
		t.Errorf("a run with no job has projection %v, want null", v)
	}
}

// D-58, over every coverage state models defines.
func TestS2PreventsMapping(t *testing.T) {
	for _, c := range []struct {
		surface, state string
		want           any
	}{
		{models.SurfaceIAMUsers, models.CloudCoverageReached, nil},
		{models.SurfaceIAMUsers, models.CloudCoverageDenied, PreventsSurfaceDenied},
		{models.SurfacePolicyDocuments, models.CloudCoveragePartial, PreventsSurfacePartial},
		{models.SurfaceIAMUsers, models.CloudCoverageThrottled, PreventsSurfaceStale},
		// §2.14.13: an unselected region's earlier results are kept and marked
		// stale -- nothing is claimed about it now.
		{"compute:eu-west-1", models.CloudCoverageNotSelected, PreventsSurfaceStale},
		{models.SurfaceIAMUsers, models.CloudCoverageUnknown, PreventsSurfaceStale},
		{models.SurfaceIAMUsers, models.CloudCoverageStale, PreventsSurfaceStale},
		{models.SurfaceIAMUsers, models.CloudCoverageConstrained, PreventsSurfaceStale},
		{SurfaceOrganizations, models.CloudCoverageUnsupported, PreventsOrganizations},
		{"bedrock-agentcore:ap-south-2", models.CloudCoverageUnsupported, nil},
		{"activity", models.CloudCoverageNotConfigured, nil},
		// A state this build does not know: a read we meant to make is not
		// known to have completed.
		{models.SurfaceIAMUsers, "brand_new_state", PreventsSurfaceStale},
	} {
		if got := Prevents(c.surface, c.state); got != c.want {
			t.Errorf("Prevents(%s, %s) = %v, want %v", c.surface, c.state, got, c.want)
		}
	}
}
