package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Phase 2 connector routes (SPEC-iga-phase2-graph.md §5.3 "Integration, scan
// and pipeline"; T2.1, T2.2):
//
//	GET   /authsec/discovery/aws/connectors/:id/regions    discovery:read
//	PATCH /authsec/discovery/aws/connectors/:id            discovery:admin
//	GET   /authsec/discovery/aws/connectors/:id/scan-runs  discovery:read
//
// These NEW routes answer errors in the §5.2 envelope, {"error": {"code",
// "message", ...}}, so a console can branch on a code rather than parse prose.
// The existing discovery routes keep their {"error": "<string>"} bodies: their
// consumers read them today.

// awsP2Error writes the structured error body.
func awsP2Error(c *gin.Context, status int, code, msg string, extra gin.H) {
	inner := gin.H{"code": code, "message": msg}
	for k, v := range extra {
		inner[k] = v
	}
	c.AbortWithStatusJSON(status, gin.H{"error": inner})
}

// p2Target resolves the token's workspace and the route's connector id. A
// malformed id is 404 not_found like an absent one (§5.2: no hint whether it
// exists elsewhere).
func (ctl *CloudAWSController) p2Target(c *gin.Context) (uuid.UUID, uuid.UUID, string, bool) {
	ws, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		awsP2Error(c, http.StatusUnauthorized, "unauthenticated", err.Error(), nil)
		return uuid.Nil, uuid.Nil, "", false
	}
	// A *igaread.Error of its own: assigned to the error above, a nil pointer
	// would be a non-nil interface.
	id, rerr := igaread.RouteID(igaread.RefConnector, c.Param("id"))
	if rerr != nil {
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)
		return uuid.Nil, uuid.Nil, "", false
	}
	return ws, id, actor, true
}

func (ctl *CloudAWSController) p2Service(c *gin.Context) (*services.AWSOnboardingService, bool) {
	svc, err := ctl.service()
	if err != nil {
		awsP2Error(c, http.StatusServiceUnavailable, "service_unavailable", err.Error(), nil)
		return nil, false
	}
	return svc, true
}

/* --------------------------------- regions -------------------------------- */

// regionView is one region of GET .../regions (D-54).
type regionView struct {
	Name        string  `json:"name"`
	OptInStatus *string `json:"opt_in_status"`
	Enabled     bool    `json:"enabled"`
	Selected    bool    `json:"selected"`
}

// GetConnectorRegions handles GET /authsec/discovery/aws/connectors/:id/regions:
// the regions enabled in the account -- ec2:DescribeRegions through the
// discovery role, live -- with which of them this connector scans (§5.3, D-54).
//
// A region the connector still selects but the account no longer enables (an
// opt-out after the selection) is listed with enabled: false and
// opt_in_status: null -- AWS did not report it, so its status is not known --
// so the console can show why its scans find nothing rather than hide it.
func (ctl *CloudAWSController) GetConnectorRegions(c *gin.Context) {
	ws, id, _, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	svc, ok := ctl.p2Service(c)
	if !ok {
		return
	}
	enabled, connector, err := svc.EnabledRegions(c.Request.Context(), ws, id)
	if err != nil {
		ctl.regionsError(c, err, connector)
		return
	}

	selected := connector.AWSAttrs().Regions
	isSelected := make(map[string]bool, len(selected))
	for _, r := range selected {
		isSelected[r] = true
	}
	out := make([]regionView, 0, len(enabled)+len(selected))
	listed := map[string]bool{}
	for _, r := range enabled {
		status := r.OptInStatus
		v := regionView{Name: r.Name, Enabled: true, Selected: isSelected[r.Name]}
		if status != "" {
			v.OptInStatus = &status
		}
		out = append(out, v)
		listed[r.Name] = true
	}
	for _, r := range selected {
		if !listed[r] {
			out = append(out, regionView{Name: r, Enabled: false, Selected: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	c.JSON(http.StatusOK, gin.H{
		"data": out,
		"meta": gin.H{
			"as_of":       time.Now().UTC(),
			"integration": igaread.R(igaread.RefConnector, connector.ID),
			"source":      "ec2:DescribeRegions",
			"note": "enabled is what AWS reported for this account just now; selected is " +
				"what this connector scans. A change applies from the next scan to start.",
		},
	})
}

// updateConnectorBody is PATCH .../connectors/:id. Only the region selection
// is changeable here (§5.3).
type updateConnectorBody struct {
	Regions *[]string `json:"regions"`
}

// UpdateConnector handles PATCH /authsec/discovery/aws/connectors/:id with
// {"regions": [...]} (§5.3, D-54).
//
// The selection is validated against the regions ENABLED in the account, read
// live; 422 invalid_region names every offender. It applies from the next scan
// to START: a run already collecting keeps the regions it was claimed with
// (the worker pins the connector, AWSOnboardingService.ForRun), and a queued
// run -- not yet claimed -- will use the new ones.
//
// An unknown field is refused (400), never ignored: a PATCH that silently drops
// part of its body tells the caller it changed something it did not.
func (ctl *CloudAWSController) UpdateConnector(c *gin.Context) {
	ws, id, actor, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	var body updateConnectorBody
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", "could not read the request body", nil)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"invalid request body: "+err.Error(), gin.H{"parameter": "body"})
		return
	}
	if body.Regions == nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"regions is required", gin.H{"parameter": "regions"})
		return
	}

	svc, ok := ctl.p2Service(c)
	if !ok {
		return
	}
	updated, before, err := svc.UpdateRegions(c.Request.Context(), ws, id, *body.Regions)
	if err != nil {
		ctl.regionsError(c, err, nil)
		return
	}

	after := updated.AWSAttrs().Regions
	auditAdminMutation(c, ws.String(), "update_regions", "cloud_connector", id.String(),
		http.StatusOK, gin.H{"regions": before}, gin.H{"regions": after, "actor": actor})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "region selection updated",
		"data":    updated,
		"meta": gin.H{
			"as_of":            time.Now().UTC(),
			"previous_regions": before,
			"applies": "from the next scan to start; a scan already running keeps the " +
				"regions it was started with",
		},
	})
}

// regionsError maps a region-listing or region-change failure to a status that
// says whose problem it is -- and, for an AWS refusal, the call and the code
// AWS returned, never a guess at the missing permission (§2.14.13).
//
// A DENIED ec2:DescribeRegions is NOT the onboarding mapping's 400
// "customer_account: the role could not be assumed": the role WAS assumed, and
// that remedy (check the trust policy and the ExternalId) sends the customer
// to the wrong place. It is 502 aws_access_denied, naming the call.
func (ctl *CloudAWSController) regionsError(c *gin.Context, err error, connector *models.CloudConnector) {
	if c.Request.Context().Err() != nil {
		// The client went away; the response is usually undeliverable (see
		// CreateConnector for why this is 499 and not a 4xx).
		c.AbortWithStatusJSON(499, gin.H{"error": gin.H{"code": "aborted",
			"message": "request aborted by the client before AWS answered"}})
		return
	}
	api, code := awsdiscovery.FailedCall(err)
	awsFacts := gin.H{"api": nullIfEmpty(api), "error_code": nullIfEmpty(code)}

	var invalid *services.InvalidRegionsError
	var selection *services.RegionSelectionError
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)

	case errors.Is(err, services.ErrAWSConnectorRevoked):
		awsP2Error(c, http.StatusConflict, "connector_revoked", err.Error(), nil)

	case errors.As(err, &invalid):
		awsP2Error(c, http.StatusUnprocessableEntity, "invalid_region",
			err.Error(), gin.H{"regions": invalid.Regions, "reason": invalid.Reason})

	case errors.As(err, &selection):
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", err.Error(),
			gin.H{"parameter": "regions"})

	case errors.Is(err, awsdiscovery.ErrRegionsDenied):
		extra := gin.H{"fault": "customer_account"}
		for k, v := range awsFacts {
			extra[k] = v
		}
		if connector != nil {
			// Facts, not a diagnosis: the stack version recorded at onboarding
			// and the one that grants ec2:DescribeRegions explicitly. An SCP or
			// a boundary produces the same refusal.
			extra["template_version"] = gin.H{
				"recorded": nullIfEmpty(connector.AWSAttrs().TemplateVersion),
				"current":  awsdiscovery.TemplateVersion,
			}
		}
		awsP2Error(c, http.StatusBadGateway, "aws_access_denied",
			"AWS refused ec2:DescribeRegions to the discovery role, so the account's "+
				"enabled regions could not be read: "+err.Error(), extra)

	case errors.Is(err, awsdiscovery.ErrNotAssumable):
		extra := gin.H{"fault": "customer_account"}
		for k, v := range awsFacts {
			extra[k] = v
		}
		awsP2Error(c, http.StatusBadGateway, "role_not_assumable",
			"the connection's role could not be assumed; verify the connection: "+err.Error(), extra)

	case errors.Is(err, awsdiscovery.ErrThrottled):
		awsP2Error(c, http.StatusTooManyRequests, "aws_throttled",
			"AWS throttled the request after retries; try again shortly", awsFacts)

	case errors.Is(err, services.ErrAWSProbeTimeout):
		awsP2Error(c, http.StatusGatewayTimeout, "aws_timeout", err.Error(), gin.H{"fault": "aws"})

	case errors.Is(err, awsdiscovery.ErrNoBaseCredentials):
		awsP2Error(c, http.StatusInternalServerError, "authsec_misconfigured", err.Error(),
			gin.H{"fault": "authsec"})

	case errors.Is(err, awsdiscovery.ErrRegionsUnavailable):
		awsP2Error(c, http.StatusBadGateway, "aws_error", err.Error(), awsFacts)

	default:
		// Everything else is AuthSec-side state (the secrets store, a connector
		// with no role recorded): not the caller's input, so never a 400.
		log.Printf("[discovery] regions for %s: %v", c.Param("id"), err)
		awsP2Error(c, http.StatusInternalServerError, "internal", err.Error(), nil)
	}
}

/* ------------------------------ scan-run history --------------------------- */

// scanRunWithProjection is GET .../scan-runs/:id's data: the run, as before,
// plus projection (§5.3 "gains projection: { status, rev }").
type scanRunWithProjection struct {
	models.CloudScanRun
	Projection gin.H `json:"projection"`
}

// projectionView renders a run's projection: null when it has no job; else the
// job's status and the revision it published (null until then, and for good
// when abandoned), with D-59's retrying, attempts and last_error.
func projectionView(p *repositories.RunProjection) gin.H {
	if p == nil {
		return nil
	}
	var rev any
	if p.Rev != nil {
		rev = *p.Rev
	}
	return gin.H{
		"status":     p.JobStatus,
		"rev":        rev,
		"attempts":   p.Attempts,
		"retrying":   p.JobStatus == models.ProjectionFailed && p.Attempts < repositories.MaxProjectionAttempts,
		"last_error": nullIfEmpty(p.LastError),
	}
}

// scanRunHistoryItem is one run of GET .../scan-runs.
//
// Times: queued_at is requested_at, when the run last (re)entered the queue --
// a refused claim moves it (T1.3), and no column keeps the original enqueue
// time (D-55). started_at is when collection began (a refused claim clears it,
// D-55). finished_at is published_at for a published run, and updated_at for a
// failed or abandoned one: a terminal run is never updated again, and 020 has
// no finished_at.
func scanRunHistoryItem(rec repositories.ScanRunRecord) gin.H {
	run := rec.Run
	var finished any
	switch run.Status {
	case models.CloudScanRunPublished:
		finished = igaread.TS(run.PublishedAt)
	case models.CloudScanRunFailed, models.CloudScanRunAbandoned:
		finished = igaread.T(run.UpdatedAt)
	}
	return gin.H{
		"ref":          igaread.R(igaread.RefScanRun, run.ID),
		"id":           run.ID,
		"integration":  igaread.R(igaread.RefConnector, run.ConnectorID),
		"status":       run.Status,
		"trigger":      run.Trigger,
		"attempts":     run.Attempts,
		"generation":   run.Generation,
		"queued_at":    igaread.T(run.RequestedAt),
		"started_at":   igaread.TS(run.StartedAt),
		"published_at": igaread.TS(run.PublishedAt),
		"finished_at":  finished,
		"last_error":   nullIfEmpty(run.LastError),
		"coverage":     coverageSummary(run),
		"projection":   projectionView(rec.Projection),
	}
}

// coverageSummary is a run's coverage in brief: the overall status and the
// surfaces it meant to read and did not, each with its state and -- when AWS
// said -- the call and the code. null for a run that published no coverage
// (queued, running, failed or abandoned: coverage is stamped at publication).
func coverageSummary(run models.CloudScanRun) gin.H {
	cov := models.DecodeScanCoverage(run.Coverage)
	if cov.Status == "" && len(cov.Surfaces) == 0 {
		return nil
	}
	reached := 0
	for _, s := range cov.Surfaces {
		if s.State == models.CloudCoverageReached {
			reached++
		}
	}
	incomplete := []gin.H{}
	for name, s := range cov.IntendedIncomplete() {
		incomplete = append(incomplete, gin.H{
			"surface":    name,
			"state":      s.State,
			"api":        nullIfEmpty(s.API),
			"error_code": nullIfEmpty(s.ErrorCode),
		})
	}
	sort.Slice(incomplete, func(i, j int) bool {
		return incomplete[i]["surface"].(string) < incomplete[j]["surface"].(string)
	})
	return gin.H{
		"status":     cov.Status,
		"surfaces":   len(cov.Surfaces),
		"reached":    reached,
		"incomplete": incomplete,
	}
}

// scanRunCursorKey is the history cursor's sort key.
type scanRunCursorKey struct {
	RequestedAt time.Time `json:"at"`
}

func (ctl *CloudAWSController) cursorSigner() *igaread.Reader {
	ctl.cursorsOnce.Do(func() { ctl.cursors = igaread.NewReader(ctl.db, cursorKeyFromEnv()) })
	return ctl.cursors
}

// ListConnectorScanRuns handles GET /authsec/discovery/aws/connectors/:id/scan-runs:
// the connector's run history, newest first, cursor-paged (§5.3) -- published,
// failed and abandoned runs alike, each with its times, coverage summary,
// projection job status and publication rev.
//
// Paging follows §5.2: limit 1-200, default 100; keyset on (requested_at, id)
// so a page boundary never skips or repeats a run. The cursor is HMAC-signed
// (IGA_CURSOR_SECRET) and bound to the workspace, THIS connector (in the route,
// D-62), the filter set and the sort: presented anywhere else it is 400
// cursor_invalid. It carries no revision -- run history is collection state,
// not a read of the graph.
func (ctl *CloudAWSController) ListConnectorScanRuns(c *gin.Context) {
	ws, id, _, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	connector, err := repositories.NewCloudConnectorRepository(ctl.db).Get(ws, id)
	if err != nil || connector.Provider != models.CloudProviderAWS {
		if err != nil && !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
			log.Printf("[discovery] scan-runs for %s: %v", id, err)
			awsP2Error(c, http.StatusInternalServerError, "internal", "could not read the connector", nil)
			return
		}
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)
		return
	}

	vals := c.Request.URL.Query()
	limit := igaread.DefaultLimit
	if l := vals.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > igaread.MaxLimit {
			awsP2Error(c, http.StatusBadRequest, "invalid_parameter", "limit must be 1-200",
				gin.H{"parameter": "limit"})
			return
		}
		limit = n
	}

	const sortKey = "-requested_at"
	want := igaread.CursorContext{
		WS:     ws,
		Route:  "aws/connectors/" + id.String() + "/scan-runs",
		Filter: igaread.FilterHash(vals),
		Sort:   sortKey,
	}
	var after *repositories.ScanRunPosition
	if token := vals.Get("cursor"); token != "" {
		cur, cerr := ctl.cursorSigner().OpenCursor(token, want)
		if cerr != nil {
			awsP2Error(c, cerr.Status, cerr.Code, cerr.Message, nil)
			return
		}
		var key scanRunCursorKey
		if err := json.Unmarshal(cur.Key, &key); err != nil || key.RequestedAt.IsZero() {
			awsP2Error(c, http.StatusBadRequest, "cursor_invalid", "Malformed cursor.", nil)
			return
		}
		after = &repositories.ScanRunPosition{RequestedAt: key.RequestedAt, ID: cur.ID}
	}

	// One more than the page, to know whether another page exists without a
	// count.
	recs, err := repositories.NewCloudScanRunRepository(ctl.db).History(ws, id, after, limit+1)
	if err != nil {
		log.Printf("[discovery] scan-runs for %s: %v", id, err)
		awsP2Error(c, http.StatusInternalServerError, "internal", "could not read the run history", nil)
		return
	}
	var next any
	if len(recs) > limit {
		recs = recs[:limit]
		last := recs[len(recs)-1].Run
		key, _ := json.Marshal(scanRunCursorKey{RequestedAt: last.RequestedAt})
		next = ctl.cursorSigner().SignCursor(igaread.Cursor{
			WS: ws, Route: want.Route, Filter: want.Filter, Sort: want.Sort,
			Key: key, ID: last.ID,
		})
	}
	items := make([]gin.H, 0, len(recs))
	for _, rec := range recs {
		items = append(items, scanRunHistoryItem(rec))
	}
	c.JSON(http.StatusOK, gin.H{
		"data": items,
		"meta": gin.H{
			"as_of":       time.Now().UTC(),
			"integration": igaread.R(igaread.RefConnector, id),
			"sort":        sortKey,
			"limit":       limit,
			"next_cursor": next,
		},
	})
}
