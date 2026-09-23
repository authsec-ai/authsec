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
// and pipeline"; T2.1, T2.2; D-54, D-90, D-91):
//
//	GET   /authsec/discovery/aws/connectors/:id/regions    discovery:read
//	PATCH /authsec/discovery/aws/connectors/:id            discovery:admin
//	GET   /authsec/discovery/aws/connectors/:id/scan-runs  discovery:read
//
// Success bodies are the discovery routes' own envelope -- {"success": true,
// "data", "meta"} -- and are not revision-bound: they describe the connection
// and its collection, not a graph revision (D-91).
//
// ERRORS on these NEW routes are the §5.2 envelope, {"error": {"code",
// "message", ...}}, so a console can branch on a code rather than parse prose.
// The existing discovery routes keep their {"error": "<string>"} bodies: their
// consumers read them today. The codes used here:
//
//	400 invalid_parameter   a malformed body, an unknown field, a bad limit,
//	                        a selection over the region cap
//	400 cursor_invalid      a history cursor from another connector,
//	                        workspace or sort, or one that fails its signature
//	401 unauthenticated     no workspace in the token
//	404 not_found           no such AWS connector in this workspace
//	409 connector_revoked   the connection was revoked (its ExternalId purged)
//	422 invalid_region      the selection names regions that are malformed or
//	                        not enabled in the account (regions: [...]), or
//	                        names none at all (regions: [])
//	422 regions_unavailable the enabled regions could not be read from AWS,
//	                        so a selection cannot be validated (api,
//	                        error_code: what AWS said, never a guessed cause)
//	500 authsec_misconfigured / internal   AuthSec's side, never the caller's
//	503 service_unavailable the secrets store is not configured

// awsP2Error writes the structured error body.
func awsP2Error(c *gin.Context, status int, code, msg string, extra gin.H) {
	inner := gin.H{"code": code, "message": msg}
	for k, v := range extra {
		inner[k] = v
	}
	c.AbortWithStatusJSON(status, gin.H{"error": inner})
}

// p2Target resolves the token's workspace and the route's connector id. A
// malformed id, or another type's reference, is 404 not_found like an absent
// one (§5.2, D-5: no hint whether it exists elsewhere).
func (ctl *CloudAWSController) p2Target(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	ws, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		awsP2Error(c, http.StatusUnauthorized, "unauthenticated", err.Error(), nil)
		return uuid.Nil, uuid.Nil, false
	}
	id, rerr := igaread.RouteID(igaread.RefConnector, c.Param("id"))
	if rerr != nil {
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)
		return uuid.Nil, uuid.Nil, false
	}
	return ws, id, true
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

// regionView is one region of GET .../regions (D-54): {name, opt_in_status,
// enabled, selected}. enabled is null -- not known -- when AWS could not be
// asked (D-90); opt_in_status is null whenever AWS did not report one.
type regionView struct {
	Name        string  `json:"name"`
	OptInStatus *string `json:"opt_in_status"`
	Enabled     *bool   `json:"enabled"`
	Selected    bool    `json:"selected"`
}

func boolPtr(b bool) *bool { return &b }

// GetConnectorRegions handles GET /authsec/discovery/aws/connectors/:id/regions:
// the regions enabled in the account -- ec2:DescribeRegions through the
// discovery role, live -- with which of them this connector scans (§5.3,
// D-54).
//
// A region the connector still selects but the account no longer enables (an
// opt-out after the selection) is listed with enabled: false and
// opt_in_status: null -- AWS did not report it, so its status is not known --
// so the console can show why its scans find nothing rather than hide it.
//
// WHEN AWS CANNOT BE ASKED (D-90) the answer is still 200: the connector's
// selected regions, each enabled: null, and meta.error naming the failed call
// and the code AWS returned -- facts, never a guessed missing permission
// (§2.14.13) -- beside meta.template_outdated, the recorded stack version
// against this build's. The selection is AuthSec's own state and is shown
// whatever AWS says; only "which regions are enabled" is unknown. A refusal
// of ec2:DescribeRegions is NOT the onboarding mapping's 400 "the role could
// not be assumed; check the trust policy and the ExternalId": the role WAS
// assumed, and that remedy sends the customer to the wrong place.
func (ctl *CloudAWSController) GetConnectorRegions(c *gin.Context) {
	ws, id, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	svc, ok := ctl.p2Service(c)
	if !ok {
		return
	}
	enabled, connector, err := svc.EnabledRegions(c.Request.Context(), ws, id)
	var unavailable *services.RegionsUnavailableError
	if err != nil && (!errors.As(err, &unavailable) || connector == nil || c.Request.Context().Err() != nil) {
		ctl.regionsError(c, err)
		return
	}

	selected := append([]string(nil), connector.AWSAttrs().Regions...)
	sort.Strings(selected)
	out := make([]regionView, 0, len(enabled)+len(selected))
	var failure any
	if unavailable != nil {
		for _, r := range selected {
			out = append(out, regionView{Name: r, Selected: true})
		}
		failure = regionsFailure(unavailable)
	} else {
		isSelected := make(map[string]bool, len(selected))
		for _, r := range selected {
			isSelected[r] = true
		}
		listed := map[string]bool{}
		for _, r := range enabled {
			v := regionView{Name: r.Name, Enabled: boolPtr(true), Selected: isSelected[r.Name]}
			if r.OptInStatus != "" {
				status := r.OptInStatus
				v.OptInStatus = &status
			}
			out = append(out, v)
			listed[r.Name] = true
		}
		for _, r := range selected {
			if !listed[r] {
				out = append(out, regionView{Name: r, Enabled: boolPtr(false), Selected: true})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	}

	recorded := connector.AWSAttrs().TemplateVersion
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    out,
		"meta": gin.H{
			"as_of":       time.Now().UTC(),
			"integration": igaread.R(igaread.RefConnector, connector.ID),
			"source":      "ec2:DescribeRegions",
			"error":       failure,
			"template":    templateFacts(recorded),
			// D-90 names it on its own; the same fact as template.outdated.
			"template_outdated": awsdiscovery.TemplateOutdated(recorded),
			"note": "enabled is what AWS reported for this account just now (null when AWS " +
				"could not be asked; see error); selected is what this connector scans. A " +
				"change applies from the next scan to start.",
		},
	})
}

// templateFacts states the stack version recorded when the account was
// onboarded and the one this build ships (D-72). A fact, never the cause of a
// denial: an SCP or a permissions boundary refuses the same call.
func templateFacts(recorded string) gin.H {
	return gin.H{
		"deployed": nullIfEmpty(recorded),
		"current":  awsdiscovery.TemplateVersion,
		"outdated": awsdiscovery.TemplateOutdated(recorded),
	}
}

// regionsFailure is what AWS said when the enabled regions could not be read:
// our classification (code), the call and the AWS error code as the SDK
// reported them, AWS's own message, and whose side the failure is on. The call
// is ec2:DescribeRegions -- the call this route makes -- unless the SDK names
// another underneath it (a refused sts:AssumeRole arrives wrapped in the
// DescribeRegions operation, because the credential provider assumes lazily).
func regionsFailure(err error) gin.H {
	api, awsCode := awsdiscovery.FailedCall(err)
	code, fault := "aws_error", "aws"
	notAssumable := errors.Is(err, awsdiscovery.ErrNotAssumable)
	switch {
	case errors.Is(err, awsdiscovery.ErrRegionsDenied):
		// Refused in the customer's account -- by a grant, an SCP or a
		// boundary; the response does not say which, so neither do we.
		code, fault = "aws_access_denied", "customer_account"
	case notAssumable:
		code, fault = "role_not_assumable", "customer_account"
	case errors.Is(err, awsdiscovery.ErrThrottled):
		code = "aws_throttled"
	case errors.Is(err, services.ErrAWSProbeTimeout):
		code = "aws_timeout"
	}
	if api == "" && !notAssumable {
		api = "ec2:DescribeRegions"
	}
	return gin.H{
		"code":       code,
		"api":        nullIfEmpty(api),
		"error_code": nullIfEmpty(awsCode),
		"message":    err.Error(),
		"fault":      fault,
	}
}

// updateConnectorBody is PATCH .../connectors/:id. Only the region selection
// is changeable here (§5.3, D-90).
type updateConnectorBody struct {
	Regions *[]string `json:"regions"`
}

// UpdateConnector handles PATCH /authsec/discovery/aws/connectors/:id with
// {"regions": [...]} (§5.3, D-54, D-90).
//
// The selection is validated against the regions ENABLED in the account, read
// live; 422 invalid_region names every offender, and an empty selection is 422
// invalid_region with none to name. When the enabled list cannot be read the
// change is refused, 422 regions_unavailable: a selection is never written
// unvalidated. Stored de-duplicated and sorted.
//
// It applies from the next scan to START: a run already collecting keeps the
// regions it was claimed with (the worker pins the connector,
// AWSOnboardingService.ForRun), and a queued run -- not yet claimed -- will
// use the new ones.
//
// Only regions is accepted: an unknown field is 400, never ignored -- a PATCH
// that silently drops part of its body tells the caller it changed something
// it did not.
func (ctl *CloudAWSController) UpdateConnector(c *gin.Context) {
	ws, id, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	var body updateConnectorBody
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", "could not read the request body",
			gin.H{"parameter": "body"})
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"invalid request body: "+err.Error(), gin.H{"parameter": "body"})
		return
	}
	if dec.More() {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"the request body must be one JSON object", gin.H{"parameter": "body"})
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
		ctl.regionsError(c, err)
		return
	}

	after := updated.AWSAttrs().Regions
	auditAdminMutation(c, ws.String(), "update_regions", "cloud_connector", id.String(),
		http.StatusOK, gin.H{"regions": before}, gin.H{"regions": after})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "region selection updated",
		"data":    updated,
		"meta": gin.H{
			"as_of":            time.Now().UTC(),
			"regions":          after,
			"previous_regions": before,
			"applies": "from the next scan to start; a scan already running keeps the " +
				"regions it was started with",
		},
	})
}

// regionsError maps a region-listing or region-change failure to a status that
// says whose problem it is.
func (ctl *CloudAWSController) regionsError(c *gin.Context, err error) {
	if c.Request.Context().Err() != nil {
		// The client went away; the response is usually undeliverable (see
		// CreateConnector for why this is 499 and not a 4xx).
		awsP2Error(c, 499, "aborted", "request aborted by the client before AWS answered", nil)
		return
	}

	var invalid *services.InvalidRegionsError
	var selection *services.RegionSelectionError
	var unavailable *services.RegionsUnavailableError
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)

	case errors.Is(err, services.ErrAWSConnectorRevoked):
		awsP2Error(c, http.StatusConflict, "connector_revoked", err.Error(), nil)

	case errors.As(err, &invalid):
		regions := invalid.Regions
		if regions == nil {
			regions = []string{}
		}
		awsP2Error(c, http.StatusUnprocessableEntity, "invalid_region",
			err.Error(), gin.H{"regions": regions, "reason": invalid.Reason})

	case errors.As(err, &selection):
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", err.Error(),
			gin.H{"parameter": "regions"})

	case errors.As(err, &unavailable):
		// D-90: the enabled list could not be read, so the selection cannot be
		// validated -- and is not written. What AWS said travels with it.
		f := regionsFailure(unavailable)
		awsP2Error(c, http.StatusUnprocessableEntity, "regions_unavailable",
			"the account's enabled regions could not be read, so the region selection was not "+
				"changed: "+unavailable.Error(),
			gin.H{"failure": f["code"], "api": f["api"], "error_code": f["error_code"], "fault": f["fault"]})

	case errors.Is(err, awsdiscovery.ErrNoBaseCredentials):
		log.Printf("[discovery] regions for %s: %v", c.Param("id"), err)
		awsP2Error(c, http.StatusInternalServerError, "authsec_misconfigured",
			"this AuthSec deployment has no AWS identity to assume the customer role with",
			gin.H{"fault": "authsec"})

	default:
		// Everything else is AuthSec-side state (the secrets store, a
		// connector with no role recorded): not the caller's input, so never a
		// 400. Logged, not sent: a secrets-store error can name where a
		// workspace's credentials live, which the connector's own JSON
		// deliberately omits (auth_ref).
		log.Printf("[discovery] regions for %s: %v", c.Param("id"), err)
		awsP2Error(c, http.StatusInternalServerError, "internal",
			"AuthSec could not prepare this connection's AWS session", gin.H{"fault": "authsec"})
	}
}

/* ------------------------------ scan-run history --------------------------- */

// scanRunWithProjection is GET .../scan-runs/:id's data: the run, as before,
// plus projection (§5.3 "gains projection: { status, rev }").
type scanRunWithProjection struct {
	models.CloudScanRun
	Projection gin.H `json:"projection"`
}

// projectionView renders a run's projection (D-91): null when it has no job;
// else the job's status, the revision it published (null until then, and for
// good when abandoned), attempts and last_error -- plus retrying, D-59's
// "failed below its attempt ceiling, and will be retried".
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
// Times (D-55, D-91): queued_at is requested_at -- when the run LAST
// (re)entered the queue: a refused claim moves it (T1.3), and no column keeps
// the original enqueue time. started_at is when collection began (a refused
// claim clears it). finished_at is published_at for a published run, and for
// a failed or abandoned one its updated_at -- "last updated": 020 has no
// finished_at, and a terminal run is not updated again by the scan path.
// updated_at is also given as itself.
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
		"updated_at":   igaread.T(run.UpdatedAt),
		"last_error":   nullIfEmpty(run.LastError),
		"coverage":     coverageSummary(run),
		"projection":   projectionView(rec.Projection),
	}
}

// coverageSummary is a run's coverage in brief (D-91): the overall status, how
// many surfaces ended in each state, and every surface that was NOT reached,
// each with its state and -- when AWS said -- the call and the code. null for
// a run that published no coverage (queued, running, failed or abandoned:
// coverage is stamped at publication).
func coverageSummary(run models.CloudScanRun) gin.H {
	cov := models.DecodeScanCoverage(run.Coverage)
	if cov.Status == "" && len(cov.Surfaces) == 0 {
		return nil
	}
	counts := map[string]int{}
	notReached := []gin.H{}
	for name, s := range cov.Surfaces {
		counts[s.State]++
		if s.State == models.CloudCoverageReached {
			continue
		}
		notReached = append(notReached, gin.H{
			"surface":    name,
			"state":      s.State,
			"api":        nullIfEmpty(s.API),
			"error_code": nullIfEmpty(s.ErrorCode),
		})
	}
	sort.Slice(notReached, func(i, j int) bool {
		return notReached[i]["surface"].(string) < notReached[j]["surface"].(string)
	})
	return gin.H{
		"status":      cov.Status,
		"counts":      counts,
		"not_reached": notReached,
	}
}

// Scan-run history paging (D-91): 20 per page by default, 1-100.
const (
	scanRunHistoryDefaultLimit = 20
	scanRunHistoryMaxLimit     = 100
)

// scanRunCursorKey is the history cursor's sort key: the last row's
// requested_at exactly as the database holds it (microseconds), never a
// display rendering, or the keyset would skip or repeat rows.
type scanRunCursorKey struct {
	RequestedAt time.Time `json:"at"`
}

func (ctl *CloudAWSController) cursorSigner() *igaread.Reader {
	ctl.cursorsOnce.Do(func() { ctl.cursors = igaread.NewReader(ctl.db, cursorKeyFromEnv()) })
	return ctl.cursors
}

// ListConnectorScanRuns handles GET /authsec/discovery/aws/connectors/:id/scan-runs:
// the connector's run history, newest first, cursor-paged (§5.3, D-91) --
// published, failed and abandoned runs alike, each with its times, coverage
// summary, projection job status and publication rev.
//
// Paging: limit 1-100, default 20; keyset on (requested_at DESC, id DESC), so
// a page boundary never skips or repeats a terminal run. The cursor is
// HMAC-signed (IGA_CURSOR_SECRET) and bound to the workspace, THIS connector
// (in the route, D-62) and the sort: presented anywhere else it is 400
// cursor_invalid. It carries no revision -- run history is collection state,
// not a read of the graph. cursor and limit are the only parameters; any
// other is 400, never silently ignored.
func (ctl *CloudAWSController) ListConnectorScanRuns(c *gin.Context) {
	ws, id, ok := ctl.p2Target(c)
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
	for k := range vals {
		if k != "cursor" && k != "limit" {
			awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
				"unknown parameter "+strconv.Quote(k)+"; this route takes cursor and limit",
				gin.H{"parameter": k})
			return
		}
	}
	limit := scanRunHistoryDefaultLimit
	if l := vals.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > scanRunHistoryMaxLimit {
			awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
				"limit must be 1-"+strconv.Itoa(scanRunHistoryMaxLimit), gin.H{"parameter": "limit"})
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
		if err := json.Unmarshal(cur.Key, &key); err != nil || key.RequestedAt.IsZero() || cur.ID == uuid.Nil {
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
		"success": true,
		"data":    items,
		"meta": gin.H{
			"as_of":       time.Now().UTC(),
			"integration": igaread.R(igaread.RefConnector, id),
			"sort":        sortKey,
			"limit":       limit,
			"next_cursor": next,
			"note": "queued_at is when the run last entered the queue (a refused claim moves " +
				"it); finished_at is published_at, or for a failed or abandoned run the time it " +
				"was last updated",
		},
	})
}
