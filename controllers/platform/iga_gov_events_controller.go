package platform

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/services"
)

// The §7.8 settings and events routes (T3.20), under the gated
// /api/iga/v1/policy group:
//
//	GET /settings         governance:read     iga_gov_settings (defaults when no row) + notification channels
//	PUT /settings         governance:enforce  mode, windows, ...; switching to enforce needs a reason; audited
//	GET /events           governance:read     iga_gov_event, redacted, newest first, cursor-paged
//	GET /events/export    governance:read     the same filter, oldest first, streamed (format=csv|json)
//	GET /events/kinds     governance:read     the Logs kind filter: categories, their events, "not recorded yet"
//
// DECISION: GET /events/kinds is not in §7.8's table. §9.6 asks Logs to list
// unrecorded categories as "Not recorded yet"; serving the vocabulary keeps
// that list in one place (services/iga_gov_event_vocabulary.go) instead of
// a second copy in the console.

func (ctl *IGAGovPolicyController) eventsService() *services.GovEventsService {
	return services.NewGovEventsService(ctl.db(), ctl.key)
}

func eventFilter(c *gin.Context) (services.GovEventFilter, error) {
	return services.ParseGovEventFilter(c.QueryArray("kind"), c.Query("category"), c.Query("object_kind"), c.Query("object_id"),
		c.Query("actor"), c.Query("actor_kind"), c.Query("from"), c.Query("to"))
}

// ListEvents handles GET /events.
func (ctl *IGAGovPolicyController) ListEvents(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f, err := eventFilter(c)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	limit, err := limitParam(c)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	rows, next, err := ctl.eventsService().List(c.Request.Context(), ws, f, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
}

// ExportEvents handles GET /events/export: every matching event, streamed.
func (ctl *IGAGovPolicyController) ExportEvents(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f, err := eventFilter(c)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	format, err := services.ParseGovExportFormat(c.Query("format"))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	ct := "application/x-ndjson; charset=utf-8"
	if format == services.GovExportCSV {
		ct = "text/csv; charset=utf-8"
	}
	c.Header("Content-Type", ct)
	c.Header("Content-Disposition", `attachment; filename="`+services.GovExportFilename(format, time.Now())+`"`)
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	n, err := ctl.eventsService().Export(c.Request.Context(), ws, f, format, c.Writer, c.Writer.Flush)
	if err != nil {
		// The status is already sent: the export ends short, and the log says why.
		log.Printf("[policy] events export for %s stopped after %d events: %v", ws, n, err)
	}
}

// EventKinds handles GET /events/kinds.
func (ctl *IGAGovPolicyController) EventKinds(c *gin.Context) {
	if _, ok := policyWorkspace(c); !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"categories":   services.GovEventCategories(),
		"events":       services.GovEventVocabulary,
		"object_kinds": services.GovEventObjectKinds(),
	}, "meta": gin.H{}})
}

// GetSettings handles GET /settings.
func (ctl *IGAGovPolicyController) GetSettings(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	v, err := services.NewGovSettingsService(ctl.db()).Get(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v, "meta": gin.H{}})
}

// PutSettings handles PUT /settings.
func (ctl *IGAGovPolicyController) PutSettings(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.policyActor(c, ws)
	if !ok {
		return
	}
	var p services.GovSettingsPatch
	if err := strictJSON(c, &p); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON with known settings fields: "+err.Error(),
			gin.H{"parameter": "body"})
		return
	}
	before, after, err := services.NewGovSettingsService(ctl.db()).Update(c.Request.Context(), ws, actor, p)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "update", "iga_gov_settings", ws.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after, "meta": gin.H{}})
}
