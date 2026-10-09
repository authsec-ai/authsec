package platform

import (
	"errors"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DiscoveryRuleCatalogController exposes the detection patterns a scan matches
// on, and lets a workspace tune them.
//
// Everything served here is DATA. The parsers themselves stay in code and are
// selected by name — see services/iga_rule_catalog_config.go for why.
type DiscoveryRuleCatalogController struct {
	db  *gorm.DB
	svc *services.RuleCatalogService
}

// NewDiscoveryRuleCatalogController constructs the controller.
func NewDiscoveryRuleCatalogController(db *gorm.DB) *DiscoveryRuleCatalogController {
	return &DiscoveryRuleCatalogController{db: db, svc: services.NewRuleCatalogService(db)}
}

// GetRuleCatalog handles GET /authsec/discovery/rule-catalog.
//
// Returns the EFFECTIVE catalogue — built-in rules with the workspace overlay
// already applied — alongside the overlay itself and the vocabulary. A console
// needs all three: what is actually being searched for, what this workspace
// changed, and what it could change.
func (ctl *DiscoveryRuleCatalogController) GetRuleCatalog(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	overlay, err := ctl.svc.Overlay(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	catalog, vocab := services.ApplyOverlay(overlay)

	stale, current, serr := services.CountStaleFindings(ctl.db, workspaceID, catalog.Version)
	staleBlock := gin.H{"unavailable": serr != nil}
	if serr == nil {
		staleBlock = gin.H{
			"findings_from_older_rulesets": stale,
			"findings_from_this_ruleset":   current,
			// Raw file bodies are discarded after parse, so a changed rule
			// cannot be re-applied to stored evidence. Re-deriving means
			// re-reading the repositories.
			"rescan_required": stale > 0,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"version":              catalog.Version,
			"builtin_version":      services.DefaultRuleCatalog().Version,
			"customised":           !overlay.IsEmpty(),
			"rules":                services.DescribeCatalog(catalog, overlay),
			"vocabularies":         vocab,
			"overlay":              overlay,
			"available_extractors": services.ExtractorNames(),
			"staleness":            staleBlock,
		},
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "path globs and vocabularies are configurable; the parsers are not. " +
				"A custom rule points new globs at an existing extractor.",
		},
	})
}

// SetRuleCatalog handles PUT /authsec/discovery/rule-catalog.
//
// The body is an OVERLAY of add/remove deltas, never a full catalogue. That is
// what lets a workspace keep its own additions and still receive patterns
// shipped in later releases.
func (ctl *DiscoveryRuleCatalogController) SetRuleCatalog(c *gin.Context) {
	workspaceID, actor, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var overlay services.RuleCatalogOverlay
	if err := c.ShouldBindJSON(&overlay); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	before, _ := ctl.svc.Overlay(workspaceID)
	saved, err := ctl.svc.Save(workspaceID, overlay, actor)
	if err != nil {
		// Validation messages explain the cost or correctness reason, so they
		// are surfaced verbatim rather than flattened to "invalid input".
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	catalog, vocab := services.ApplyOverlay(saved)

	auditAdminMutation(c, workspaceID.String(), "update", "discovery_rule_catalog",
		workspaceID.String(), http.StatusOK, before, saved)

	c.JSON(http.StatusOK, gin.H{
		"message": "Detection patterns updated",
		"success": true,
		"data": gin.H{
			"version":      catalog.Version,
			"customised":   !saved.IsEmpty(),
			"rules":        services.DescribeCatalog(catalog, saved),
			"vocabularies": vocab,
			"overlay":      saved,
		},
		"meta": gin.H{
			"rescan_required": true,
			"note": "existing findings keep the catalogue version that produced them and are now " +
				"from an older ruleset. Raw file contents are not retained, so the new patterns " +
				"cannot be applied to them — run a scan to re-derive.",
		},
	})
}

// ResetRuleCatalog handles DELETE /authsec/discovery/rule-catalog — back to the
// patterns as shipped. Deleting the overlay IS the reset, which is why a
// workspace can never edit itself into an unrecoverable state.
func (ctl *DiscoveryRuleCatalogController) ResetRuleCatalog(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	before, _ := ctl.svc.Overlay(workspaceID)
	if err := ctl.svc.Reset(workspaceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, workspaceID.String(), "reset", "discovery_rule_catalog",
		workspaceID.String(), http.StatusOK, before, nil)

	base := services.DefaultRuleCatalog()
	c.JSON(http.StatusOK, gin.H{
		"message": "Detection patterns reset to defaults",
		"success": true,
		"data":    gin.H{"version": base.Version, "customised": false},
		"meta":    gin.H{"rescan_required": true},
	})
}

// TestRuleCatalogRequest asks which rule would claim each path.
type TestRuleCatalogRequest struct {
	Paths []string `json:"paths" binding:"required"`
	// Overlay, when present, is tested INSTEAD of the stored one — so a console
	// can show the effect of an edit before saving it.
	Overlay *services.RuleCatalogOverlay `json:"overlay,omitempty"`
}

// TestRuleCatalog handles POST /authsec/discovery/rule-catalog/test.
//
// A dry run against paths, with no GitHub call and no writes. The cost of a
// wrong glob is not a validation error — it is a scan that quietly downloads
// too much, or looks in the wrong place and reports a clean estate. Testing a
// path before saving turns that into a two-second check.
func (ctl *DiscoveryRuleCatalogController) TestRuleCatalog(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req TestRuleCatalogRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Paths) == 0 || len(req.Paths) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "supply between 1 and 200 paths"})
		return
	}

	overlay := services.RuleCatalogOverlay{}
	if req.Overlay != nil {
		// Validate the candidate too: a dry run that accepts a glob the save
		// endpoint would reject teaches the wrong thing.
		if verr := req.Overlay.Validate(); verr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": verr.Error()})
			return
		}
		overlay = *req.Overlay
	} else {
		if overlay, err = ctl.svc.Overlay(workspaceID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	matches := services.TestPaths(overlay, req.Paths)
	matched := 0
	for _, m := range matches {
		if m.Matched {
			matched++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"results":     matches,
			"matched":     matched,
			"not_matched": len(matches) - matched,
			"draft":       req.Overlay != nil,
		},
		"meta": gin.H{
			"note": "a matched path is fetched and parsed during a scan; an unmatched one is never downloaded",
		},
	})
}

// workspaceAndActorFrom resolves the authenticated workspace and the principal
// to attribute the change to.
//
// Free function rather than a method: both this controller and the GitHub
// discovery controller need it, and there must be exactly one implementation of
// "who is calling, and for which workspace" — a second copy is how the two
// drift and one of them stops checking something.
func workspaceAndActorFrom(c *gin.Context) (uuid.UUID, string, error) {
	ws := c.GetString("workspace_id")
	if ws == "" {
		return uuid.Nil, "", errors.New("workspace_id not found in token")
	}
	id, err := uuid.Parse(ws)
	if err != nil {
		return uuid.Nil, "", errors.New("invalid workspace_id")
	}
	actor := c.GetString("client_id")
	if actor == "" {
		if u, uerr := middlewares.ResolveUserID(c); uerr == nil {
			actor = u
		}
	}
	if actor == "" {
		actor = "system"
	}
	return id, actor, nil
}
