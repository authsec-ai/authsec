package platform

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/igaread"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// IGAGraphReadController serves the Phase 2 graph reads under /api/iga/v1
// (SPEC-iga-phase2-graph.md §5.3). Every read goes through internal/igaread,
// which owns the §5.1 consistency contract; the handlers here only resolve the
// workspace from the token, apply the 503 gate, and render.
//
// The route groups live in iga_graph_read_*.go beside this file.
type IGAGraphReadController struct {
	gate func() *services.GraphProjectionGate
	db   func() *gorm.DB
	key  []byte

	readerOnce sync.Once
	reader     *igaread.Reader

	// classifier is the classification decision service a test installed
	// (WithClassificationService); nil builds one over db() per request.
	classifier *services.ClassificationService
}

// NewIGAGraphReadController reads the process-wide projection gate on every
// request, so a gate verified after startup is reported as soon as it is.
func NewIGAGraphReadController() *IGAGraphReadController {
	return &IGAGraphReadController{
		gate: services.GraphProjection,
		db:   func() *gorm.DB { return config.DB },
		key:  cursorKeyFromEnv(),
	}
}

// NewIGAGraphReadControllerWith builds a controller over an explicit database,
// gate and cursor key. Tests use it; production uses NewIGAGraphReadController.
func NewIGAGraphReadControllerWith(db *gorm.DB, gate *services.GraphProjectionGate, cursorKey []byte) *IGAGraphReadController {
	return &IGAGraphReadController{
		gate: func() *services.GraphProjectionGate { return gate },
		db:   func() *gorm.DB { return db },
		key:  cursorKey,
	}
}

// IGACursorSecretEnv signs list cursors (§5.1). It must be the same on every
// replica, or a cursor issued by one is cursor_invalid on another.
const IGACursorSecretEnv = "IGA_CURSOR_SECRET"

var warnCursorOnce sync.Once

// cursorKeyFromEnv reads IGA_CURSOR_SECRET. Unset, a random per-process key is
// used and a warning logged: cursors then stop verifying across a restart or
// between replicas (400 cursor_invalid, and the console restarts the list) --
// safe, never a forged position, but a deployment must set the secret.
func cursorKeyFromEnv() []byte {
	if s := os.Getenv(IGACursorSecretEnv); s != "" {
		return []byte(s)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(fmt.Sprintf("igaread: no randomness for the cursor key: %v", err))
	}
	warnCursorOnce.Do(func() {
		log.Printf("[graph] %s is not set; list cursors are signed with a per-process key and will not survive a restart or cross replicas", IGACursorSecretEnv)
	})
	return k
}

// Reader returns the process's graph reader, built on first use.
func (ctl *IGAGraphReadController) Reader() *igaread.Reader {
	ctl.readerOnce.Do(func() { ctl.reader = igaread.NewReader(ctl.db(), ctl.key) })
	return ctl.reader
}

// graphFeatures is what THIS build serves NOW (§5.3 /capabilities). A feature
// is true only when its routes are implemented AND graph_projection is on
// (D-11): with the switch off or misconfigured every graph route answers 503,
// so nothing is usable. The console hides a feature it is told is
// unavailable, and a feature reported available with no route behind it would
// render as empty rather than as unavailable -- which §2.14.7 forbids. And only
// when the switch is on (D-11): off or misconfigured, every graph route
// answers 503, so nothing is usable.
func graphFeatures(on bool) gin.H {
	return gin.H{
		"identities": false, "resources": false,
		"graph": false, "evidence": false, "changes": false,
		// T6.2 + T6.3: GET /workloads, /workloads/:id and its identities and
		// resources tabs (its Changes tab is the "changes" feature).
		"workloads": on,
		// T6.6: POST and GET /workloads/:id/classification. T2.3: /coverage.
		"classification": on,
		"coverage":       on,
	}
}

// GetCapabilities handles GET /api/iga/v1/capabilities (§5.3): what this
// deployment supports. Any authenticated caller; no permission beyond a token.
//
// graph_projection is on | off | misconfigured, with the reason when it is
// not on. "misconfigured" is the fail-closed state (§2.8): the switch is on and
// schema verification failed or errored, so the scan worker claims nothing and
// the projector is not running.
func (ctl *IGAGraphReadController) GetCapabilities(c *gin.Context) {
	mode, reason, head := ctl.gate().Status()
	if db := ctl.db(); head == "" && db != nil {
		// Off, or never verified: report the migration head we can see, so an
		// operator can tell "off" from "on against an old schema".
		if h, err := repositories.MigrationHead(db); err == nil && h > 0 {
			head = fmt.Sprintf("%03d", h)
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"graph_projection": mode,
		"reason":           nullIfEmpty(reason),
		"features":         graphFeatures(mode == services.GraphProjectionOn),
		"schema_head":      nullIfEmpty(head),
	}})
}

// graphCall is one graph read: the workspace from the token and the reader.
type graphCall struct {
	C      *gin.Context
	WS     uuid.UUID
	Reader *igaread.Reader
}

// serve runs one graph read under the contract every route shares:
//
//   - 503 graph_unavailable unless IGA_GRAPH_PROJECTION is on AND verified
//     (§2.8, T6.9): the console shows Unavailable, never an empty graph;
//   - the workspace ONLY from the token, never a parameter (§5);
//   - errors rendered as {"error": {...}} with the §5.2 status, nothing partial.
//
// fn returns the full response body (an igaread.Envelope, normally).
func (ctl *IGAGraphReadController) serve(c *gin.Context, fn func(g graphCall) (any, error)) {
	if mode, reason, _ := ctl.gate().Status(); mode != services.GraphProjectionOn {
		writeGraphError(c, igaread.GraphUnavailable(mode, reason))
		return
	}
	ws, ok := tokenWorkspace(c)
	if !ok {
		writeGraphError(c, igaread.Unauthenticated())
		return
	}
	body, err := fn(graphCall{C: c, WS: ws, Reader: ctl.Reader()})
	if err != nil {
		writeGraphError(c, igaread.AsError(err))
		return
	}
	c.JSON(http.StatusOK, body)
}

// tokenWorkspace is the workspace AuthMiddleware established. Never a
// parameter, never a fallback to another claim.
func tokenWorkspace(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.GetString("workspace_id"))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, false
	}
	return id, true
}

func writeGraphError(c *gin.Context, e *igaread.Error) {
	if e.Status >= 500 && e.Status != http.StatusServiceUnavailable {
		log.Printf("[graph] %s %s: %v", c.Request.Method, c.FullPath(), e)
	}
	c.AbortWithStatusJSON(e.Status, e.Body())
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// notYet answers a route whose task has not landed: 501, after the same gate
// and token checks every real route applies.
func (ctl *IGAGraphReadController) notYet(c *gin.Context) {
	ctl.serve(c, func(graphCall) (any, error) {
		return nil, &igaread.Error{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "Not implemented yet."}
	})
}
