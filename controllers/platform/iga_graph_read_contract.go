package platform

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// The §5.2 error envelope for 401 and 403 on the graph routes (D-9):
// "Errors, on every route" names 401 unauthenticated and 403 forbidden, so a
// denial on a graph route is {"error": {"code", "message", ...}} like every
// other error the console branches on -- not the shared middlewares' own
// bodies ({"error": "<text>"}, {"error": "insufficient_scope", ...}, or none
// at all for a missing claims set).
//
// The permission DECISION is unchanged: the wrapped middleware decides
// exactly as before, and only the body of its denial is rewritten. A denial
// that is already the §5.2 envelope -- a graph handler's own 401 (no
// workspace in the token) or 403 (not a verified human for a classification
// decision) -- passes through verbatim. The shared middlewares, and every
// Phase 1 /api/iga/v1 route that uses them, keep their bodies.

// MountIGAGraphReadRoutes mounts the §5.3 graph catalogue on its OWN
// /api/iga/v1 group of r: behind auth, with each route's permission
// middleware built by require, both wrapped by GraphEnvelope. Production
// calls it from routes.SetupIGARoutes, with middlewares.AuthMiddleware() and
// middlewares.Require; the contract test (p2_contract_errors_test.go) mounts
// that same SetupIGARoutes -- not this function -- so the wiring production
// runs is the wiring that is tested, and checks that SetupRoutes calls it
// (D-100). A separate group because AuthMiddleware on the shared /api/iga/v1
// group also guards the Phase 1 routes, whose bodies must not change.
func MountIGAGraphReadRoutes(r gin.IRouter, ctl *IGAGraphReadController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1")
	g.Use(GraphEnvelope(auth))
	RegisterIGAGraphReadRoutes(g, ctl, GraphRequire(require))
}

// GraphEnvelope wraps an authentication or permission middleware so that a
// 401 or 403 it answers with is rendered as the §5.2 envelope: code
// unauthenticated or forbidden, the middleware's own description as the
// message when it gave one, and the permissions it named. Headers it set
// (WWW-Authenticate) are kept. Anything else it or the handlers after it
// write passes through untouched.
func GraphEnvelope(inner gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		w := &graphDenyWriter{ResponseWriter: c.Writer}
		c.Writer = w
		inner(c)
		c.Writer = w.ResponseWriter
		if w.status == 0 {
			return
		}
		if graphIsEnvelope(w.body.Bytes()) {
			c.Data(w.status, "application/json; charset=utf-8", w.body.Bytes())
			return
		}
		c.AbortWithStatusJSON(w.status, graphDenial(w.status, w.body.Bytes()))
	}
}

// GraphRequire is require with every middleware it builds wrapped by
// GraphEnvelope: what RegisterIGAGraphReadRoutes is given in production
// (routes.go), so each graph route's 403 is the §5.2 envelope.
func GraphRequire(require func(resource, action string) gin.HandlerFunc) func(resource, action string) gin.HandlerFunc {
	return func(resource, action string) gin.HandlerFunc { return GraphEnvelope(require(resource, action)) }
}

// graphDenyWriter holds back a 401 or 403 and its body until the wrapped
// middleware returns; every other status and body goes straight through.
type graphDenyWriter struct {
	gin.ResponseWriter
	status int // the held denial's status, 0 when none
	body   bytes.Buffer
}

func (w *graphDenyWriter) WriteHeader(code int) {
	if w.status == 0 && !w.ResponseWriter.Written() && (code == http.StatusUnauthorized || code == http.StatusForbidden) {
		w.status = code
		return
	}
	if w.status != 0 {
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *graphDenyWriter) WriteHeaderNow() {
	if w.status != 0 {
		return
	}
	w.ResponseWriter.WriteHeaderNow()
}

func (w *graphDenyWriter) Write(b []byte) (int, error) {
	if w.status != 0 {
		return w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *graphDenyWriter) WriteString(s string) (int, error) {
	if w.status != 0 {
		return w.body.WriteString(s)
	}
	return w.ResponseWriter.WriteString(s)
}

// graphIsEnvelope reports whether a body is already the §5.2 envelope:
// {"error": {"code": "<string>", ...}}.
func graphIsEnvelope(raw []byte) bool {
	var b struct {
		Error *struct {
			Code *string `json:"code"`
		} `json:"error"`
	}
	return json.Unmarshal(raw, &b) == nil && b.Error != nil && b.Error.Code != nil && *b.Error.Code != ""
}

// graphDenial is the §5.2 body for a denial the middleware rendered its own
// way (or not at all): the code for its status; as the message, the
// middleware's error_description, else its error text when it is prose, else
// a fixed sentence; and required_permissions when it named them.
func graphDenial(status int, raw []byte) gin.H {
	code, msg := "forbidden", "This token lacks the permission this route requires."
	if status == http.StatusUnauthorized {
		code, msg = "unauthenticated", "No valid token."
	}
	inner := gin.H{"code": code, "message": msg}
	var theirs map[string]any
	if json.Unmarshal(raw, &theirs) == nil {
		if d, ok := theirs["error_description"].(string); ok && d != "" {
			inner["message"] = d
		} else if e, ok := theirs["error"].(string); ok && e != "" && e != "insufficient_scope" {
			inner["message"] = e
		}
		if p, ok := theirs["required_permissions"]; ok {
			inner["required_permissions"] = p
		}
	}
	return gin.H{"error": inner}
}
