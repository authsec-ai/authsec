// Package igaread is the Phase 2 graph read path (SPEC-iga-phase2-graph.md §5).
//
// It owns EVERY read of the iga_* graph for the /api/iga/v1 graph routes, so
// the consistency contract of §5.1 lives in one place: one REPEATABLE READ,
// READ ONLY snapshot per request, one request deadline, optional work in
// savepoints, the revision check, and signed cursors. It never writes.
package igaread

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Error is a contract error (§5.2 "Errors, on every route"): an HTTP status, a
// machine code and a message, plus the code's own fields (requested_rev,
// current, reason ...). Handlers render it as {"error": {...}}; nothing partial
// is ever returned beside it.
type Error struct {
	Status  int
	Code    string
	Message string
	Extra   map[string]any
	cause   error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.cause }

// Body is the JSON the handler writes: {"error": {"code", "message", ...extra}}.
func (e *Error) Body() map[string]any {
	inner := map[string]any{"code": e.Code, "message": e.Message}
	for k, v := range e.Extra {
		inner[k] = v
	}
	return map[string]any{"error": inner}
}

func newErr(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// With adds one field to the error body and returns the error.
func (e *Error) With(k string, v any) *Error {
	if e.Extra == nil {
		e.Extra = map[string]any{}
	}
	e.Extra[k] = v
	return e
}

// InvalidParameter is 400 invalid_parameter, naming the parameter.
func InvalidParameter(param, msg string) *Error {
	return newErr(http.StatusBadRequest, "invalid_parameter", msg).With("parameter", param)
}

// CursorInvalid is 400 cursor_invalid: a cursor from another workspace, route,
// filter set or sort, or one that fails its signature (§5.1).
func CursorInvalid(msg string) *Error {
	return newErr(http.StatusBadRequest, "cursor_invalid", msg)
}

// Unauthenticated is 401.
func Unauthenticated() *Error {
	return newErr(http.StatusUnauthorized, "unauthenticated", "No valid token.")
}

// Forbidden is 403.
func Forbidden(msg string) *Error { return newErr(http.StatusForbidden, "forbidden", msg) }

// NotFound is 404 not_found, with no hint whether the id exists elsewhere.
func NotFound() *Error { return newErr(http.StatusNotFound, "not_found", "Not found.") }

// RevisionStale is THE stale-revision status and payload, on every route
// (§5.1): the requested revision (or the cursor's) is no longer current.
func RevisionStale(requested int64, cur *Revision) *Error {
	e := newErr(http.StatusConflict, "revision_stale", "A newer scan was published.").
		With("requested_rev", requested)
	if cur != nil {
		e.With("current_rev", cur.Rev).With("current_published_at", PublicationTime(cur.PublishedAt).Format(time.RFC3339)) // D-94
	} else {
		e.With("current_rev", nil).With("current_published_at", nil)
	}
	return e
}

// ListingChanged is 409 listing_changed: a classification list's clock moved
// between pages (§5.5).
func ListingChanged(reason string) *Error {
	return newErr(http.StatusConflict, "listing_changed", "The listing changed; restart from the first page.").
		With("reason", reason)
}

// Conflict is a 409 with its own code (classification_conflict).
func Conflict(code, msg string) *Error { return newErr(http.StatusConflict, code, msg) }

// Unprocessable is a 422 with its own code (provider_native, invalid_decision,
// operation_id_reused).
func Unprocessable(code, msg string) *Error { return newErr(http.StatusUnprocessableEntity, code, msg) }

// GraphUnavailable is 503 graph_unavailable: IGA_GRAPH_PROJECTION is off or
// misconfigured (§2.8), with the reason.
func GraphUnavailable(mode, reason string) *Error {
	e := newErr(http.StatusServiceUnavailable, "graph_unavailable", "The identity graph is not available.").
		With("graph_projection", mode)
	if reason == "" {
		return e.With("reason", nil)
	}
	return e.With("reason", reason)
}

// QueryTimeout is 504 query_timeout: a MANDATORY query did not finish inside
// the request deadline. Nothing partial is returned.
func QueryTimeout(cause error) *Error {
	e := newErr(http.StatusGatewayTimeout, "query_timeout", "The request did not finish within its deadline.")
	e.cause = cause
	return e
}

// Internal is 500 internal: a database error. The cause is logged, never sent.
func Internal(cause error) *Error {
	e := newErr(http.StatusInternalServerError, "internal", "Internal error.")
	e.cause = cause
	return e
}

// AsError maps any error to its contract error: an *Error passes through, a
// deadline or statement cancellation is 504, anything else is 500.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if IsTimeout(err) {
		return QueryTimeout(err)
	}
	return Internal(err)
}

// IsTimeout reports whether err is the request deadline or a statement that
// PostgreSQL cancelled (57014: statement_timeout, or the driver cancelling on
// the context).
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	// pgconn.PgError and lib/pq's Error both expose SQLState; asserting the
	// method keeps the driver out of this package's imports.
	var st interface{ SQLState() string }
	if errors.As(err, &st) && st.SQLState() == "57014" {
		return true
	}
	return false
}
