package middlewares

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/logintickets"
	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// LoginSubject is who a request on the MFA surface is allowed to act for.
type LoginSubject struct {
	WorkspaceID string
	UserID      string
	Email       string
	// Ticket is the raw login ticket when the subject came from one; empty for
	// a Bearer session.
	Ticket string
}

const loginSubjectKey = "login_subject"

// maxLoginBody bounds how much of a request body the subject check buffers.
const maxLoginBody = 1 << 20

// identityFields are the request fields that name whose account a request on
// the MFA surface touches. Each one, when present, must match the subject.
var identityFields = []string{"email", "user_email", "workspace_id", "tenant_id", "user_id"}

// RequireLoginSubject gates the interactive MFA endpoints (enrolment and
// verification of WebAuthn, TOTP, SMS). A request must carry either
//
//   - a valid platform session (Authorization: Bearer), or
//   - a live login ticket (X-Login-Ticket header) of the given realm, which is
//     only issued after a first factor was verified server-side,
//
// and every identity field in its body or query (email, workspace_id, ...)
// must name that same subject. realm "" accepts a ticket of either realm.
//
// With markMFA, a 2xx response from the wrapped verification handler marks
// the ticket as having passed its second factor; registration and setup
// routes must not set it.
func RequireLoginSubject(realm string, markMFA bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := resolveLoginSubject(c, realm)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "sign in first: this step needs a login ticket or a session",
			})
			return
		}

		if field, ok := requestMatchesSubject(c, subject); !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "request does not match the signed-in user (" + field + ")",
			})
			return
		}

		c.Set(loginSubjectKey, subject)
		c.Next()

		if markMFA && subject.Ticket != "" && c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			if err := logintickets.MarkMFAVerified(config.GetDatabase().DB, subject.Ticket); err != nil {
				log.Printf("login ticket: failed to record second factor: %v", err)
			}
		}
	}
}

// GetLoginSubject returns the subject RequireLoginSubject admitted.
func GetLoginSubject(c *gin.Context) (*LoginSubject, bool) {
	v, ok := c.Get(loginSubjectKey)
	if !ok {
		return nil, false
	}
	s, ok := v.(*LoginSubject)
	return s, ok
}

// LoginTicketFromRequest reads the ticket from the header or, for clients that
// cannot set headers, the login_ticket JSON field.
func LoginTicketFromRequest(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader(logintickets.HeaderName)); v != "" {
		return v
	}
	body, err := peekBody(c)
	if err != nil || len(body) == 0 {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	v, _ := m[logintickets.ResponseField].(string)
	return strings.TrimSpace(v)
}

func resolveLoginSubject(c *gin.Context, realm string) (*LoginSubject, error) {
	if authz := c.GetHeader("Authorization"); authz != "" {
		token, err := extractBearerToken(c)
		if err != nil {
			return nil, err
		}
		// The console realm accepts console tokens only; the end-user realm
		// (and the realm-less legacy routes) accept either user class (AS-033).
		allowed := userSessionClasses
		if realm == logintickets.RealmAdmin {
			allowed = []sessiontoken.Class{sessiontoken.Admin, sessiontoken.Legacy}
		}
		claims, err := validateJWTTokenFor(token, DefaultAuthConfig(), allowed)
		if err != nil {
			return nil, err
		}
		if sessionRevoked(claims) {
			return nil, errors.New("session has been revoked")
		}
		return subjectFromClaims(claims)
	}

	value := LoginTicketFromRequest(c)
	t, err := logintickets.Lookup(config.GetDatabase().DB, value)
	if err != nil {
		return nil, err
	}
	if realm != "" && t.Realm != realm {
		return nil, logintickets.ErrInvalid
	}
	return &LoginSubject{
		WorkspaceID: t.WorkspaceID.String(),
		UserID:      t.UserID.String(),
		Email:       t.Email,
		Ticket:      value,
	}, nil
}

func subjectFromClaims(claims jwt.MapClaims) (*LoginSubject, error) {
	ws, _ := claims["workspace_id"].(string)
	email, _ := claims["email_id"].(string)
	if email == "" {
		email, _ = claims["email"].(string)
	}
	uid, _ := claims["user_id"].(string)
	if uid == "" {
		uid, _ = claims["sub"].(string)
	}
	if ws == "" || email == "" {
		return nil, errors.New("session token lacks workspace or email")
	}
	return &LoginSubject{WorkspaceID: ws, UserID: uid, Email: strings.ToLower(email)}, nil
}

// requestMatchesSubject checks every identity field in the JSON body and the
// query string. It returns the first mismatching field.
func requestMatchesSubject(c *gin.Context, s *LoginSubject) (string, bool) {
	values := map[string][]string{}
	for _, f := range identityFields {
		if v := c.Query(f); v != "" {
			values[f] = append(values[f], v)
		}
	}
	if body, err := peekBody(c); err == nil && len(body) > 0 {
		var m map[string]interface{}
		if json.Unmarshal(body, &m) == nil {
			for _, f := range identityFields {
				if v, ok := m[f].(string); ok && v != "" {
					values[f] = append(values[f], v)
				}
			}
		}
	}

	for f, vs := range values {
		for _, v := range vs {
			if !fieldMatches(f, v, s) {
				return f, false
			}
		}
	}
	return "", true
}

func fieldMatches(field, value string, s *LoginSubject) bool {
	switch field {
	case "email", "user_email":
		return strings.EqualFold(strings.TrimSpace(value), s.Email)
	case "workspace_id", "tenant_id":
		return strings.EqualFold(strings.TrimSpace(value), s.WorkspaceID)
	case "user_id":
		return s.UserID != "" && strings.EqualFold(strings.TrimSpace(value), s.UserID)
	}
	return true
}

// peekBody reads the request body (bounded) and restores it for the handler.
func peekBody(c *gin.Context) ([]byte, error) {
	if c.Request.Body == nil {
		return nil, nil
	}
	if cached, ok := c.Get("_login_peeked_body"); ok {
		return cached.([]byte), nil
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxLoginBody))
	if err != nil {
		return nil, err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Set("_login_peeked_body", body)
	return body, nil
}
