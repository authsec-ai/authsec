package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

/* conditions.go keeps an IAM condition exactly as Google returned it and pulls out
   the one thing a reviewer asks first: when does this grant start and stop.

   NOTHING IS EVALUATED. The expression is CEL; AuthSec does not run it. Title,
   description and expression are stored verbatim, and a binding with any
   condition is conditional -- never plain access.

   BOUNDS ARE EXTRACTED CONSERVATIVELY. A bound is read only from a conjunct of
   the form  request.time < timestamp("...")  (or <=, >, >=), and only when the
   whole expression is an AND of conjuncts. An OR, or a negation, can widen or
   invert what a bound means, so any expression containing one yields no bounds
   at all: a missing expires_at is honest, a wrong one is not. The raw CEL is
   always kept, so nothing is lost by declining to interpret it. */

// Condition is a parsed IAM condition.
type Condition struct {
	Title       string
	Description string
	Expression  string
	// ExpiresAt is the earliest upper bound on request.time, StartsAt the latest
	// lower bound; nil when the expression has none that can be trusted.
	ExpiresAt *time.Time
	StartsAt  *time.Time
}

// conditionJSON is the shape stored in cloud_permission.condition.
type conditionJSON struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"`
}

var timeBound = regexp.MustCompile(
	`^request\.time\s*(<=|>=|<|>)\s*timestamp\(\s*(?:"([^"]*)"|'([^']*)')\s*\)$`)

// ParseCondition records a condition and extracts trustworthy time bounds. It
// returns nil when the binding has no condition (an empty expression).
func ParseCondition(title, description, expression string) *Condition {
	if strings.TrimSpace(expression) == "" {
		return nil
	}
	c := &Condition{Title: title, Description: description, Expression: expression}
	if strings.Contains(expression, "||") {
		return c
	}
	for _, part := range strings.Split(expression, "&&") {
		part = stripParens(strings.TrimSpace(part))
		m := timeBound.FindStringSubmatch(part)
		if m == nil {
			continue
		}
		raw := m[2]
		if raw == "" {
			raw = m[3]
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			continue
		}
		t = t.UTC()
		switch m[1] {
		case "<", "<=":
			if c.ExpiresAt == nil || t.Before(*c.ExpiresAt) {
				c.ExpiresAt = &t
			}
		case ">", ">=":
			if c.StartsAt == nil || t.After(*c.StartsAt) {
				c.StartsAt = &t
			}
		}
	}
	return c
}

// stripParens removes balanced outer parentheses.
func stripParens(s string) string {
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		depth := 0
		balanced := true
		for i, r := range s {
			switch r {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(s)-1 {
					balanced = false
				}
			}
			if !balanced {
				break
			}
		}
		if !balanced {
			return s
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// JSON is the stored form of the condition column.
func (c *Condition) JSON() (string, error) {
	raw, err := json.Marshal(conditionJSON{Title: c.Title, Description: c.Description, Expression: c.Expression})
	return string(raw), err
}

// Hash is a short stable digest of the condition, part of a binding's native_id
// so one member holding one role under two conditions keeps two rows. The empty
// string for no condition.
func (c *Condition) Hash() string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Title + "\x00" + c.Description + "\x00" + c.Expression))
	return hex.EncodeToString(sum[:])[:12]
}
