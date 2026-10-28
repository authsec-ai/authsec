package services

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/models"
)

// PolicyV2Validator validates V2 policy documents. It provides both structural
// validation (via compile.ValidateV2) and backend compatibility checks.
type PolicyV2Validator struct{}

// NewPolicyV2Validator creates a new V2 policy validator.
func NewPolicyV2Validator() *PolicyV2Validator {
	return &PolicyV2Validator{}
}

// ValidateDocument performs full V2 document validation and returns
// field-specific errors with JSON pointers.
func (v *PolicyV2Validator) ValidateDocument(raw []byte) (models.RuntimePolicyV2Document, compile.V2ValidationResult, error) {
	doc, err := compile.ParseV2(raw)
	if err != nil {
		return models.RuntimePolicyV2Document{}, compile.V2ValidationResult{}, err
	}
	result := compile.ValidateV2(doc)
	return doc, result, nil
}

// CheckBackendCompatibility verifies that a V2 document's rules can be
// enforced by the selected backend and profile. It returns errors for rules
// that reference primitives the backend cannot handle.
func (v *PolicyV2Validator) CheckBackendCompatibility(doc models.RuntimePolicyV2Document) []compile.V2FieldError {
	var errs []compile.V2FieldError
	backend := doc.Enforcement.Backend

	for i, rule := range doc.Rules {
		if !isPrimitiveSupportedByBackend(rule.Primitive, backend) {
			errs = append(errs, compile.V2FieldError{
				Pointer: fmt.Sprintf("/rules/%d/primitive", i),
				Code:    "backend_incompatible",
				Message: fmt.Sprintf("primitive %s is not supported by backend %s", rule.Primitive, backend),
			})
		}
	}
	return errs
}

// isPrimitiveSupportedByBackend checks if a primitive can be enforced by a backend.
func isPrimitiveSupportedByBackend(primitive, backend string) bool {
	switch backend {
	case models.EnforcementBackendAuthSec:
		// AuthSec supports all primitives.
		return true
	case models.EnforcementBackendOpenShell:
		// OpenShell supports a subset of primitives via its native enforcement.
		switch primitive {
		case models.PrimitiveFileRead, models.PrimitiveFileWrite,
			models.PrimitiveProcessHarden, models.PrimitiveProcessExec,
			models.PrimitiveNetworkConnect, models.PrimitiveUnixSocket:
			return true
		default:
			// Gateway-mediated primitives (LLM, GitHub, secret, etc.) are
			// not supported by OpenShell natively.
			return false
		}
	default:
		return false
	}
}

// DetectFormat inspects raw JSON to determine whether it is a V1 or V2 document.
func DetectFormat(raw []byte) (string, error) {
	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", statusErr(http.StatusBadRequest, "invalid_document", "The document is not valid JSON.")
	}
	switch probe.Format {
	case compile.FormatV1:
		return compile.FormatV1, nil
	case compile.FormatV2:
		return compile.FormatV2, nil
	case "":
		return "", statusErr(http.StatusBadRequest, "invalid_document", "The document is missing a format field.")
	default:
		return "", statusErr(http.StatusBadRequest, "invalid_document", "Unknown document format: "+probe.Format)
	}
}
