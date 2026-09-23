package igaread

// Pure pieces of the identity and external-principal detail routes
// (idetail_*.go). Everything that touches the database is proven end to end
// in tests/integration/p2_idetail_*.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// StatementContent reads the verbatim AWS statement with the parser the
// projector used -- string or list Action, NotAction, the Condition verbatim
// -- and the fallback NativeRights shape; lists are never nil.
func TestIdetailStatementContent(t *testing.T) {
	for name, tc := range map[string]struct {
		raw        string
		actions    string
		notActions string
		cond       string
	}{
		"verbatim, string action": {`{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`,
			"s3:GetObject", "", ""},
		"verbatim, list action and condition": {`{"Effect":"Deny","Action":["s3:A","s3:B"],"Resource":"*",` +
			`"Condition":{"Bool":{"aws:SecureTransport":"false"}}}`, "s3:A,s3:B", "", `{"Bool":{"aws:SecureTransport":"false"}}`},
		"verbatim NotAction": {`{"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"}`, "", "iam:*", ""},
		"fallback NativeRights": {`{"effect":"allow","actions":["s3:X"],"not_actions":["s3:Y"],"condition":{"k":1}}`,
			"s3:X", "s3:Y", `{"k":1}`},
		"garbage": {`{}`, "", "", ""},
	} {
		a, na, c := StatementContent(json.RawMessage(tc.raw))
		if a == nil || na == nil {
			t.Errorf("%s: nil list (actions %v, not_actions %v): the API writes [] not null", name, a, na)
		}
		if strings.Join(a, ",") != tc.actions || strings.Join(na, ",") != tc.notActions || string(c) != tc.cond {
			t.Errorf("%s: got actions %v not_actions %v condition %s, want %q %q %s", name, a, na, c, tc.actions, tc.notActions, tc.cond)
		}
	}
}

// D-84: the API index is the stored one plus one; nil stays nil.
func TestIdetailStatementIndexOf(t *testing.T) {
	zero, four := 0, 4
	if StatementIndexOf(nil) != nil || *StatementIndexOf(&zero) != 1 || *StatementIndexOf(&four) != 5 {
		t.Error("StatementIndexOf must be stored+1, nil for nil")
	}
}

// The stored credential lifecycle maps to AWS's status; anything that does
// not record one is null, never guessed.
func TestIdetailCredentialStatusOf(t *testing.T) {
	for lc, want := range map[string]string{"active": "active", "revoked": "inactive", "expired": "", "rotated": "", "": ""} {
		got := CredentialStatusOf(lc)
		if (want == "" && got != nil) || (want != "" && (got == nil || *got != want)) {
			t.Errorf("CredentialStatusOf(%q) = %v, want %q", lc, got, want)
		}
	}
}

// D-85: the allowlist, exactly; trust flags only on roles, null when the
// projector did not write them, never false.
func TestIdetailIdentityProviderAttrs(t *testing.T) {
	raw := json.RawMessage(`{"path":"/svc/","tags":{"team":"a"},"permissions_boundary_arn":"arn:b",` +
		`"trust_has_deny":true,"trust_negated_statements":["k"],"secret_thing":"x"}`)
	role := IdentityProviderAttrs(models.CloudIdentityIAMRole, raw)
	if len(role) != 5 || role["trust_has_deny"] != true || role["trust_has_not_principal"] != nil ||
		role["path"] != "/svc/" || role["permissions_boundary_arn"] != "arn:b" {
		t.Errorf("role attrs = %v, want the five allowlisted keys, trust_has_not_principal null (unknown)", role)
	}
	if _, has := role["trust_negated_statements"]; has {
		t.Error("trust_negated_statements leaked: it feeds limitations, not the detail (D-85)")
	}
	user := IdentityProviderAttrs(models.CloudIdentityIAMUser, json.RawMessage(`{"path":"/"}`))
	if len(user) != 3 || user["permissions_boundary_arn"] != nil || len(user["tags"].(map[string]any)) != 0 {
		t.Errorf("user attrs = %v, want path, tags {} and boundary null only", user)
	}
}

// §4.7: the Sid is read back from a Sid-keyed trust statement key only.
func TestIdetailTrustStatementOf(t *testing.T) {
	role := igagraph.Key("aws", "uid", "AROA1")
	sid := igagraph.Key("aws", role, "trust", "sid:PartnerA")
	hash := igagraph.Key("aws", role, "trust", "h:abc#1")
	pod := igagraph.Key("aws", role, "pod_identity", "issuer", "system:serviceaccount:ns:sid:x")
	if st := TrustStatementOf(sid, map[string]bool{sid: true}); st.Sid != "PartnerA" || !st.Negated || st.Key != sid {
		t.Errorf("sid-keyed = %+v", st)
	}
	if st := TrustStatementOf(hash, nil); st.Sid != "" || st.Negated {
		t.Errorf("hash-keyed = %+v, want no Sid", st)
	}
	if st := TrustStatementOf(pod, nil); st.Sid != "" {
		t.Errorf("pod-identity key = %+v, want no Sid", st)
	}
}

// Why an external principal is unresolved, in order; nil only when a
// resolution is in force.
func TestIdetailUnresolvedReasonOf(t *testing.T) {
	id := uuid.New()
	inForce := ExternalResolutionOf(models.BasisDerived, models.ResolutionActive, models.ResolutionRuleExactARN, "", &id, nil)
	suspended := ExternalResolutionOf(models.BasisAsserted, models.ResolutionSuspended, "", "priya", &id, nil)
	off := &Account{ID: "300000000003", Connected: false}
	on := &Account{ID: "220171243705", Connected: true}
	for name, tc := range map[string]struct {
		mech, subject string
		account       *Account
		res           *ExternalResolution
		want          string
	}{
		"in force":           {models.ExternalPrincipalAWSPrincipal, "arn:aws:iam::220171243705:role/r", on, inForce, ""},
		"star":               {models.ExternalPrincipalAWSAccount, "*", nil, nil, UnresolvedWildcard},
		"oidc pattern":       {models.ExternalPrincipalOIDC, "repo:org/*", nil, nil, UnresolvedWildcard},
		"service":            {models.ExternalPrincipalAWSService, "lambda.amazonaws.com", nil, nil, UnresolvedServicePrincipal},
		"unconnected":        {models.ExternalPrincipalAWSAccount, "300000000003", off, nil, UnresolvedAccountNotConnected},
		"connected, no id":   {models.ExternalPrincipalAWSPrincipal, "arn:aws:iam::220171243705:role/gone", on, nil, UnresolvedNotInInventory},
		"resolution off":     {models.ExternalPrincipalAWSPrincipal, "arn:aws:iam::220171243705:role/r", on, suspended, UnresolvedNotInInventory},
		"exact oidc subject": {models.ExternalPrincipalOIDC, "repo:org/app:ref:main", nil, nil, UnresolvedNotInInventory},
	} {
		got := UnresolvedReasonOf(tc.mech, tc.subject, tc.account, tc.res)
		if (tc.want == "" && got != nil) || (tc.want != "" && (got == nil || *got != tc.want)) {
			t.Errorf("%s: unresolved_reason = %v, want %q", name, got, tc.want)
		}
	}
	if ExternalResolutionOf("", models.ResolutionActive, "", "", nil, nil) != nil {
		t.Error("a resolution with no basis must be null (D-87): 034 defaults the state to active")
	}
	if r := ExternalResolutionOf(models.BasisAsserted, models.ResolutionActive, "", "priya", nil, &id); r.ResolvedTo != R(RefWorkload, id) ||
		r.Rule != nil || r.ResolvedBy == nil || *r.ResolvedBy != "priya" {
		t.Errorf("asserted to a workload = %+v", r)
	}
}

// D-47: derived lifecycle.
func TestIdetailExternalLifecycleOf(t *testing.T) {
	if ExternalLifecycleOf(StateCurrent) != "active" || ExternalLifecycleOf(StateStale) != "active" ||
		ExternalLifecycleOf(StateEnded) != "retired" {
		t.Error("an external principal is active while any edge from it is current or stale, else retired")
	}
}
