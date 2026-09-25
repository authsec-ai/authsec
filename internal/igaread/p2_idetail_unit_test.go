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

// The stored credential lifecycle maps to AWS's status, spelled as AWS spells
// it (D-86: Active/Inactive); anything that does not record one is null,
// never guessed.
func TestIdetailCredentialStatusOf(t *testing.T) {
	for lc, want := range map[string]string{"active": "Active", "revoked": "Inactive", "expired": "", "rotated": "", "": ""} {
		got := CredentialStatusOf(lc)
		if (want == "" && got != nil) || (want != "" && (got == nil || *got != want)) {
			t.Errorf("CredentialStatusOf(%q) = %v, want %q", lc, got, want)
		}
	}
}

// D-85: the allowlist, exactly, on every kind (D-102d); trust flags stated
// only for a role, null when the projector did not write them, never false --
// and null, never absent, on a user or group, which has no trust document.
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
	for _, kind := range []string{models.CloudIdentityIAMUser, models.CloudIdentityIAMGroup} {
		// Even a flag in the jsonb is no trust document's: only a role has one.
		attrs := IdentityProviderAttrs(kind, json.RawMessage(`{"path":"/","trust_has_deny":false}`))
		deny, hasDeny := attrs["trust_has_deny"]
		np, hasNP := attrs["trust_has_not_principal"]
		if len(attrs) != 5 || attrs["permissions_boundary_arn"] != nil || len(attrs["tags"].(map[string]any)) != 0 ||
			!hasDeny || deny != nil || !hasNP || np != nil {
			t.Errorf("%s attrs = %v, want path, tags {}, boundary null and both trust flags null (D-102d)", kind, attrs)
		}
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
		"unconnected role":   {models.ExternalPrincipalAWSPrincipal, "arn:aws:iam::300000000003:role/r", off, nil, UnresolvedAccountNotConnected},
		"connected root":     {models.ExternalPrincipalAWSAccount, "220171243705", on, nil, UnresolvedAccountPrincipal},
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

// An external principal's account is connected only as of the revision: a
// live connector for it with a run in the revision. Onboarded but not yet
// published, or revoked, is not connected; an account no connector reads is
// named, not connected; no account is nil. An account connected twice --
// its first connector revoked (its runs are what the revision holds), the
// new one onboarded but not yet published -- is not connected either: the
// revoked connector's runs never make it so (D-89), and the live one has
// none in the revision.
func TestIdetailExternalPrincipalAccount(t *testing.T) {
	published, pending, revoked := uuid.New(), uuid.New(), uuid.New()
	oldConn, newConn := uuid.New(), uuid.New()
	accts := &Accounts{byAccount: map[string]*ConnectorInfo{}, byConnector: map[uuid.UUID]*ConnectorInfo{}}
	for _, c := range []*ConnectorInfo{
		{ID: published, AccountID: "111111111111", Label: "prod", Status: models.CloudConnectorActive},
		{ID: pending, AccountID: "222222222222", Label: "new", Status: models.CloudConnectorActive},
		{ID: revoked, AccountID: "333333333333", Label: "gone", Status: models.CloudConnectorRevoked},
		{ID: oldConn, AccountID: "555555555555", Label: "again", Status: models.CloudConnectorRevoked},
		{ID: newConn, AccountID: "555555555555", Label: "again", Status: models.CloudConnectorActive},
	} {
		accts.byConnector[c.ID] = c
		// As LoadAccounts: a live connector is preferred for its account.
		if prev, ok := accts.byAccount[c.AccountID]; !ok || prev.Status == models.CloudConnectorRevoked {
			accts.byAccount[c.AccountID] = c
		}
	}
	inRevision := map[uuid.UUID]bool{published: true, revoked: true, oldConn: true}
	for id, want := range map[string]bool{"111111111111": true, "222222222222": false, "333333333333": false,
		"444444444444": false, "555555555555": false} {
		a := ExternalPrincipalAccount(accts, inRevision, id)
		if a == nil || a.ID != id || a.Connected != want {
			t.Errorf("ExternalPrincipalAccount(%s) = %+v, want connected %v", id, a, want)
		}
	}
	if a := ExternalPrincipalAccount(accts, inRevision, "222222222222"); a.Label != "new" {
		t.Errorf("a pending account keeps its label: %+v", a)
	}
	if ExternalPrincipalAccount(accts, inRevision, "") != nil {
		t.Error("a principal that names no account has account null")
	}
}

// D-47: derived lifecycle.
func TestIdetailExternalLifecycleOf(t *testing.T) {
	if ExternalLifecycleOf(StateCurrent) != "active" || ExternalLifecycleOf(StateStale) != "active" ||
		ExternalLifecycleOf(StateEnded) != "retired" {
		t.Error("an external principal is active while any edge from it is current or stale, else retired")
	}
}
