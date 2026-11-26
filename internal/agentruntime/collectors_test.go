package agentruntime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const azureTenant = "11111111-2222-3333-4444-555555555555"

func TestParseAzureActivityRecord(t *testing.T) {
	raw := json.RawMessage(`{"time":"2026-11-24T10:00:00.1234567Z","resourceId":"/SUBSCRIPTIONS/AAAA-BBBB/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/x",
		"operationName":"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE","category":"Administrative","resultType":"Failure",
		"resultSignature":"Forbidden.AuthorizationFailed","callerIpAddress":"203.0.113.9","correlationId":"c-1",
		"identity":{"claims":{"http://schemas.microsoft.com/identity/claims/objectidentifier":"oid-1","appid":"app-1","idtyp":"app"},
		"authorization":{"action":"x"}},"properties":{"requestbody":"{\"secret\":\"do-not-store\"}","statusCode":"Forbidden","eventDataId":"evd-1"}}`)
	r := ParseAzureRecord(raw)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	e := r.Event
	if e.Provider != ProviderAzure || e.EventID != "evd-1" || e.PrincipalID != "oid-1" || e.PrincipalType != "ServicePrincipal" {
		t.Fatalf("event %+v", e)
	}
	if e.EventSource != "azure:microsoft.authorization" || e.ReadOnly == nil || *e.ReadOnly || !e.AuthorizationDenied || e.ErrorCode == "" {
		t.Fatalf("event %+v", e)
	}
	if e.AccountID != "aaaa-bbbb" || len(e.RawHash) != 64 || r.TenantID != "" {
		t.Fatalf("account %q hash %q tenant %q", e.AccountID, e.RawHash, r.TenantID)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "do-not-store") {
		t.Fatal("a request body reached the event")
	}
}

func TestParseAzureSignInRecord(t *testing.T) {
	raw := json.RawMessage(`{"time":"2026-11-24T10:00:00Z","operationName":"Sign-in activity","category":"ServicePrincipalSignInLogs",
		"tenantId":"` + strings.ToUpper(azureTenant) + `","resultType":"0","identity":"svc",
		"properties":{"id":"si-1","servicePrincipalId":"sp-1","servicePrincipalName":"agent-app","appId":"app-9","ipAddress":"198.51.100.1","status":{"errorCode":0}}}`)
	r := ParseAzureRecord(raw)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	e := r.Event
	if e.EventID != "si-1" || e.PrincipalID != "sp-1" || e.PrincipalARN != "agent-app" || e.ErrorCode != "" ||
		e.SourceIP != "198.51.100.1" || r.TenantID != azureTenant || e.RequestFacts[FactAppID] != "app-9" {
		t.Fatalf("event %+v tenant %q", e, r.TenantID)
	}
	// No id at all: the record's hash is the id, so a redelivery is one event.
	r1 := ParseAzureRecord(json.RawMessage(`{"time":"2026-11-24T10:00:00Z","operationName":"Microsoft.Storage/storageAccounts/read","category":"Administrative"}`))
	r2 := ParseAzureRecord(json.RawMessage(`{"time":"2026-11-24T10:00:00Z","operationName":"Microsoft.Storage/storageAccounts/read","category":"Administrative"}`))
	if r1.Event.EventID == "" || r1.Event.EventID != r2.Event.EventID {
		t.Fatalf("hash ids %q %q", r1.Event.EventID, r2.Event.EventID)
	}
	if ParseAzureRecord(json.RawMessage(`{"category":"x"}`)).Err == nil {
		t.Fatal("a record without operation and time must be refused")
	}
}

func TestSplitAzureBody(t *testing.T) {
	if r, err := SplitAzureBody([]byte(`{"records":[{},{}]}`)); err != nil || len(r) != 2 {
		t.Fatalf("object: %v %d", err, len(r))
	}
	if r, err := SplitAzureBody([]byte(`[{"records":[{}]},{"records":[{},{}]}]`)); err != nil || len(r) != 3 {
		t.Fatalf("array: %v %d", err, len(r))
	}
	for _, bad := range []string{"", "{}", `{"workspace_id":"x"}`, "[1]", "x"} {
		if _, err := SplitAzureBody([]byte(bad)); err != ErrCollectorBody {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestParseK8sAudit(t *testing.T) {
	body := []byte(`{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[
	 {"auditID":"a1","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:ns:agent","uid":"u1"},
	  "sourceIPs":["10.0.0.1"],"objectRef":{"resource":"secrets","namespace":"ns","name":"db"},"responseStatus":{"code":403},
	  "requestObject":{"data":{"password":"do-not-store"}},"requestReceivedTimestamp":"2026-11-24T10:00:00.000000Z"},
	 {"auditID":"a1","stage":"RequestReceived","verb":"get","user":{"username":"x"},"requestReceivedTimestamp":"2026-11-24T10:00:00Z"},
	 {"auditID":"a2","stage":"ResponseComplete","verb":"create","user":{"username":"alice"},"impersonatedUser":{"username":"bob"},
	  "objectRef":{"resource":"rolebindings","apiGroup":"rbac.authorization.k8s.io","namespace":"ns","name":"rb"},
	  "responseStatus":{"code":201},"requestReceivedTimestamp":"2026-11-24T10:01:00Z"},
	 {"stage":"ResponseComplete"}]}`)
	raws, err := SplitK8sAuditBody(body)
	if err != nil || len(raws) != 4 {
		t.Fatalf("split: %v %d", err, len(raws))
	}
	r := ParseK8sAuditEvent(raws[0], "cluster/c1")
	e := r.Event
	if r.Err != nil || e.EventID != "a1" || e.PrincipalType != "ServiceAccount" || !e.AuthorizationDenied ||
		e.EventName != "get secrets" || e.EventSource != "k8s:core" || e.AccountID != "cluster/c1" || e.Provider != ProviderK8s {
		t.Fatalf("event %+v err %v", e, r.Err)
	}
	if b, _ := json.Marshal(e); strings.Contains(string(b), "do-not-store") {
		t.Fatal("a request object reached the event")
	}
	if !ParseK8sAuditEvent(raws[1], "c").Skipped {
		t.Error("RequestReceived must be skipped")
	}
	r = ParseK8sAuditEvent(raws[2], "c")
	if r.Event.EventSource != "k8s:rbac.authorization.k8s.io" || r.Event.RequestFacts[FactImpersonatedUser] != "bob" || *r.Event.ReadOnly {
		t.Fatalf("event %+v", r.Event)
	}
	if ParseK8sAuditEvent(raws[3], "c").Err == nil {
		t.Error("no auditID must be refused")
	}
	if _, err := SplitK8sAuditBody([]byte(`{"kind":"PodList","items":[]}`)); err != ErrCollectorBody {
		t.Errorf("not an audit EventList: %v", err)
	}
}

func TestRawHashAndDelivery(t *testing.T) {
	raw := []byte(`{"eventID":"e1","eventName":"GetCallerIdentity","eventSource":"sts.amazonaws.com","eventTime":"2026-11-24T10:00:00Z"}`)
	e, err := ParseCloudTrailRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.RawHash != RawHash(raw) || e.ProviderOf() != ProviderAWS {
		t.Fatalf("hash %q provider %q", e.RawHash, e.ProviderOf())
	}
	if d := DeliveryFrom(context.Background()); d.Kind != DeliveryOther {
		t.Fatalf("default delivery %+v", d)
	}
	ctx := WithDelivery(context.Background(), Delivery{Kind: DeliveryAWSStream, Ref: "r"})
	if d := DeliveryFrom(ctx); d.Kind != DeliveryAWSStream || d.Ref != "r" {
		t.Fatalf("delivery %+v", d)
	}
}
