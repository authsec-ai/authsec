package agentruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Pushed collectors (SPEC-secops-backend-upgrade W1, C1): Azure diagnostic
// settings records (Event Hub push format) and Kubernetes audit events
// (audit.k8s.io/v1 EventList from the iga-agent), normalised into Event.
//
// Only metadata is read: who, what operation, on what, from where, with what
// result. Request and response objects (a Kubernetes audit event at level
// Request/RequestResponse carries them; an Azure record's properties can
// carry request bodies) are never read, so a secret or a prompt can never
// reach an Event.

// Fact keys used by the collectors (Event.RequestFacts).
const (
	FactNamespace        = "namespace"         // Kubernetes objectRef.namespace
	FactImpersonatedUser = "impersonated_user" // Kubernetes impersonatedUser.username
	FactCorrelationID    = "correlation_id"    // Azure correlationId
	FactAppID            = "app_id"            // Azure application (client) id
)

// ErrCollectorBody: not a body the collector accepts.
var ErrCollectorBody = errors.New("unsupported body")

const maxCollectorString = 2048

func clip(s string) string {
	if len(s) > maxCollectorString {
		return s[:maxCollectorString]
	}
	return s
}

/* --------------------------------- Azure --------------------------------- */

// AzureRecord is one parsed diagnostic record: the event, or why it was
// refused, and the tenant the record states ("" when it states none).
type AzureRecord struct {
	Event    Event
	TenantID string
	Err      error
}

type azureRaw struct {
	Time            string          `json:"time"`
	ResourceID      string          `json:"resourceId"`
	OperationName   string          `json:"operationName"`
	Category        string          `json:"category"`
	ResultType      string          `json:"resultType"`
	ResultSignature string          `json:"resultSignature"`
	CallerIPAddress string          `json:"callerIpAddress"`
	CorrelationID   string          `json:"correlationId"`
	TenantID        string          `json:"tenantId"`
	Location        string          `json:"location"`
	ID              string          `json:"id"`
	EventDataID     string          `json:"eventDataId"`
	Identity        json.RawMessage `json:"identity"`
	Properties      json.RawMessage `json:"properties"`
}

// azureProps are the few properties read (sign-in, audit and activity
// records); everything else in properties is ignored.
type azureProps struct {
	ID                   string `json:"id"`
	EventDataID          string `json:"eventDataId"`
	UserPrincipalName    string `json:"userPrincipalName"`
	UserID               string `json:"userId"`
	AppID                string `json:"appId"`
	AppDisplayName       string `json:"appDisplayName"`
	ServicePrincipalID   string `json:"servicePrincipalId"`
	ServicePrincipalName string `json:"servicePrincipalName"`
	IPAddress            string `json:"ipAddress"`
	StatusCode           string `json:"statusCode"`
	Status               *struct {
		ErrorCode json.Number `json:"errorCode"`
	} `json:"status"`
	InitiatedBy *struct {
		User *struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"user"`
		App *struct {
			ServicePrincipalID string `json:"servicePrincipalId"`
			DisplayName        string `json:"displayName"`
			AppID              string `json:"appId"`
		} `json:"app"`
	} `json:"initiatedBy"`
}

const (
	claimOID   = "http://schemas.microsoft.com/identity/claims/objectidentifier"
	claimUPN   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
	claimName  = "name"
	claimAppID = "appid"
)

// SplitAzureBody splits a diagnostic-settings push into raw records: an
// object {"records": [...]} (what Event Hub carries), or an array of such
// objects (a batch of Event Hub messages).
func SplitAzureBody(body []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, ErrCollectorBody
	}
	type envelope struct {
		Records []json.RawMessage `json:"records"`
	}
	switch trimmed[0] {
	case '{':
		var env envelope
		if err := json.Unmarshal(trimmed, &env); err != nil || env.Records == nil {
			return nil, ErrCollectorBody
		}
		return env.Records, nil
	case '[':
		var envs []envelope
		if err := json.Unmarshal(trimmed, &envs); err != nil || len(envs) == 0 {
			return nil, ErrCollectorBody
		}
		var out []json.RawMessage
		for _, env := range envs {
			if env.Records == nil {
				return nil, ErrCollectorBody
			}
			out = append(out, env.Records...)
		}
		return out, nil
	}
	return nil, ErrCollectorBody
}

// ParseAzureRecord normalises one diagnostic record (Activity log,
// Entra sign-in or audit log).
func ParseAzureRecord(raw json.RawMessage) AzureRecord {
	var r azureRaw
	if err := json.Unmarshal(raw, &r); err != nil {
		return AzureRecord{Err: err}
	}
	if r.OperationName == "" || r.Time == "" {
		return AzureRecord{Err: errors.New("azure record: missing operationName or time")}
	}
	t, err := time.Parse(time.RFC3339Nano, r.Time)
	if err != nil {
		return AzureRecord{Err: errors.New("azure record: bad time")}
	}
	var p azureProps
	if len(r.Properties) > 0 && r.Properties[0] == '{' {
		_ = json.Unmarshal(r.Properties, &p) // unreadable properties: metadata only
	}
	e := Event{
		Provider: ProviderAzure, RawHash: RawHash(raw),
		EventTime: t.UTC(), EventName: clip(r.OperationName), EventCategory: r.Category,
		SourceIP: r.CallerIPAddress, Region: r.Location,
	}
	// The id: the record's own id, else the activity log's event data id,
	// else the record's hash (an identical redelivery is still one event).
	switch {
	case p.ID != "":
		e.EventID = p.ID
	case r.ID != "" && !strings.HasPrefix(r.ID, "/"):
		e.EventID = r.ID
	case r.EventDataID != "":
		e.EventID = r.EventDataID
	case p.EventDataID != "":
		e.EventID = p.EventDataID
	default:
		e.EventID = "sha256:" + e.RawHash
	}
	if e.SourceIP == "" {
		e.SourceIP = p.IPAddress
	}
	cat := strings.ToLower(r.Category)
	setFact := func(k, v string) {
		if v == "" {
			return
		}
		if e.RequestFacts == nil {
			e.RequestFacts = map[string]string{}
		}
		e.RequestFacts[k] = clip(v)
	}
	setFact(FactCorrelationID, r.CorrelationID)
	switch {
	case strings.Contains(cat, "signinlogs"):
		e.EventType, e.EventSource = "AzureSignIn", "azure:entra-signin"
		switch cat {
		case "serviceprincipalsigninlogs":
			e.PrincipalType = "ServicePrincipal"
		case "managedidentitysigninlogs":
			e.PrincipalType = "ManagedIdentity"
		default:
			e.PrincipalType = "User"
		}
		if p.ServicePrincipalID != "" && e.PrincipalType != "User" {
			e.PrincipalID, e.PrincipalARN = p.ServicePrincipalID, p.ServicePrincipalName
		} else {
			e.PrincipalID, e.PrincipalARN = p.UserID, p.UserPrincipalName
		}
		setFact(FactAppID, p.AppID)
		ro := true
		e.ReadOnly = &ro
		code := r.ResultType
		if p.Status != nil && p.Status.ErrorCode.String() != "" {
			code = p.Status.ErrorCode.String()
		}
		if code != "" && code != "0" && !strings.EqualFold(code, "success") {
			e.ErrorCode = clip(code)
		}
	case cat == "auditlogs":
		e.EventType, e.EventSource = "AzureAudit", "azure:entra-audit"
		if ib := p.InitiatedBy; ib != nil {
			switch {
			case ib.User != nil && ib.User.ID != "":
				e.PrincipalType, e.PrincipalID, e.PrincipalARN = "User", ib.User.ID, ib.User.UserPrincipalName
			case ib.App != nil && ib.App.ServicePrincipalID != "":
				e.PrincipalType, e.PrincipalID, e.PrincipalARN = "ServicePrincipal", ib.App.ServicePrincipalID, ib.App.DisplayName
				setFact(FactAppID, ib.App.AppID)
			}
		}
		if rt := strings.ToLower(r.ResultType); rt != "" && rt != "success" && rt != "0" {
			e.ErrorCode = clip(r.ResultType)
		}
	default:
		e.EventType = "AzureActivity"
		ns := r.OperationName
		if i := strings.Index(ns, "/"); i > 0 {
			ns = ns[:i]
		}
		e.EventSource = "azure:" + strings.ToLower(clip(ns))
		lop := strings.ToLower(r.OperationName)
		ro := strings.HasSuffix(lop, "/read")
		if strings.HasSuffix(lop, "/read") || strings.HasSuffix(lop, "/write") || strings.HasSuffix(lop, "/delete") || strings.HasSuffix(lop, "/action") {
			e.ReadOnly = &ro
		}
		claims := azureClaims(r.Identity)
		e.PrincipalID = claims[claimOID]
		if e.PrincipalID == "" {
			e.PrincipalID = claims["oid"]
		}
		switch {
		case claims[claimUPN] != "":
			e.PrincipalType, e.PrincipalARN = "User", claims[claimUPN]
		case claims[claimAppID] != "":
			e.PrincipalType, e.PrincipalARN = "ServicePrincipal", claims[claimAppID]
			setFact(FactAppID, claims[claimAppID])
		case claims[claimName] != "":
			e.PrincipalType, e.PrincipalARN = "User", claims[claimName]
		}
		if strings.EqualFold(claims["idtyp"], "app") {
			e.PrincipalType = "ServicePrincipal"
		}
		if strings.EqualFold(r.ResultType, "Failure") || strings.EqualFold(r.ResultType, "Failed") {
			e.ErrorCode = clip(firstNonEmpty(p.StatusCode, r.ResultSignature, r.ResultType))
			sig := strings.ToLower(p.StatusCode + " " + r.ResultSignature)
			e.AuthorizationDenied = strings.Contains(sig, "forbidden") || strings.Contains(sig, "authorizationfailed")
		}
	}
	e.PrincipalID, e.PrincipalARN = clip(e.PrincipalID), clip(e.PrincipalARN)
	if r.ResourceID != "" {
		e.Resources = []string{clip(r.ResourceID)}
	}
	e.AccountID = r.TenantID
	if e.AccountID == "" {
		e.AccountID = azureSubscription(r.ResourceID)
	}
	return AzureRecord{Event: e, TenantID: strings.ToLower(strings.TrimSpace(r.TenantID))}
}

// azureClaims reads identity.claims as strings; identity may be a string
// (sign-in records) or absent.
func azureClaims(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 || raw[0] != '{' {
		return out
	}
	var id struct {
		Claims map[string]json.RawMessage `json:"claims"`
	}
	if json.Unmarshal(raw, &id) != nil {
		return out
	}
	for k, v := range id.Claims {
		var s string
		if json.Unmarshal(v, &s) == nil {
			out[k] = s
		}
	}
	return out
}

// azureSubscription is the subscription id of an ARM resource id.
func azureSubscription(resourceID string) string {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "subscriptions") {
			return strings.ToLower(parts[i+1])
		}
	}
	return ""
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

/* ------------------------------- Kubernetes ------------------------------- */

// K8sAuditRecord is one parsed audit event, or why it was refused. Skipped
// is set for a stage that is not the final one (each request is logged at
// several stages; only ResponseComplete and Panic are kept).
type K8sAuditRecord struct {
	Event   Event
	Skipped bool
	Err     error
}

type k8sAuditRaw struct {
	AuditID string `json:"auditID"`
	Stage   string `json:"stage"`
	Verb    string `json:"verb"`
	User    struct {
		Username string `json:"username"`
		UID      string `json:"uid"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	RequestReceivedTimestamp string            `json:"requestReceivedTimestamp"`
	StageTimestamp           string            `json:"stageTimestamp"`
	Annotations              map[string]string `json:"annotations"`
}

// SplitK8sAuditBody splits an audit.k8s.io/v1 EventList (or a bare array of
// audit events) into raw events.
func SplitK8sAuditBody(body []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, ErrCollectorBody
	}
	switch trimmed[0] {
	case '{':
		var list struct {
			Kind       string            `json:"kind"`
			APIVersion string            `json:"apiVersion"`
			Items      []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(trimmed, &list); err != nil || list.Kind != "EventList" ||
			!strings.HasPrefix(list.APIVersion, "audit.k8s.io/") || list.Items == nil {
			return nil, ErrCollectorBody
		}
		return list.Items, nil
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil || len(arr) == 0 {
			return nil, ErrCollectorBody
		}
		return arr, nil
	}
	return nil, ErrCollectorBody
}

// ParseK8sAuditEvent normalises one audit event of the cluster named
// cluster (AccountID).
func ParseK8sAuditEvent(raw json.RawMessage, cluster string) K8sAuditRecord {
	var r k8sAuditRaw
	if err := json.Unmarshal(raw, &r); err != nil {
		return K8sAuditRecord{Err: err}
	}
	if r.AuditID == "" || r.Verb == "" {
		return K8sAuditRecord{Err: errors.New("audit event: missing auditID or verb")}
	}
	if r.Stage != "" && r.Stage != "ResponseComplete" && r.Stage != "Panic" {
		return K8sAuditRecord{Skipped: true}
	}
	ts := r.StageTimestamp
	if r.RequestReceivedTimestamp != "" {
		ts = r.RequestReceivedTimestamp
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return K8sAuditRecord{Err: errors.New("audit event: bad timestamp")}
	}
	e := Event{
		Provider: ProviderK8s, RawHash: RawHash(raw),
		EventID: clip(r.AuditID), EventTime: t.UTC(), EventType: "K8sAudit",
		EventCategory: "Management", AccountID: cluster, UserAgent: clip(r.UserAgent),
		PrincipalARN: clip(r.User.Username), PrincipalID: clip(r.User.UID),
	}
	if r.Stage == "Panic" {
		e.EventID = clip(r.AuditID + "/Panic")
	}
	switch {
	case strings.HasPrefix(r.User.Username, "system:serviceaccount:"):
		e.PrincipalType = "ServiceAccount"
	case strings.HasPrefix(r.User.Username, "system:node:"):
		e.PrincipalType = "Node"
	default:
		e.PrincipalType = "User"
	}
	if len(r.SourceIPs) > 0 {
		e.SourceIP = r.SourceIPs[0]
	}
	group, name := "core", r.Verb
	if o := r.ObjectRef; o != nil {
		if o.APIGroup != "" {
			group = o.APIGroup
		}
		res := o.Resource
		if o.Subresource != "" {
			res += "/" + o.Subresource
		}
		if res != "" {
			name = r.Verb + " " + res
		}
		ref := "k8s:" + cluster + "/" + o.Namespace + "/" + res + "/" + o.Name
		e.Resources = []string{clip(ref)}
		if o.Namespace != "" {
			e.RequestFacts = map[string]string{FactNamespace: clip(o.Namespace)}
		}
	}
	e.EventSource, e.EventName = "k8s:"+clip(group), clip(name)
	ro := r.Verb == "get" || r.Verb == "list" || r.Verb == "watch"
	e.ReadOnly = &ro
	if r.ImpersonatedUser != nil && r.ImpersonatedUser.Username != "" {
		if e.RequestFacts == nil {
			e.RequestFacts = map[string]string{}
		}
		e.RequestFacts[FactImpersonatedUser] = clip(r.ImpersonatedUser.Username)
	}
	if r.ResponseStatus != nil && r.ResponseStatus.Code >= 400 {
		e.ErrorCode = strconv.Itoa(r.ResponseStatus.Code)
		e.AuthorizationDenied = r.ResponseStatus.Code == 403
	}
	if r.Annotations["authorization.k8s.io/decision"] == "forbid" {
		e.AuthorizationDenied = true
		if e.ErrorCode == "" {
			e.ErrorCode = "403"
		}
	}
	return K8sAuditRecord{Event: e}
}
