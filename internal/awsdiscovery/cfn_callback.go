package awsdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The CloudFormation custom-resource protocol, as it reaches AuthSec: the
// stack's Custom::AuthSecRegistration resource makes CloudFormation publish a
// request to AuthSec's SNS topic, SNS delivers it to AuthSec's SQS queue, and
// AuthSec answers by PUTting a JSON document to the presigned S3 URL the
// request carried. CloudFormation waits for that answer (up to the resource's
// ServiceTimeout) before continuing the stack.
//
// This file knows the protocol and nothing about AuthSec's policy: what to do
// with a request lives in services. Everything a message carries is
// attacker-controllable — the topic accepts publishes from any AWS account —
// so nothing parsed here is trusted beyond its shape.

// Names the callback resource carries in the template. Checked on every
// request so a message for any other custom resource is rejected outright.
const (
	RegistrationLogicalID    = "AuthSecRegistration"
	RegistrationResourceType = "Custom::AuthSecRegistration"
)

// CloudFormation request types.
const (
	CFNRequestCreate = "Create"
	CFNRequestUpdate = "Update"
	CFNRequestDelete = "Delete"
)

// CloudFormation response statuses.
const (
	CFNStatusSuccess = "SUCCESS"
	CFNStatusFailed  = "FAILED"
)

// cfnResponseMaxBytes is CloudFormation's own limit on a response body.
const cfnResponseMaxBytes = 4096

// cfnResponseTimeout bounds one PUT to the response URL.
const cfnResponseTimeout = 10 * time.Second

var (
	// ErrMalformedCallback means a message is not a well-formed CloudFormation
	// request for AuthSec's registration resource.
	ErrMalformedCallback = errors.New("malformed CloudFormation callback")
	// ErrResponseURLRejected means a request's ResponseURL is not one AuthSec
	// will contact. The URL is never requested when this is returned.
	ErrResponseURLRejected = errors.New("response URL rejected")
	// ErrResponseRejected means S3 refused the response with a 4xx: the
	// presigned URL expired or its signature does not match. Retrying cannot
	// help.
	ErrResponseRejected = errors.New("CloudFormation response URL refused the response")
)

// SNSEnvelope is the SNS notification SQS delivers when raw message delivery
// is off. TopicArn is why raw delivery stays off: it is how the worker knows
// which regional topic, and therefore which region, a request came through.
type SNSEnvelope struct {
	Type      string    `json:"Type"`
	MessageID string    `json:"MessageId"`
	TopicArn  string    `json:"TopicArn"`
	Message   string    `json:"Message"`
	Timestamp time.Time `json:"Timestamp"`
}

// ParseSNSEnvelope decodes an SQS message body as an SNS notification.
func ParseSNSEnvelope(body string) (*SNSEnvelope, error) {
	var env SNSEnvelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return nil, fmt.Errorf("%w: SNS envelope: %v", ErrMalformedCallback, err)
	}
	if env.Type != "Notification" || env.TopicArn == "" || env.Message == "" || env.Timestamp.IsZero() {
		return nil, fmt.Errorf("%w: not an SNS notification", ErrMalformedCallback)
	}
	return &env, nil
}

// RegistrationProperties are the ResourceProperties the template sends.
// ServiceToken and ServiceTimeout arrive too and are ignored.
type RegistrationProperties struct {
	RoleArn         string `json:"RoleArn"`
	ExternalID      string `json:"ExternalId"`
	AccountID       string `json:"AccountId"`
	TemplateVersion string `json:"TemplateVersion"`
}

// CFNRequest is a custom-resource request, reduced to the fields AuthSec uses.
type CFNRequest struct {
	RequestType        string                 `json:"RequestType"`
	RequestID          string                 `json:"RequestId"`
	StackID            string                 `json:"StackId"`
	ResponseURL        string                 `json:"ResponseURL"`
	ResourceType       string                 `json:"ResourceType"`
	LogicalResourceID  string                 `json:"LogicalResourceId"`
	PhysicalResourceID string                 `json:"PhysicalResourceId"`
	ResourceProperties RegistrationProperties `json:"ResourceProperties"`
}

// ParseCFNRequest decodes and shape-checks a request for AuthSec's
// registration resource.
func ParseCFNRequest(message string) (*CFNRequest, error) {
	var req CFNRequest
	if err := json.Unmarshal([]byte(message), &req); err != nil {
		return nil, fmt.Errorf("%w: request: %v", ErrMalformedCallback, err)
	}
	switch req.RequestType {
	case CFNRequestCreate, CFNRequestUpdate, CFNRequestDelete:
	default:
		return nil, fmt.Errorf("%w: unknown RequestType %q", ErrMalformedCallback, req.RequestType)
	}
	if req.LogicalResourceID != RegistrationLogicalID || req.ResourceType != RegistrationResourceType {
		return nil, fmt.Errorf("%w: not the %s resource", ErrMalformedCallback, RegistrationLogicalID)
	}
	if req.RequestID == "" || req.StackID == "" || req.ResponseURL == "" {
		return nil, fmt.Errorf("%w: missing RequestId, StackId or ResponseURL", ErrMalformedCallback)
	}
	return &req, nil
}

// stackIDPattern matches a CloudFormation stack ARN.
var stackIDPattern = regexp.MustCompile(
	`^arn:(aws|aws-us-gov|aws-cn):cloudformation:([a-z0-9-]+):(\d{12}):stack/[A-Za-z][A-Za-z0-9-]*/[A-Za-z0-9-]+$`)

// StackRef is what a StackId says about where the stack lives.
type StackRef struct {
	Partition string
	Region    string
	AccountID string
}

// ParseStackID extracts the partition, region and account from a stack ARN.
func ParseStackID(stackID string) (StackRef, error) {
	m := stackIDPattern.FindStringSubmatch(stackID)
	if m == nil {
		return StackRef{}, fmt.Errorf("%w: %q is not a stack ARN", ErrMalformedCallback, stackID)
	}
	return StackRef{Partition: m[1], Region: m[2], AccountID: m[3]}, nil
}

// snsTopicPattern matches an SNS topic ARN.
var snsTopicPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):sns:([a-z0-9-]+):(\d{12}):([A-Za-z0-9_-]{1,256})$`)

// ParseTopicARN extracts the partition and region from an SNS topic ARN.
func ParseTopicARN(arn string) (partition, region string, err error) {
	m := snsTopicPattern.FindStringSubmatch(arn)
	if m == nil {
		return "", "", fmt.Errorf("%q is not an SNS topic ARN", arn)
	}
	return m[1], m[2], nil
}

/* ------------------------------ response URL ------------------------------ */

// responseHostForms are the ResponseURL host shapes AuthSec will contact.
//
// Every form here must be backed by a captured, real ResponseURL in
// testdata/cfn_response_urls, and nothing is added on a guess. The response
// bucket names its region WITHOUT dashes (useast1, not us-east-1), which is
// exactly the detail a guessed pattern gets wrong. A real callback whose host
// matches no form is not contacted: it lands in the DLQ with an alarm, and the
// form is added here together with its fixture after review.
//
// Known so far:
//   - `.s3.{region}.` — captured live in ap-south-1 (2026-09-24). This is what
//     CloudFormation sends today.
//   - `.s3-{region}.` — the legacy form in AWS's own Lambda/CloudFormation
//     documentation example (us-west-2). Kept because AWS documents it, not
//     because it has been seen live.
var responseHostForms = []func(region, compact string) string{
	func(region, compact string) string {
		return "cloudformation-custom-resource-response-" + compact + ".s3." + region + ".amazonaws.com"
	},
	func(region, compact string) string {
		return "cloudformation-custom-resource-response-" + compact + ".s3-" + region + ".amazonaws.com"
	},
}

// CFNResponseHosts returns the exact hosts a ResponseURL for a stack in region
// may use.
func CFNResponseHosts(region string) []string {
	compact := strings.ReplaceAll(region, "-", "")
	hosts := make([]string, 0, len(responseHostForms))
	for _, form := range responseHostForms {
		hosts = append(hosts, form(region, compact))
	}
	return hosts
}

// ValidateResponseURL decides whether AuthSec may PUT to a request's
// ResponseURL. stackRegion is the region parsed from the request's StackId.
//
// The URL comes from a message anyone can publish, so an unchecked PUT would
// let a forger aim AuthSec's backend at any host. Hosts are compared by exact
// string equality against CFNResponseHosts — never a suffix or pattern match,
// which is how `…amazonaws.com.evil.example` gets through.
func ValidateResponseURL(raw, stackRegion string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: unparseable", ErrResponseURLRejected)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrResponseURLRejected, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo present", ErrResponseURLRejected)
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, fmt.Errorf("%w: port %s", ErrResponseURLRejected, p)
	}
	host := strings.ToLower(u.Hostname())
	allowed := false
	for _, h := range CFNResponseHosts(stackRegion) {
		if host == h {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("%w: host %q is not a CloudFormation response host for %s",
			ErrResponseURLRejected, host, stackRegion)
	}
	if u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("%w: no object path", ErrResponseURLRejected)
	}
	q := u.Query()
	if q.Get("X-Amz-Signature") == "" && (q.Get("Signature") == "" || q.Get("Expires") == "") {
		return nil, fmt.Errorf("%w: not a presigned URL", ErrResponseURLRejected)
	}
	return u, nil
}

// RedactedURL is a URL safe to log: scheme, host and path only. The query of
// a ResponseURL is a presigned write credential and must never be logged.
func RedactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

/* -------------------------------- response -------------------------------- */

// CFNResponse is the document CloudFormation expects at the ResponseURL.
type CFNResponse struct {
	Status             string            `json:"Status"`
	Reason             string            `json:"Reason,omitempty"`
	PhysicalResourceID string            `json:"PhysicalResourceId"`
	StackID            string            `json:"StackId"`
	RequestID          string            `json:"RequestId"`
	LogicalResourceID  string            `json:"LogicalResourceId"`
	Data               map[string]string `json:"Data,omitempty"`
}

// NewCFNResponse answers req. StackId, RequestId and LogicalResourceId are
// copied verbatim, as CloudFormation requires.
func NewCFNResponse(req *CFNRequest, status, reason, physicalID string) CFNResponse {
	return CFNResponse{
		Status:             status,
		Reason:             reason,
		PhysicalResourceID: physicalID,
		StackID:            req.StackID,
		RequestID:          req.RequestID,
		LogicalResourceID:  req.LogicalResourceID,
	}
}

// Encode marshals the response inside CloudFormation's 4096-byte limit,
// shortening Reason when it would not fit. Everything else is fixed-size or
// copied from the request, so Reason is the only field worth giving up.
func (r CFNResponse) Encode() ([]byte, error) {
	for {
		body, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if len(body) <= cfnResponseMaxBytes {
			return body, nil
		}
		if r.Reason == "" {
			return nil, fmt.Errorf("CloudFormation response is %d bytes even without a reason", len(body))
		}
		cut := len(r.Reason) - (len(body) - cfnResponseMaxBytes) - 3
		if cut < 0 {
			cut = 0
		}
		r.Reason = r.Reason[:cut] + "..."
	}
}

// NewCFNResponseClient returns the HTTP client for response PUTs: short
// timeout, and redirects never followed. A presigned S3 PUT has no legitimate
// reason to redirect, and following one would undo ValidateResponseURL.
func NewCFNResponseClient() *http.Client {
	return &http.Client{
		Timeout: cfnResponseTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SendCFNResponse PUTs a response to an already-validated ResponseURL.
//
// No Content-Type header: the URL is presigned without one, and S3 rejects a
// PUT whose headers differ from what was signed. A 4xx is ErrResponseRejected
// (retrying cannot help); a 5xx or transport error is returned as-is, and the
// caller retries.
func SendCFNResponse(ctx context.Context, client *http.Client, target *url.URL, resp CFNResponse) error {
	body, err := resp.Encode()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	res, err := client.Do(req)
	if err != nil {
		// *url.Error's message embeds the full request URL, presigned query and
		// all. Keep only the cause, so the signature can never reach a log line
		// through this error.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("response PUT to %s: %v", RedactedURL(target), err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return nil
	case res.StatusCode >= 400 && res.StatusCode < 500:
		return fmt.Errorf("%w: HTTP %d from %s", ErrResponseRejected, res.StatusCode, RedactedURL(target))
	default:
		return fmt.Errorf("response PUT to %s: HTTP %d", RedactedURL(target), res.StatusCode)
	}
}
