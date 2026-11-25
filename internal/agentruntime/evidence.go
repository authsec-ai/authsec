package agentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Evidence and coverage contracts (SPEC-secops-backend-upgrade W1): which
// provider an event id belongs to, which path delivered a batch, and the
// raw-record hash every parser sets.

// Providers: the namespace of an event id (Event.Provider). The same
// CloudTrail event delivered by the stream, the poller and a trail-bucket
// backfill has one id in ProviderAWS.
const (
	ProviderAWS   = "aws"
	ProviderAzure = "azure"
	ProviderK8s   = "k8s"
)

// Delivery kinds: the path a batch arrived by. They are also the source kinds
// of source_heartbeat and agent_evidence_event.source.
const (
	DeliveryAWSStream      = "aws_stream"      // POST /authsec/ingest/aws/events (EventBridge)
	DeliveryCloudTrailPoll = "cloudtrail_poll" // LookupEvents during a scan
	DeliveryTrailBackfill  = "trail_backfill"  // log files read from the trail's S3 bucket
	DeliveryAzureDiag      = "azure_diag"      // POST /authsec/ingest/azure/events (diagnostic settings)
	DeliveryK8sAudit       = "k8s_audit"       // POST /authsec/ingest/k8s/audit (iga-agent)
	DeliveryGateway        = "gateway"         // agent gateway decision log (not dispatched yet)
	DeliveryOther          = "other"           // a dispatch that did not say
)

// Delivery is how a dispatched batch arrived: its kind and the source's
// reference (a connector's region, a cluster), so a sink can keep a
// heartbeat per source.
type Delivery struct {
	Kind string
	// Ref names the source within the workspace, e.g. "connector/<id>" or
	// "connector/<id>/region/us-east-1". "" lets the sink derive it.
	Ref string
}

type deliveryKey struct{}

// WithDelivery marks ctx with the batch's delivery. The ingest, the poller
// and the backfill set it before agentruntime.Dispatch.
func WithDelivery(ctx context.Context, d Delivery) context.Context {
	return context.WithValue(ctx, deliveryKey{}, d)
}

// DeliveryFrom is ctx's delivery; Kind is DeliveryOther when none was set.
func DeliveryFrom(ctx context.Context) Delivery {
	if d, ok := ctx.Value(deliveryKey{}).(Delivery); ok && d.Kind != "" {
		return d
	}
	return Delivery{Kind: DeliveryOther}
}

// RawHash is sha256 of a raw record, lower-case hex.
func RawHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ProviderOf is e's id namespace ("" reads as AWS).
func (e Event) ProviderOf() string {
	if e.Provider == "" {
		return ProviderAWS
	}
	return e.Provider
}
