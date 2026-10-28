package agentstream

import (
	"context"
	"log/slog"
)

// DefaultHandler is a basic Handler implementation that logs actions.
// Production code wires this to the CollectorSyncService and delivery pipeline.
type DefaultHandler struct {
	Logger *slog.Logger
}

// HandleHello validates the agent hello and logs the session start.
func (h *DefaultHandler) HandleHello(_ context.Context, sess *Session, hello Hello) error {
	h.Logger.Info("stream session started",
		"session_id", sess.ID,
		"collector_id", sess.Principal.CollectorID,
		"workspace_id", sess.Principal.WorkspaceID,
		"capability_digest", hello.CapabilityDigest,
		"schemas", hello.SupportedSchemas,
		"previous_acks", len(hello.PreviousAcks),
	)
	return nil
}

// HandleObservationBatch accepts an observation batch and returns an ack.
func (h *DefaultHandler) HandleObservationBatch(_ context.Context, sess *Session, batch ObservationBatch) (*BatchAck, error) {
	h.Logger.Info("observation batch received",
		"session_id", sess.ID,
		"batch_id", batch.BatchID,
		"observations", len(batch.Observations),
		"objects", len(batch.Objects),
	)
	return &BatchAck{
		BatchID:  batch.BatchID,
		Accepted: true,
	}, nil
}

// HandleAppliedReceipt records a policy application receipt.
func (h *DefaultHandler) HandleAppliedReceipt(_ context.Context, sess *Session, receipt AppliedReceipt) (*ReceiptAck, error) {
	h.Logger.Info("applied receipt received",
		"session_id", sess.ID,
		"manifest_id", receipt.ManifestID,
		"delivery_revision", receipt.DeliveryRevision,
		"applied", receipt.Applied,
	)
	return &ReceiptAck{
		ManifestID: receipt.ManifestID,
		Accepted:   true,
	}, nil
}

// HandleHealth logs the health status.
func (h *DefaultHandler) HandleHealth(_ context.Context, sess *Session, health Health) error {
	h.Logger.Debug("health ping",
		"session_id", sess.ID,
		"status", health.Status,
	)
	return nil
}

// SendDesiredManifest pushes a desired state manifest to the agent.
func SendDesiredManifest(sess *Session, manifest DesiredManifest) error {
	return sess.Send(StreamMessage{
		SchemaVersion: SchemaVersion,
		Kind:          KindDesiredManifest,
		MessageID:     sess.ID + "-manifest",
		Payload:       manifest,
	})
}

// SendRevocation pushes a revocation to the agent.
func SendRevocation(sess *Session, revocation Revocation) error {
	return sess.Send(StreamMessage{
		SchemaVersion: SchemaVersion,
		Kind:          KindRevocation,
		MessageID:     sess.ID + "-revoke",
		Payload:       revocation,
	})
}

// SendResumeRequired tells the agent to reconnect.
func SendResumeRequired(sess *Session, reason string) error {
	return sess.Send(StreamMessage{
		SchemaVersion: SchemaVersion,
		Kind:          KindResumeRequired,
		MessageID:     sess.ID + "-resume",
		Payload:       ResumeRequired{Reason: reason},
	})
}
