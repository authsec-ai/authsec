package agentstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Flow control defaults.
const (
	MaxBatchEvents       = 500
	MaxBatchBytes        = 1 << 20 // 1 MiB
	LivenessPingInterval = 30 * time.Second
	SessionTimeout       = 5 * time.Minute
)

var (
	ErrSessionClosed   = errors.New("agentstream: session closed")
	ErrFlowControl     = errors.New("agentstream: flow control limit exceeded")
	ErrInvalidMessage  = errors.New("agentstream: invalid message")
	ErrUnauthenticated = errors.New("agentstream: unauthenticated")
)

// Principal identifies the authenticated caller.
type Principal struct {
	WorkspaceID  string
	CollectorID  string
	SPIFFEURI    string
	IdentityMode string
}

// Session represents a single agent stream connection.
type Session struct {
	ID        string
	Principal Principal
	CreatedAt time.Time
	LastPingAt time.Time

	mu       sync.Mutex
	sequence int64
	closed   bool
	sendCh   chan StreamMessage
	recvCh   chan StreamMessage
}

// NewSession creates a new stream session.
func NewSession(principal Principal) *Session {
	return &Session{
		ID:         uuid.New().String(),
		Principal:  principal,
		CreatedAt:  time.Now(),
		LastPingAt: time.Now(),
		sendCh:     make(chan StreamMessage, 64),
		recvCh:     make(chan StreamMessage, 64),
	}
}

// Send queues a message to the agent.
func (s *Session) Send(msg StreamMessage) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	s.sequence++
	msg.Sequence = s.sequence
	msg.StreamSessionID = s.ID
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}
	s.mu.Unlock()

	select {
	case s.sendCh <- msg:
		return nil
	default:
		return ErrFlowControl
	}
}

// Receive returns the next inbound message from the agent.
func (s *Session) Receive(ctx context.Context) (StreamMessage, error) {
	select {
	case msg := <-s.recvCh:
		return msg, nil
	case <-ctx.Done():
		return StreamMessage{}, ctx.Err()
	}
}

// Close terminates the session.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.sendCh)
	}
}

// IsClosed returns whether the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Server manages active stream sessions.
type Server struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	handler  Handler
}

// Handler processes stream messages from agents.
type Handler interface {
	HandleHello(ctx context.Context, session *Session, hello Hello) error
	HandleObservationBatch(ctx context.Context, session *Session, batch ObservationBatch) (*BatchAck, error)
	HandleAppliedReceipt(ctx context.Context, session *Session, receipt AppliedReceipt) (*ReceiptAck, error)
	HandleHealth(ctx context.Context, session *Session, health Health) error
}

// NewServer creates a new stream server.
func NewServer(handler Handler) *Server {
	return &Server{
		sessions: make(map[string]*Session),
		handler:  handler,
	}
}

// AcceptSession registers a new session for an authenticated principal.
func (srv *Server) AcceptSession(principal Principal) (*Session, error) {
	if principal.WorkspaceID == "" || principal.CollectorID == "" {
		return nil, ErrUnauthenticated
	}
	sess := NewSession(principal)
	srv.mu.Lock()
	srv.sessions[sess.ID] = sess
	srv.mu.Unlock()
	return sess, nil
}

// GetSession retrieves a session by ID.
func (srv *Server) GetSession(id string) (*Session, bool) {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	s, ok := srv.sessions[id]
	return s, ok
}

// RemoveSession removes and closes a session.
func (srv *Server) RemoveSession(id string) {
	srv.mu.Lock()
	if s, ok := srv.sessions[id]; ok {
		s.Close()
		delete(srv.sessions, id)
	}
	srv.mu.Unlock()
}

// ActiveSessionCount returns the number of active sessions.
func (srv *Server) ActiveSessionCount() int {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	return len(srv.sessions)
}

// DispatchInbound routes an inbound message to the appropriate handler.
func (srv *Server) DispatchInbound(ctx context.Context, sess *Session, raw []byte) error {
	var msg StreamMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}

	switch msg.Kind {
	case KindHello:
		data, _ := json.Marshal(msg.Payload)
		var hello Hello
		if err := json.Unmarshal(data, &hello); err != nil {
			return fmt.Errorf("%w: hello payload: %v", ErrInvalidMessage, err)
		}
		return srv.handler.HandleHello(ctx, sess, hello)

	case KindObservationBatch:
		data, _ := json.Marshal(msg.Payload)
		var batch ObservationBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return fmt.Errorf("%w: batch payload: %v", ErrInvalidMessage, err)
		}
		ack, err := srv.handler.HandleObservationBatch(ctx, sess, batch)
		if err != nil {
			return err
		}
		if ack != nil {
			return sess.Send(StreamMessage{
				SchemaVersion: SchemaVersion,
				Kind:          KindBatchAck,
				MessageID:     uuid.New().String(),
				Payload:       ack,
			})
		}
		return nil

	case KindAppliedReceipt:
		data, _ := json.Marshal(msg.Payload)
		var receipt AppliedReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return fmt.Errorf("%w: receipt payload: %v", ErrInvalidMessage, err)
		}
		ack, err := srv.handler.HandleAppliedReceipt(ctx, sess, receipt)
		if err != nil {
			return err
		}
		if ack != nil {
			return sess.Send(StreamMessage{
				SchemaVersion: SchemaVersion,
				Kind:          KindReceiptAck,
				MessageID:     uuid.New().String(),
				Payload:       ack,
			})
		}
		return nil

	case KindHealth:
		data, _ := json.Marshal(msg.Payload)
		var health Health
		if err := json.Unmarshal(data, &health); err != nil {
			return fmt.Errorf("%w: health payload: %v", ErrInvalidMessage, err)
		}
		sess.mu.Lock()
		sess.LastPingAt = time.Now()
		sess.mu.Unlock()
		return srv.handler.HandleHealth(ctx, sess, health)

	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidMessage, msg.Kind)
	}
}
