package services

import (
	"errors"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Who may decide an agent action: the principal the action is on behalf of
// (push approval, as with push MFA), or a member holding governance:approve.
// Any other member is refused (F3: any member could approve).
func TestMayDecideAgentAction(t *testing.T) {
	principal, other := uuid.New(), uuid.New()
	req := &models.AgentActionRequest{UserID: principal}
	holds := func(v bool, err error) (func() (bool, error), *int) {
		n := 0
		return func() (bool, error) { n++; return v, err }, &n
	}

	t.Run("principal decides their own agent's action", func(t *testing.T) {
		f, n := holds(false, nil)
		ok, err := mayDecideAgentAction(req, principal, f)
		if err != nil || !ok {
			t.Fatalf("principal: ok=%v err=%v, want allowed", ok, err)
		}
		if *n != 0 {
			t.Fatalf("principal needs no permission lookup, looked up %d times", *n)
		}
	})
	t.Run("member without governance:approve is refused", func(t *testing.T) {
		f, n := holds(false, nil)
		ok, err := mayDecideAgentAction(req, other, f)
		if err != nil || ok {
			t.Fatalf("plain member: ok=%v err=%v, want refused", ok, err)
		}
		if *n != 1 {
			t.Fatalf("permission looked up %d times, want 1", *n)
		}
	})
	t.Run("member holding governance:approve decides", func(t *testing.T) {
		f, _ := holds(true, nil)
		if ok, err := mayDecideAgentAction(req, other, f); err != nil || !ok {
			t.Fatalf("approver: ok=%v err=%v, want allowed", ok, err)
		}
	})
	t.Run("permission lookup failure fails closed", func(t *testing.T) {
		f, _ := holds(true, errors.New("db down"))
		if _, err := mayDecideAgentAction(req, other, f); err == nil {
			t.Fatal("lookup error swallowed")
		}
	})
	t.Run("nil approver is refused", func(t *testing.T) {
		f, _ := holds(true, nil)
		if ok, _ := mayDecideAgentAction(&models.AgentActionRequest{}, uuid.Nil, f); ok {
			t.Fatal("nil approver allowed (would match a request with a nil user_id)")
		}
	})
}
