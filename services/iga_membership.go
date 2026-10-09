package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/database"
	"github.com/google/uuid"
)

// Membership: who exists in a workspace, for routing reviews, recording
// decisions and checking who may answer for whom.
//
// IGA reads this through an INTERFACE and never by querying a legacy table.
// Nothing in the database enforces that -- IGA runs in the same process against
// the same `public` schema, so a `JOIN users` would work -- which is exactly
// why the boundary has to be visible. scripts/ci-iga-isolation-check.sh fails
// the build if an IGA file names one.
//
// The point is not purity. It is that a dependency spelled out as an interface
// is one an implementer can see, fake in a test, and carry across a later
// database split; a dependency spelled out as a table name is invisible until
// the split, and then it is a rewrite.

var (
	// ErrMembershipUnavailable means the authority could not be reached. A
	// MUTATION must fail on this. Recording a review decision against
	// membership nobody can currently confirm produces an audit record that
	// cannot be defended.
	ErrMembershipUnavailable = errors.New("membership authority unavailable")

	// ErrMembershipStale means the cached snapshot is older than the ceiling.
	// Same rule: reads may proceed with a banner, mutations may not.
	ErrMembershipStale = errors.New("membership snapshot is too old to act on")

	ErrNotAMember = errors.New("not a member of this workspace")
)

const (
	// How long a snapshot is served before it is re-read.
	membershipCacheTTL = 5 * time.Minute
	// Past this, a snapshot may still be READ (with a staleness banner) but
	// must not be used to authorise a change. Chosen well above the TTL so it
	// only bites during a real outage, not a slow refresh.
	membershipStaleCeiling = 60 * time.Minute
	// A workspace with more members than this is paged; the cap exists so one
	// enormous workspace cannot make every review page slow.
	membershipPageCap = 2000
)

// Member is one person who can be a reviewer, an owner or an actor.
//
// Deliberately narrow. IGA needs to know that someone exists, how to name them
// and whether they are active; it does not need their password state, MFA
// enrolment or sync provenance, and copying those here would make the seam
// wider than the question it answers.
type Member struct {
	SubjectID   uuid.UUID `json:"subject_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Active      bool      `json:"active"`
}

// MembershipSnapshot is the answer at a moment, with that moment attached.
//
// SnapshotAt is not decoration: a caller has to be able to say "this is what
// membership looked like at 14:02" rather than "this is membership", because
// during an outage those are different claims.
type MembershipSnapshot struct {
	Members    []Member
	SnapshotAt time.Time
}

// Age reports how old this snapshot is.
func (s MembershipSnapshot) Age(now time.Time) time.Duration { return now.Sub(s.SnapshotAt) }

// Stale reports whether this snapshot is too old to authorise a change.
func (s MembershipSnapshot) Stale(now time.Time) bool { return s.Age(now) > membershipStaleCeiling }

// MembershipAuthority answers who exists. Implemented by the legacy side, which
// holds the connection to the membership tables.
type MembershipAuthority interface {
	// Members returns everyone in the workspace, newest first.
	Members(ctx context.Context, workspaceID uuid.UUID) (MembershipSnapshot, error)
	// Member returns one, or ErrNotAMember.
	Member(ctx context.Context, workspaceID, subjectID uuid.UUID) (Member, error)
	// CanAct reports whether this subject may be recorded as having made a
	// decision. False for anyone inactive or absent.
	//
	// Separate from Member so the caller cannot accidentally treat "found" as
	// "allowed": an offboarded user is still found.
	CanAct(ctx context.Context, workspaceID, subjectID uuid.UUID) error
}

// legacyMembership reads the existing users table through the legacy
// repository. It is the ONLY place in the IGA path that touches it, and it sits
// on the legacy side of the interface deliberately.
type legacyMembership struct {
	users *database.UserRepository

	mu    sync.Mutex
	cache map[uuid.UUID]MembershipSnapshot
	now   func() time.Time
}

// NewLegacyMembershipAuthority wires IGA to the existing user store.
func NewLegacyMembershipAuthority(users *database.UserRepository) MembershipAuthority {
	return &legacyMembership{
		users: users,
		cache: map[uuid.UUID]MembershipSnapshot{},
		now:   time.Now,
	}
}

func (m *legacyMembership) Members(
	ctx context.Context, workspaceID uuid.UUID,
) (MembershipSnapshot, error) {
	if workspaceID == uuid.Nil {
		return MembershipSnapshot{}, errors.New("workspace_id is required")
	}
	now := m.now()

	m.mu.Lock()
	cached, ok := m.cache[workspaceID]
	m.mu.Unlock()
	if ok && cached.Age(now) < membershipCacheTTL {
		return cached, nil
	}

	rows, err := m.users.GetUsersByWorkspaceID(workspaceID, membershipPageCap, 0)
	if err != nil {
		// Serve the stale snapshot rather than nothing: browsing an inventory
		// may continue during an outage. The caller decides whether its own
		// operation is allowed on data this old -- see CanAct.
		if ok {
			return cached, nil
		}
		return MembershipSnapshot{}, fmt.Errorf("%w: %v", ErrMembershipUnavailable, err)
	}

	snapshot := MembershipSnapshot{SnapshotAt: now, Members: make([]Member, 0, len(rows))}
	for _, u := range rows {
		if u == nil {
			continue
		}
		snapshot.Members = append(snapshot.Members, Member{
			SubjectID:   u.ID,
			Email:       u.Email,
			DisplayName: u.Name,
			Active:      u.Active,
		})
	}

	m.mu.Lock()
	m.cache[workspaceID] = snapshot
	m.mu.Unlock()
	return snapshot, nil
}

func (m *legacyMembership) Member(
	ctx context.Context, workspaceID, subjectID uuid.UUID,
) (Member, error) {
	snapshot, err := m.Members(ctx, workspaceID)
	if err != nil {
		return Member{}, err
	}
	for _, mem := range snapshot.Members {
		if mem.SubjectID == subjectID {
			return mem, nil
		}
	}
	return Member{}, ErrNotAMember
}

func (m *legacyMembership) CanAct(
	ctx context.Context, workspaceID, subjectID uuid.UUID,
) error {
	snapshot, err := m.Members(ctx, workspaceID)
	if err != nil {
		return err
	}
	// FAIL CLOSED on a stale snapshot.
	//
	// A review decision recorded against membership we cannot currently confirm
	// is an audit record nobody can defend later: the whole value of the record
	// is that the person was entitled to make it AT THE TIME, and an hour-old
	// snapshot cannot establish that.
	if snapshot.Stale(m.now()) {
		return fmt.Errorf("%w: snapshot is %s old", ErrMembershipStale,
			snapshot.Age(m.now()).Round(time.Second))
	}
	for _, mem := range snapshot.Members {
		if mem.SubjectID == subjectID {
			if !mem.Active {
				return fmt.Errorf("%w: account is inactive", ErrNotAMember)
			}
			return nil
		}
	}
	return ErrNotAMember
}

// Invalidate drops a workspace's cached snapshot.
//
// Called when membership changes -- a revocation in particular. Both halves
// being in one process is what makes this a function call rather than a
// distributed invalidation problem; when IGA moves to its own database this
// becomes the push half of the contract.
func (m *legacyMembership) Invalidate(workspaceID uuid.UUID) {
	m.mu.Lock()
	delete(m.cache, workspaceID)
	m.mu.Unlock()
}
