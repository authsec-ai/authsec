package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// Membership is what routes a review and records who answered it. Two rules
// carry the weight, and both are about refusing to act rather than acting:
//
//   - an inactive account is FOUND but may not act;
//   - a snapshot older than the ceiling may be READ but may not authorise a
//     change, because the value of a decision record is that the person was
//     entitled at the time, and an hour-old snapshot cannot establish that.

// fakeAuthority is the seam the interface exists to provide: membership can be
// staged without a users table, which is the whole argument for depending on an
// interface rather than a query.
type fakeAuthority struct {
	snapshot services.MembershipSnapshot
	err      error
	now      time.Time
}

func (f *fakeAuthority) Members(context.Context, uuid.UUID) (services.MembershipSnapshot, error) {
	if f.err != nil {
		return services.MembershipSnapshot{}, f.err
	}
	return f.snapshot, nil
}

func (f *fakeAuthority) Member(
	ctx context.Context, ws, subject uuid.UUID,
) (services.Member, error) {
	snap, err := f.Members(ctx, ws)
	if err != nil {
		return services.Member{}, err
	}
	for _, m := range snap.Members {
		if m.SubjectID == subject {
			return m, nil
		}
	}
	return services.Member{}, services.ErrNotAMember
}

func (f *fakeAuthority) CanAct(ctx context.Context, ws, subject uuid.UUID) error {
	snap, err := f.Members(ctx, ws)
	if err != nil {
		return err
	}
	if snap.Stale(f.now) {
		return services.ErrMembershipStale
	}
	m, err := f.Member(ctx, ws, subject)
	if err != nil {
		return err
	}
	if !m.Active {
		return services.ErrNotAMember
	}
	return nil
}

func TestAStaleSnapshotMayBeReadButNotActedOn(t *testing.T) {
	now := time.Now()
	subject := uuid.New()
	auth := &fakeAuthority{
		now: now,
		snapshot: services.MembershipSnapshot{
			// Older than the 60-minute ceiling: an outage, not a slow refresh.
			SnapshotAt: now.Add(-90 * time.Minute),
			Members:    []services.Member{{SubjectID: subject, Active: true}},
		},
	}

	// Reading is allowed — browsing an inventory during an outage is fine.
	if _, err := auth.Members(context.Background(), uuid.New()); err != nil {
		t.Fatalf("a stale snapshot must still be readable: %v", err)
	}
	// Acting is not.
	err := auth.CanAct(context.Background(), uuid.New(), subject)
	if !errors.Is(err, services.ErrMembershipStale) {
		t.Fatalf("CanAct on a stale snapshot = %v, want ErrMembershipStale", err)
	}
}

func TestAnInactiveMemberIsFoundButMayNotAct(t *testing.T) {
	now := time.Now()
	subject := uuid.New()
	auth := &fakeAuthority{
		now: now,
		snapshot: services.MembershipSnapshot{
			SnapshotAt: now,
			Members:    []services.Member{{SubjectID: subject, Active: false}},
		},
	}
	// Found: an offboarded person still appears in history and in old reviews.
	if _, err := auth.Member(context.Background(), uuid.New(), subject); err != nil {
		t.Fatalf("an inactive member should still be findable: %v", err)
	}
	// Not permitted: "found" is not "allowed", and collapsing the two is how an
	// offboarded account keeps approving things.
	if err := auth.CanAct(context.Background(), uuid.New(), subject); !errors.Is(err, services.ErrNotAMember) {
		t.Fatalf("CanAct for an inactive member = %v, want ErrNotAMember", err)
	}
}

func TestAnUnknownSubjectMayNotAct(t *testing.T) {
	now := time.Now()
	auth := &fakeAuthority{
		now:      now,
		snapshot: services.MembershipSnapshot{SnapshotAt: now},
	}
	if err := auth.CanAct(context.Background(), uuid.New(), uuid.New()); !errors.Is(err, services.ErrNotAMember) {
		t.Fatalf("CanAct for a stranger = %v, want ErrNotAMember", err)
	}
}

func TestMutationsFailClosedWhenTheAuthorityIsUnreachable(t *testing.T) {
	auth := &fakeAuthority{now: time.Now(), err: services.ErrMembershipUnavailable}
	if err := auth.CanAct(context.Background(), uuid.New(), uuid.New()); !errors.Is(err, services.ErrMembershipUnavailable) {
		t.Fatalf("CanAct with the authority down = %v, want ErrMembershipUnavailable", err)
	}
}

func TestSnapshotAgeIsReportable(t *testing.T) {
	now := time.Now()
	s := services.MembershipSnapshot{SnapshotAt: now.Add(-10 * time.Minute)}
	if got := s.Age(now); got < 9*time.Minute || got > 11*time.Minute {
		t.Fatalf("Age = %v, want about 10m", got)
	}
	if s.Stale(now) {
		t.Fatal("ten minutes is inside the ceiling; a banner is warranted, refusal is not")
	}
}
