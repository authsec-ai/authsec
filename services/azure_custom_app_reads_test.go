package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
)

// slowARM answers every read after a delay, refuses one subscription and gives
// another Contributor, and records how many reads ran at once.
type slowARM struct {
	delay          time.Duration
	denied, wide   string
	inFlight, peak atomic.Int32
}

func (f *slowARM) enter() func() {
	n := f.inFlight.Add(1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(f.delay)
	return func() { f.inFlight.Add(-1) }
}

func (f *slowARM) GetSubscription(_ context.Context, _, id string) (*azure.Subscription, error) {
	defer f.enter()()
	if id == f.denied {
		return nil, errors.New("AuthorizationFailed")
	}
	return &azure.Subscription{SubscriptionID: id}, nil
}

func (f *slowARM) ListRoleAssignmentsForPrincipal(_ context.Context, _, sub, _ string) ([]azure.RoleAssignment, error) {
	defer f.enter()()
	if sub != f.wide {
		return nil, nil
	}
	var a azure.RoleAssignment
	a.Properties.RoleDefinitionID = azure.RoleDefinitionResourceID(sub, azure.RoleContributor)
	return []azure.RoleAssignment{a}, nil
}

// ConnectCustom read each subscription one at a time (two ARM reads each), so
// a tenant with a few dozen subscriptions ran past the 105s connect budget.
func TestCustomSubscriptionReadsRunInParallel(t *testing.T) {
	var subs []azure.Subscription
	for i := 0; i < 12; i++ {
		subs = append(subs, azure.Subscription{SubscriptionID: fmt.Sprintf("sub-%02d", i), DisplayName: fmt.Sprintf("Sub %02d", i)})
	}
	f := &slowARM{delay: 40 * time.Millisecond, denied: "sub-03", wide: "sub-07"}
	start := time.Now()
	results, privileged := customSubscriptionReads(context.Background(), f, "tok", "sp", subs)
	elapsed := time.Since(start)

	if p := f.peak.Load(); p < 2 || p > azureAssignConcurrency {
		t.Fatalf("peak concurrent reads %d, want 2..%d", p, azureAssignConcurrency)
	}
	// Serial: 12 subscriptions x 2 reads (one for the refused) x 40ms ~ 0.9s.
	if elapsed > 600*time.Millisecond {
		t.Fatalf("reads took %s; they ran one at a time", elapsed)
	}
	if len(results) != len(subs) {
		t.Fatalf("%d results for %d subscriptions", len(results), len(subs))
	}
	for i, r := range results {
		if r.SubscriptionID != subs[i].SubscriptionID {
			t.Fatalf("result %d is %s: order lost", i, r.SubscriptionID)
		}
		want := models.AzureReaderExisting
		if r.SubscriptionID == "sub-03" {
			want = models.AzureReaderDenied
		}
		if r.Reader.Status != want {
			t.Fatalf("%s: reader %s, want %s", r.SubscriptionID, r.Reader.Status, want)
		}
	}
	if len(privileged) != 1 || !strings.HasPrefix(privileged[0], "Sub 07 (Contributor") {
		t.Fatalf("privileged %v", privileged)
	}
}
