package services

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/google/uuid"
)

// Running the whole onboarding off one sign-in.
//
// Every step here already existed as its own endpoint, and still does. What was
// missing was the obvious thing: an administrator signing in to their OWN
// tenant, holding both privileges the flow needs, had to click through four
// screens to reach a state that was fully determined the moment they consented.
// This runs those four steps for them and reports what happened.
//
// It is opt-in (?auto_setup=true) and not the default, because the assumption it
// makes is not always true. The manual path exists for the case it was built
// for: one operator onboarding tenants they do not administer, where consent and
// Reader are granted by different people at different times, and where assigning
// Reader across subscriptions unasked would be a write nobody authorised.
//
// The chain runs in the background. It cannot run inside the callback: the
// browser is mid-redirect waiting for a Location header, and assigning Reader
// across a dozen subscriptions is not something to make it wait for.

// AzureSetupStatus is the progress of one automatic setup run.
//
// Everything durable it produces lands in azure_connectors and
// azure_subscriptions. This is only the narration -- which step is running, what
// went wrong -- which is why it lives in memory rather than a table. A restart
// loses the narration and keeps every fact.
type AzureSetupStatus struct {
	// State is "running", "done" or "failed". "done" means the chain reached the
	// end, NOT that everything in it succeeded. Read the counts.
	State string `json:"state"`

	// Step is the human label of what is happening, or what failed.
	Step string `json:"step"`

	TenantID   string     `json:"tenantId,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`

	// TenantWide says Reader was granted once at the tenant root management
	// group rather than per subscription, so subscriptions created later are
	// covered without anyone coming back.
	TenantWide bool `json:"tenantWide"`

	Subscriptions  int `json:"subscriptions"`
	ReaderAssigned int `json:"readerAssigned"`
	ReaderFailed   int `json:"readerFailed"`

	// Elevation is the full account of a temporary root-scope privilege raise:
	// whether it happened, and -- the part that matters -- whether it was given
	// back. Present only on the tenant-wide path, and only when the operator's
	// existing privilege was not already enough.
	Elevation *ElevationOutcome `json:"elevation,omitempty"`

	ARMReaderOK bool `json:"armReaderOk"`
	GraphOK     bool `json:"graphOk"`

	GrantedRoles []string `json:"grantedRoles"`
	MissingRoles []string `json:"missingRoles"`

	// Problems is everything that did not work, in the order it was found. A
	// partial setup is the normal outcome when one person holds Global
	// Administrator but not Owner, and saying so plainly is the point.
	Problems []string `json:"problems"`
}

const (
	// autoSetupTTL is how long a finished run stays readable -- long enough for
	// a browser closed mid-run to come back and read the outcome.
	autoSetupTTL = 30 * time.Minute

	// autoSetupBudget bounds one run. Generous: a tenant with many
	// subscriptions makes one role assignment each, and ARM throttles.
	autoSetupBudget = 10 * time.Minute
)

// autoSetupRBACSettle is how long to wait before re-checking ARM. Azure RBAC is
// eventually consistent: an assignment that returned 201 can still be invisible
// to the next call. A variable so tests do not pay it.
var autoSetupRBACSettle = 10 * time.Second

// setupStore holds run status for this process.
//
// Process-local on purpose. Behind more than one replica a poll can land on an
// instance that never ran the chain and will answer "not found" -- which the
// console already handles, because a run also expires. The connector rows are
// the shared truth; this is a progress bar.
type setupStore struct {
	mu  sync.Mutex
	run map[string]*AzureSetupStatus
}

var autoSetup = &setupStore{run: map[string]*AzureSetupStatus{}}

// begin claims the session for a run, or reports that one is already going.
func (st *setupStore) begin(sessionID, tenantID string) (*AzureSetupStatus, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()

	if cur, ok := st.run[sessionID]; ok && cur.State == "running" {
		return cur, false
	}
	s := &AzureSetupStatus{
		State:        "running",
		Step:         "starting",
		TenantID:     tenantID,
		StartedAt:    time.Now().UTC(),
		GrantedRoles: []string{},
		MissingRoles: []string{},
		Problems:     []string{},
	}
	st.run[sessionID] = s
	return s, true
}

// update mutates the stored status under the lock. Callers never hold a pointer
// they write to directly: the poll handler reads the same struct.
func (st *setupStore) update(sessionID string, fn func(*AzureSetupStatus)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.run[sessionID]; ok {
		fn(s)
	}
}

// get returns a COPY. Handing out the pointer would race with the run.
func (st *setupStore) get(sessionID string) (AzureSetupStatus, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()

	s, ok := st.run[sessionID]
	if !ok {
		return AzureSetupStatus{}, false
	}
	out := *s
	out.GrantedRoles = append([]string(nil), s.GrantedRoles...)
	out.MissingRoles = append([]string(nil), s.MissingRoles...)
	out.Problems = append([]string(nil), s.Problems...)
	return out, true
}

// sweepLocked drops finished runs past their TTL. A run still marked running is
// kept regardless of age: the goroutine holds the only other reference, and
// dropping it would strand a poller on "not found" while work continues.
func (st *setupStore) sweepLocked() {
	cutoff := time.Now().UTC().Add(-autoSetupTTL)
	for id, s := range st.run {
		if s.FinishedAt != nil && s.FinishedAt.Before(cutoff) {
			delete(st.run, id)
		}
	}
}

// SetupStatus reports an automatic setup run, if this process ran one.
func (s *AzureOnboardService) SetupStatus(sessionID string) (AzureSetupStatus, bool) {
	return autoSetup.get(sessionID)
}

// StartAutoSetup runs the chain in the background and returns immediately.
//
// Returns false when a run for this session is already in flight, which is what
// a replayed callback or a double-clicked link produces. The state row is
// one-shot, so this is belt and braces -- but the cost of getting it wrong is
// duplicate role assignments and the cost of the check is a map lookup.
func (s *AzureOnboardService) StartAutoSetup(
	workspaceID uuid.UUID, sessionID, tenantID string, tenantWide bool,
) bool {
	if sessionID == "" || azureonboard.ValidateTenantID(tenantID) != nil {
		return false
	}
	if _, started := autoSetup.begin(sessionID, tenantID); !started {
		return false
	}
	go func() {
		// A panic in a background goroutine takes the process with it. The
		// callback has already returned by now, so there is nobody left to
		// report to except the log and the status row.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("azure auto-setup panic: %v\n%s", r, debug.Stack())
				now := time.Now().UTC()
				autoSetup.update(sessionID, func(st *AzureSetupStatus) {
					st.State, st.Step, st.FinishedAt = "failed", "internal error", &now
					st.Problems = append(st.Problems, "setup stopped unexpectedly")
				})
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), autoSetupBudget)
		defer cancel()
		s.autoSetup(ctx, workspaceID, sessionID, tenantID, tenantWide)
	}()
	return true
}

// autoSetup is the chain itself.
//
// It never returns an error. Every step records what it achieved and moves on,
// because the steps are independent facts: Reader can fail while Graph succeeds,
// and reporting only the first failure would hide the half that worked.
func (s *AzureOnboardService) autoSetup(
	ctx context.Context, workspaceID uuid.UUID, sessionID, tenantID string, tenantWide bool,
) {
	// Recorded here rather than by the caller, so the status always describes
	// what this run actually did.
	autoSetup.update(sessionID, func(st *AzureSetupStatus) { st.TenantWide = tenantWide })

	step := func(label string) {
		autoSetup.update(sessionID, func(st *AzureSetupStatus) { st.Step = label })
	}
	problem := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		autoSetup.update(sessionID, func(st *AzureSetupStatus) {
			st.Problems = append(st.Problems, msg)
		})
	}
	finish := func(state, label string) {
		now := time.Now().UTC()
		autoSetup.update(sessionID, func(st *AzureSetupStatus) {
			st.State, st.Step, st.FinishedAt = state, label, &now
		})
	}

	// 1. Confirm the tenant. The id came from the tid claim of a token we were
	//    just issued, which is trustworthy -- but the tenant listing is what
	//    every other path in this service is built on, and a tenant absent from
	//    it is one the operator cannot act in. One call keeps the two views from
	//    diverging.
	step("reading tenants")
	tenants, err := s.ListTenants(ctx, workspaceID, sessionID)
	if err != nil {
		problem("could not list tenants: %v", err)
		finish("failed", "reading tenants")
		return
	}
	found := false
	for _, t := range tenants {
		if strings.EqualFold(t.TenantID, tenantID) {
			found = true
			break
		}
	}
	if !found {
		problem("signed-in tenant %s is not in this account's tenant list", tenantID)
		finish("failed", "reading tenants")
		return
	}

	// 2+3. Reader across every subscription the operator can see, in ONE call.
	//
	//    One call, not one per subscription, and the reason is a bug this used to
	//    have. Every AssignReader redeems the session's refresh token at the
	//    tenant's authority -- and Entra ROTATES a refresh token on redemption,
	//    superseding the one presented. Looping meant presenting the same stored
	//    token N+1 times: the first two landed inside Entra's grace window and
	//    the rest came back
	//
	//        AADSTS65001: The user or administrator has not consented ...
	//
	//    which reads like a consent problem and is nothing of the kind. Against a
	//    real tenant with five subscriptions, one was granted and four were
	//    refused.
	//
	//    AssignReader with an EMPTY scope already does the right thing: acquire
	//    the tenant token once, list the operator's subscriptions with it, and
	//    assign at each. Its result carries one entry per scope, so per
	//    subscription reporting survives.
	//
	//    tenantWide switches this to ONE grant at the tenant root management
	//    group, which covers subscriptions created later so nobody has to come
	//    back. It can require briefly raising the operator's own privilege to
	//    root User Access Administrator, which is why it is never the default
	//    and never inferred: only an operator who ticked the box at
	//    POST /api/azure/auto-setup can reach it, and the raise is reported
	//    whether or not it happened. AssignReader gives the privilege back in a
	//    deferred call that runs even when the assignment itself fails.
	if tenantWide {
		step("assigning Reader at the tenant root")
	} else {
		step("assigning Reader")
	}
	res, err := s.AssignReader(ctx, workspaceID, sessionID, tenantID, "", tenantWide)
	if err != nil {
		// Not fatal. Graph does not depend on ARM, and a tenant with no
		// subscription access is still worth onboarding for its directory.
		problem("could not assign Reader: %s", explainReaderFailure(err))
	}

	assignedCount, failedCount := 0, 0
	if res != nil {
		for _, a := range res.Assigned {
			if a.OK {
				assignedCount++
				continue
			}
			failedCount++
			problem("Reader on %s: %s", scopeLabel(a.Scope),
				firstNonEmpty(a.Error, "refused"))
		}

		// The privilege raise, reported in full. An operator must never have to
		// discover from a log that their own account was briefly root User
		// Access Administrator -- or, worse, that it still is.
		if res.Elevation != nil {
			el := res.Elevation
			autoSetup.update(sessionID, func(st *AzureSetupStatus) { st.Elevation = el })
			// Elevated without Removed is the one state that needs a human:
			// root User Access Administrator does not expire on its own.
			if el.Elevated && !el.Removed {
				problem("YOUR ACCOUNT IS STILL ROOT USER ACCESS ADMINISTRATOR: the temporary "+
					"privilege raise could not be undone (%s). It does not expire. Remove it: "+
					"Microsoft Entra ID -> Properties -> Access management for Azure "+
					"resources -> No",
					firstNonEmpty(el.Error, "no reason given"))
			}
		}
	}

	autoSetup.update(sessionID, func(st *AzureSetupStatus) {
		st.ReaderAssigned = assignedCount
		st.ReaderFailed = failedCount
		// On the tenant-wide path there is exactly one grant and it is not a
		// subscription, so a subscription count here would be a fiction. The
		// real count arrives from ValidateARM below, which asks the application
		// what it can actually read -- which is the only answer worth showing.
		if !tenantWide {
			st.Subscriptions = assignedCount + failedCount
		}
	})
	// Nothing attempted and nothing refused means there was nothing to act on.
	// Only meaningful on the per-subscription path: the tenant-wide grant does
	// not depend on the operator being able to see any subscription, which is
	// part of why it is the better answer for a tenant that has many.
	if !tenantWide && assignedCount+failedCount == 0 && err == nil {
		problem("the signed-in account can see no subscriptions in this tenant, " +
			"so Reader could not be assigned anywhere")
	}

	// 4. Prove it. Assigning a role and being able to read are different facts,
	//    and this is the check the whole flow exists to make.
	//
	//    It runs twice, for two different reasons, and the SECOND result is the
	//    one that counts:
	//
	//    - A failure right after a grant is usually Azure RBAC being eventually
	//      consistent rather than a refusal, so it deserves a second look before
	//      being reported as one.
	//
	//    - A tenant-wide grant PASSES on the first look and still under-reports.
	//      ARMReaderOK is "at least one subscription", which the pre-existing one
	//      satisfies immediately -- while the root management group assignment is
	//      still propagating to the rest. Observed against a real tenant: the
	//      first check saw 1 subscription and stopped; ARM listed all 5 moments
	//      later. Recording 1 there is not a small inaccuracy, it is the number
	//      an operator uses to decide whether the grant worked.
	step("checking ARM access")
	armOK, armCount := false, 0
	for attempt := 0; attempt < 2; attempt++ {
		arm, err := s.ValidateARM(ctx, workspaceID, tenantID)
		if err != nil {
			problem("could not check ARM access: %v", err)
			break
		}
		armOK, armCount = arm.ARMReaderOK, arm.Count

		if attempt == 1 || ctx.Err() != nil {
			if !armOK {
				problem("ARM read check did not pass: %s",
					firstNonEmpty(arm.Error, "no readable subscription"))
			}
			break
		}
		// Look again when the answer is still settling: either nothing was
		// readable yet despite a grant, or the grant covers a scope whose
		// membership arrives over the following seconds.
		if tenantWide || (!armOK && assignedCount > 0) {
			select {
			case <-time.After(autoSetupRBACSettle):
				continue
			case <-ctx.Done():
			}
		}
		if !armOK {
			problem("ARM read check did not pass: %s",
				firstNonEmpty(arm.Error, "no readable subscription"))
		}
		break
	}
	autoSetup.update(sessionID, func(st *AzureSetupStatus) {
		st.ARMReaderOK = armOK
		// The authoritative subscription count: what the APPLICATION can read,
		// asked after the grant settled. On the tenant-wide path nothing else
		// sets this -- the grant is one assignment at a scope that is not a
		// subscription -- and leaving it at zero reported "none visible" on a
		// run that had just made five readable.
		if tenantWide || armCount > 0 {
			st.Subscriptions = armCount
		}
	})

	// 5. Graph. Independent of everything above: it is the consent plane, and it
	//    either was granted at sign-in or was not.
	step("checking directory access")
	graph, err := s.ValidateGraph(ctx, workspaceID, tenantID)
	if err != nil {
		problem("could not check directory access: %v", err)
	} else {
		granted := append([]string(nil), graph.Granted...)
		missing := append([]string(nil), graph.Missing...)
		sort.Strings(granted)
		sort.Strings(missing)
		autoSetup.update(sessionID, func(st *AzureSetupStatus) {
			st.GraphOK, st.GrantedRoles, st.MissingRoles = graph.GraphOK, granted, missing
		})
		if !graph.GraphOK {
			// Unreadable is a different fault, and naming the missing
			// permissions there would be a fabrication: nothing was read, so the
			// list is every required permission rather than an observation.
			// Telling an operator "you granted nothing" when the application
			// could not authenticate sends them to re-grant four permissions
			// that were never the problem.
			if graph.Unreadable {
				problem("could not read the directory: %s",
					firstNonEmpty(graph.Error, "no reason given"))
			} else {
				problem("directory permissions not usable; missing: %s",
					firstNonEmpty(strings.Join(missing, ", "), "unknown"))
			}
			if graph.Hint != "" {
				problem("%s", graph.Hint)
			}
		}
	}

	finish("done", "finished")
}

// explainReaderFailure translates the one Entra error that means something
// other than what it says.
//
// AADSTS65001 on the delegated ARM token reads "the user or administrator has
// not consented", and an operator looking at a console that ALSO says "directory
// access verified, 4 permissions usable" has no way to reconcile those. Both are
// true: Graph is consented, and the Azure Service Management delegated scope is
// not, because the registration never declared it and admin consent's .default
// therefore deleted the grant that sign-in had created.
//
// Passing the raw message through cost a real debugging session. The fix is one
// checkbox in the portal, so it belongs in the message.
func explainReaderFailure(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if !strings.Contains(msg, "AADSTS65001") {
		return msg
	}
	return "the application is not consented for the Azure Service Management API in this " +
		"tenant, so it cannot act as the operator to assign a role. This is NOT the Graph " +
		"consent, which succeeded. Declare user_impersonation as a DELEGATED permission on " +
		"the app registration (API permissions -> APIs my organization uses -> Azure Service " +
		"Management) and consent again -- without it, admin consent's .default scope deletes " +
		"the grant that sign-in creates. Original error: " + msg
}

// scopeLabel shortens an ARM scope for a status line. The full scope is what
// went to Azure and what belongs in a log; "subscription <id>" is what an
// operator reads.
func scopeLabel(scope string) string {
	if id := strings.TrimPrefix(scope, "/subscriptions/"); id != scope && id != "" {
		return "subscription " + id
	}
	if scope == "" {
		return "unknown scope"
	}
	return scope
}
