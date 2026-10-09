// Pre-deadline warnings — phase 1B of ENFORCEMENT-ARCHITECTURE.md §7 (§3A.9).
//
// The uncomfortable property first, because everything else follows from it:
//
//  1. A FAILED WARNING NEVER BLOCKS THE ACTION. Blocking would let an SMTP outage
//     quietly turn every destructive policy into a no-op, and the operator would
//     believe it was handled. The failure is recorded as a governance exception
//     instead — the action still happens, and nobody-was-told is auditable.
//  2. ONLY DESTRUCTIVE DEADLINES ARE WARNED ABOUT. Warning on every expiring
//     entitlement would bury the deletions, and noise is how a real warning gets
//     filtered into a folder nobody reads.
//  3. IT FIRES ONCE, ACROSS REPLICAS — but a MOVED deadline re-warns. Keyed on the
//     policy alone, pushing a deletion out by a month would silently consume the
//     only warning anyone was going to get.
//  4. A DEACTIVATED USER IS NOT A RECIPIENT. Mailing a closed account is a bounce,
//     and counting it as delivered would launder an unannounced deletion into a
//     warned one.
package ownership

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

/* ------------------------------- harness --------------------------------- */

// captureSender records what it was asked to send instead of sending it.
type captureSender struct {
	mu   sync.Mutex
	sent []services.WarningBody
	to   []string
	// fail makes every send fail, for the retry and exception paths.
	fail error
}

func (c *captureSender) Send(w *models.AgentPolicyWarning, b services.WarningBody) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	c.sent = append(c.sent, b)
	c.to = append(c.to, w.Recipient)
	return nil
}

func (c *captureSender) recipients() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.to))
	copy(out, c.to)
	return out
}

type warnFixture struct {
	provFixture
	mgr   services.PolicyWarningManager
	email *captureSender
	hook  *captureSender
}

func newWarnFixture(t *testing.T) warnFixture {
	t.Helper()
	f := newProvFixture(t)
	email, hook := &captureSender{}, &captureSender{}
	return warnFixture{
		provFixture: f,
		mgr:         services.NewPolicyWarningManagerWith(gormFor(t, f.raw), email, hook),
		email:       email, hook: hook,
	}
}

// destructivePolicy attaches an evict-on-expiry policy with a confirmation, due in
// `in`. Everything a real destructive policy needs, so nothing under test passes
// for want of a constraint.
func (f warnFixture) destructivePolicy(t *testing.T, in time.Duration) uuid.UUID {
	t.Helper()
	pm := policyMgr(t, f.provFixture)
	expires := time.Now().Add(in)
	p, err := pm.Create(f.ws, claimOwner.String(), services.AgentPolicyInput{
		Name: "delete on expiry", DiscoveredAgentID: &f.agent,
		DesiredState: models.AgentPolicyStateQuarantined,
		ExpiresAt:    &expires,
		OnExpiry:     models.OnExpiryEvict,
		Reason:       "decommissioned project",
		ConfirmedBy:  &claimOwner,
		// A direct policy confirms against the one agent it targets.
		ConfirmAgentIDs: []uuid.UUID{f.agent},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	return p.ID
}

/* ------------------------------ scheduling ------------------------------- */

func TestDestructiveDeadlineIsWarnedAbout(t *testing.T) {
	f := newWarnFixture(t)
	f.destructivePolicy(t, 48*time.Hour) // inside the default 7-day lead

	n, err := f.mgr.Schedule(f.ws)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if n == 0 {
		t.Fatal("a deletion 48h away inside a 7-day lead must be warned about")
	}

	rows, err := f.mgr.List(f.ws, nil, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for i := range rows {
		if rows[i].OnExpiry != models.OnExpiryEvict {
			t.Errorf("warning must snapshot what was scheduled, got %q", rows[i].OnExpiry)
		}
		if rows[i].State != models.WarningPending {
			t.Errorf("a fresh warning must be pending, got %q", rows[i].State)
		}
		// available_at = deadline - lead. With the deadline already inside the lead
		// window that is in the past, which is correct: it is due immediately.
		if !rows[i].AvailableAt.Before(rows[i].Deadline) {
			t.Error("a warning must become available BEFORE the deadline it warns about")
		}
	}
}

// Noise is how a real warning gets filtered into a folder nobody reads.
func TestNonDestructiveExpiryIsNotWarnedAbout(t *testing.T) {
	f := newWarnFixture(t)
	expires := time.Now().Add(24 * time.Hour)
	if _, err := policyMgr(t, f.provFixture).Create(f.ws, claimOwner.String(), services.AgentPolicyInput{
		Name: "lapse access", DiscoveredAgentID: &f.agent,
		DesiredState: models.AgentPolicyStateQuarantined,
		ExpiresAt:    &expires, OnExpiry: models.OnExpiryRevoke,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	n, err := f.mgr.Schedule(f.ws)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if n != 0 {
		t.Errorf("revoke-on-expiry lapses an entitlement and is reversible by "+
			"re-provisioning; warning about it would bury the deletions. Got %d warnings", n)
	}
}

func TestDeadlineBeyondTheLeadIsNotYetWarnedAbout(t *testing.T) {
	f := newWarnFixture(t)
	f.destructivePolicy(t, 30*24*time.Hour) // well past the 7-day lead

	n, err := f.mgr.Schedule(f.ws)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if n != 0 {
		t.Errorf("a deadline 30 days out must not be warned about under a 7-day lead; got %d", n)
	}
}

// Two replicas scheduling in the same tick must not double-mail somebody about the
// deletion of their workload.
func TestSchedulingIsIdempotent(t *testing.T) {
	f := newWarnFixture(t)
	f.destructivePolicy(t, 48*time.Hour)

	first, err := f.mgr.Schedule(f.ws)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if first == 0 {
		t.Fatal("setup: expected warnings")
	}
	for i := 0; i < 3; i++ {
		again, aerr := f.mgr.Schedule(f.ws)
		if aerr != nil {
			t.Fatalf("re-schedule: %v", aerr)
		}
		if again != 0 {
			t.Fatalf("re-run %d minted %d duplicate warnings", i, again)
		}
	}
}

// Keyed on the policy alone, pushing a deletion out by a month would silently
// consume the only warning anyone was going to get.
func TestMovingTheDeadlineSchedulesAFreshWarning(t *testing.T) {
	f := newWarnFixture(t)
	pid := f.destructivePolicy(t, 48*time.Hour)
	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	before, _ := f.mgr.List(f.ws, &pid, 0)

	// The operator pushes the deletion out by two days — still inside the lead.
	exec(t, f.raw, `UPDATE agent_policies SET expires_at = expires_at + interval '2 days'
	                 WHERE id = $1`, pid)

	n, err := f.mgr.Schedule(f.ws)
	if err != nil {
		t.Fatalf("re-schedule: %v", err)
	}
	if n == 0 {
		t.Fatal("a moved deadline must schedule a fresh warning: the sent one described " +
			"a deadline that no longer exists")
	}
	after, _ := f.mgr.List(f.ws, &pid, 0)
	if len(after) <= len(before) {
		t.Errorf("want more warnings after the move, had %d now %d", len(before), len(after))
	}
}

/* ------------------------------- recipients ------------------------------ */

func TestOwnerIsWarned(t *testing.T) {
	f := newWarnFixture(t)
	f.destructivePolicy(t, 48*time.Hour)
	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, err := f.mgr.Deliver(50); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	var ownerEmail string
	if err := f.raw.QueryRow(`SELECT email FROM users WHERE id = $1`, claimOwner).
		Scan(&ownerEmail); err != nil {
		t.Fatalf("read owner: %v", err)
	}
	got := f.email.recipients()
	found := false
	for _, r := range got {
		if r == ownerEmail {
			found = true
		}
	}
	if !found {
		t.Errorf("the accountable owner must be warned — their workload is the one that "+
			"disappears. Warned: %v, owner: %s", got, ownerEmail)
	}
}

// Mailing a closed account is a bounce, and counting it as delivered would launder
// an unannounced deletion into a warned one.
func TestDeactivatedUsersAreNotWarned(t *testing.T) {
	f := newWarnFixture(t)
	exec(t, f.raw, `UPDATE users SET active = false WHERE id = $1`, claimOwner)
	f.destructivePolicy(t, 48*time.Hour)

	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, err := f.mgr.Deliver(50); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	var ownerEmail string
	_ = f.raw.QueryRow(`SELECT email FROM users WHERE id = $1`, claimOwner).Scan(&ownerEmail)
	for _, r := range f.email.recipients() {
		if r == ownerEmail && ownerEmail != "" {
			t.Errorf("a deactivated user was warned at %s; that is a bounce recorded as a "+
				"delivered warning", r)
		}
	}
}

/* -------------------------------- delivery ------------------------------- */

func TestDeliveryMarksSentAndCarriesTheDetail(t *testing.T) {
	f := newWarnFixture(t)
	f.destructivePolicy(t, 48*time.Hour)
	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	out, err := f.mgr.Deliver(50)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if out.Sent == 0 {
		t.Fatalf("nothing was sent: %+v", out)
	}

	rows, _ := f.mgr.List(f.ws, nil, 0)
	for i := range rows {
		if rows[i].State != models.WarningSent {
			t.Errorf("want sent, got %q (%s)", rows[i].State, rows[i].LastError)
			continue
		}
		if rows[i].SentAt == nil {
			t.Error("a sent warning must carry its timestamp, or 'was this warned about' " +
				"degrades to a boolean with no time to compare against the deadline")
		}
	}

	// The message has to say what will happen, to what, and when.
	f.email.mu.Lock()
	defer f.email.mu.Unlock()
	if len(f.email.sent) == 0 {
		t.Fatal("no body captured")
	}
	b := f.email.sent[0]
	if b.OnExpiry != models.OnExpiryEvict || b.AgentLabel == "" || b.Deadline.IsZero() {
		t.Errorf("body is missing the essentials: %+v", b)
	}
	if !b.Confirmed {
		t.Error("this agent IS covered by the confirmation; saying otherwise would tell " +
			"the reader the deletion will be refused when it will not")
	}
	if !strings.Contains(b.Reason, "decommissioned") {
		t.Errorf("the operator's justification must reach the reader, got %q", b.Reason)
	}
}

// Retries are bounded, and exhausting them does NOT stop the deadline.
func TestFailedDeliveryRetriesThenGivesUpWithoutBlocking(t *testing.T) {
	f := newWarnFixture(t)
	f.email.fail = errSMTPDown{}
	f.destructivePolicy(t, 48*time.Hour)
	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	// Drive it past the retry ceiling. available_at is pushed forward on each
	// failure, so it is wound back between passes rather than sleeping.
	for i := 0; i < models.MaxWarningAttempts+1; i++ {
		if _, err := f.mgr.Deliver(50); err != nil {
			t.Fatalf("deliver: %v", err)
		}
		exec(t, f.raw, `UPDATE agent_policy_warnings SET available_at = now() - interval '1 hour'
		                 WHERE state IN ('pending','failed')`)
	}

	rows, _ := f.mgr.List(f.ws, nil, 0)
	sawDead := false
	for i := range rows {
		if rows[i].State == models.WarningDead {
			sawDead = true
			if rows[i].LastError == "" {
				t.Error("a dead warning must say why it died")
			}
			if rows[i].AttemptCount < models.MaxWarningAttempts {
				t.Errorf("gave up after %d attempts, want at least %d",
					rows[i].AttemptCount, models.MaxWarningAttempts)
			}
		}
		if rows[i].State == models.WarningSent {
			t.Error("nothing could be sent; a sent row means the failure was swallowed")
		}
	}
	if !sawDead {
		t.Fatal("retries must be bounded: a permanently bad address would otherwise " +
			"consume the worker's budget forever")
	}

	// THE POINT: the policy still stands and its deadline is untouched. An SMTP
	// outage must not silently no-op a destructive policy.
	var expires *time.Time
	var enabled bool
	if err := f.raw.QueryRow(`SELECT expires_at, enabled FROM agent_policies
	                           WHERE workspace_id = $1 LIMIT 1`, f.ws).
		Scan(&expires, &enabled); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !enabled || expires == nil {
		t.Error("an undeliverable warning must not disable or defer the policy it warned " +
			"about — that is the silent-non-execution failure §3A.4 exists to prevent")
	}
}

// The governance exception: the action ran, and nobody was told.
func TestUnwarnedDestructiveActionIsRecordedAsAnException(t *testing.T) {
	f := newWarnFixture(t)
	pm := policyMgr(t, f.provFixture)

	// A deletion already past due, with no warning ever delivered.
	past := time.Now().Add(-time.Hour)
	if _, err := pm.Create(f.ws, claimOwner.String(), services.AgentPolicyInput{
		Name: "overdue", DiscoveredAgentID: &f.agent,
		DesiredState: models.AgentPolicyStateQuarantined,
		ExpiresAt:    &past, OnExpiry: models.OnExpiryRevoke,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := pm.Reconcile(f.ws, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// revoke is not destructive, so warning_delivered stays NULL — there is
	// nothing to warn about when an entitlement lapses and can be re-provisioned.
	var nulls int
	if err := f.raw.QueryRow(`SELECT count(*) FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'revoked' AND warning_delivered IS NULL`,
		f.ws).Scan(&nulls); err != nil {
		t.Fatalf("read actions: %v", err)
	}
	if nulls == 0 {
		t.Error("a non-destructive action must leave warning_delivered NULL; false would " +
			"manufacture a governance exception out of an ordinary lapse")
	}
}

func TestWasWarnedReadsDeliveredOnly(t *testing.T) {
	f := newWarnFixture(t)
	f.destructivePolicy(t, 48*time.Hour)
	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	var deadline time.Time
	if err := f.raw.QueryRow(`SELECT deadline FROM agent_policy_warnings
	                           WHERE workspace_id = $1 LIMIT 1`, f.ws).Scan(&deadline); err != nil {
		t.Fatalf("read deadline: %v", err)
	}

	warned, err := f.mgr.WasWarned(f.ws, f.agent, deadline)
	if err != nil {
		t.Fatalf("was warned: %v", err)
	}
	if warned {
		t.Error("a SCHEDULED warning is not a delivered one; treating pending as warned " +
			"would report an unannounced deletion as announced")
	}

	if _, err := f.mgr.Deliver(50); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	warned, err = f.mgr.WasWarned(f.ws, f.agent, deadline)
	if err != nil {
		t.Fatalf("was warned: %v", err)
	}
	if !warned {
		t.Error("after delivery the action must read as warned")
	}
}

/* -------------------------------- settings ------------------------------- */

// A workspace that never configured anything must still be warned. Requiring
// configuration first would make the safe path the one you have to opt into.
func TestUnconfiguredWorkspaceGetsDefaults(t *testing.T) {
	f := newWarnFixture(t)
	s, err := f.mgr.Settings(f.ws)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if s.Lead() != models.DefaultWarningLead {
		t.Errorf("want the 7-day default, got %s", s.Lead())
	}
	if !s.EmailEnabled {
		t.Error("email must be on by default: an unconfigured workspace that is silently " +
			"not warned is the worst version of this feature")
	}
}

func TestWebhookMustBeHTTPS(t *testing.T) {
	f := newWarnFixture(t)
	bad := "http://hooks.example/x"
	if _, err := f.mgr.SaveSettings(f.ws, services.NotificationSettingsInput{
		WebhookURL: &bad,
	}); err == nil {
		t.Error("a plaintext webhook must be refused: a warning naming the workload about " +
			"to be deleted is a map of what to attack while nobody is watching it")
	}
	good := "https://hooks.example/x"
	if _, err := f.mgr.SaveSettings(f.ws, services.NotificationSettingsInput{
		WebhookURL: &good,
	}); err != nil {
		t.Errorf("https must be accepted: %v", err)
	}
}

func TestAbsurdLeadsAreRefused(t *testing.T) {
	f := newWarnFixture(t)
	for name, d := range map[string]time.Duration{
		"zero":    0,
		"a click": time.Second,
		"a year":  365 * 24 * time.Hour,
	} {
		lead := d
		if _, err := f.mgr.SaveSettings(f.ws, services.NotificationSettingsInput{
			WarningLead: &lead,
		}); err == nil {
			t.Errorf("%s must be refused as a warning lead", name)
		}
	}
	ok := 72 * time.Hour
	out, err := f.mgr.SaveSettings(f.ws, services.NotificationSettingsInput{WarningLead: &ok})
	if err != nil {
		t.Fatalf("72h must be accepted: %v", err)
	}
	if out.Lead() != ok {
		t.Errorf("lead did not round-trip: want %s got %s", ok, out.Lead())
	}
}

// The webhook is a second channel, not a replacement — and turning email off must
// not turn warnings off.
func TestWebhookIsScheduledAlongsideEmail(t *testing.T) {
	f := newWarnFixture(t)
	url := "https://hooks.example/governance"
	if _, err := f.mgr.SaveSettings(f.ws, services.NotificationSettingsInput{
		WebhookURL: &url,
	}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	f.destructivePolicy(t, 48*time.Hour)
	if _, err := f.mgr.Schedule(f.ws); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	rows, _ := f.mgr.List(f.ws, nil, 0)
	var emails, hooks int
	for i := range rows {
		switch rows[i].Channel {
		case models.WarningChannelEmail:
			emails++
		case models.WarningChannelWebhook:
			hooks++
		}
	}
	if hooks != 1 {
		t.Errorf("want exactly one webhook warning, got %d", hooks)
	}
	if emails == 0 {
		t.Error("configuring a webhook must not silence email")
	}

	if _, err := f.mgr.Deliver(50); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(f.hook.recipients()) != 1 {
		t.Errorf("the webhook sender must have been used once, got %d", len(f.hook.recipients()))
	}
}

type errSMTPDown struct{}

func (errSMTPDown) Error() string { return "smtp: connection refused" }
