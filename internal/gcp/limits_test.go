package gcp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The governor's job is to stop a large estate turning a scan into the
// incident. Its defaults are AuthSec-side budgets rather than transcribed
// Google quotas, so what is tested here is that the budget is enforced and that
// a misconfigured one cannot become an unlimited one -- not that any particular
// number is correct, which only a live benchmark can say.

func TestGovernor_DefaultsWhenEnvironmentIsUnset(t *testing.T) {
	t.Setenv(EnvMaxProjectConcurrency, "")
	t.Setenv(EnvIAMQPS, "")
	t.Setenv(EnvCAIQPS, "")

	g := NewGovernor()
	if got := g.ProjectConcurrency(); got != defaultMaxProjectConcurrency {
		t.Fatalf("concurrency = %d, want the default %d", got, defaultMaxProjectConcurrency)
	}
	if g.IAM == nil || g.CAI == nil || g.ResourceManager == nil {
		t.Fatal("every limiter must be constructed, or an ungoverned call path exists")
	}
}

func TestGovernor_EnvironmentOverridesAreApplied(t *testing.T) {
	t.Setenv(EnvMaxProjectConcurrency, "9")
	g := NewGovernor()
	if got := g.ProjectConcurrency(); got != 9 {
		t.Fatalf("concurrency = %d, want 9", got)
	}
}

// A typo must slow a scan down, never remove the governor. Zero, negative and
// unparseable all fall back rather than being taken literally -- a concurrency
// of 0 would deadlock and a QPS of 0 would stall forever.
func TestGovernor_BadEnvironmentFallsBackRatherThanDisabling(t *testing.T) {
	for _, raw := range []string{"0", "-4", "banana", "1e"} {
		t.Run("concurrency="+raw, func(t *testing.T) {
			t.Setenv(EnvMaxProjectConcurrency, raw)
			if got := NewGovernor().ProjectConcurrency(); got != defaultMaxProjectConcurrency {
				t.Fatalf("concurrency = %d, want the default %d", got, defaultMaxProjectConcurrency)
			}
		})
	}
	for _, raw := range []string{"0", "-1", "banana"} {
		t.Run("qps="+raw, func(t *testing.T) {
			t.Setenv(EnvIAMQPS, raw)
			if got := floatFromEnv(EnvIAMQPS, defaultIAMQPS); got != defaultIAMQPS {
				t.Fatalf("qps = %v, want the default %v", got, defaultIAMQPS)
			}
		})
	}
}

// The fan-out guarantee: an org with hundreds of projects must not open
// hundreds of concurrent calls.
func TestGovernor_FanOutNeverExceedsConfiguredConcurrency(t *testing.T) {
	t.Setenv(EnvMaxProjectConcurrency, "3")
	g := NewGovernor()

	var (
		inFlight int32
		peak     int32
		wg       sync.WaitGroup
	)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.AcquireProject(context.Background())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			defer release()

			now := atomic.AddInt32(&inFlight, 1)
			for {
				was := atomic.LoadInt32(&peak)
				if now <= was || atomic.CompareAndSwapInt32(&peak, was, now) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
		}()
	}
	wg.Wait()

	if peak > 3 {
		t.Fatalf("peak concurrency was %d, above the configured 3", peak)
	}
	if peak == 0 {
		t.Fatal("nothing ran; the test proved nothing")
	}
}

// A release must be safe to defer unconditionally, including after an error,
// and must not free a slot twice -- a double release would let the pool grow
// past its bound over a long scan.
func TestGovernor_ReleaseIsIdempotent(t *testing.T) {
	t.Setenv(EnvMaxProjectConcurrency, "1")
	g := NewGovernor()

	release, err := g.AcquireProject(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	release() // must not panic, and must not free a second slot

	// The single slot is free exactly once, so this acquire succeeds and the
	// next one blocks.
	release2, err := g.AcquireProject(context.Background())
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	defer release2()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := g.AcquireProject(ctx); err == nil {
		t.Fatal("a slot was freed twice; the pool grew past its bound")
	}
}

// A scan whose deadline expires while waiting for a slot must stop rather than
// queue behind work that will never matter.
func TestGovernor_AcquireRespectsContext(t *testing.T) {
	t.Setenv(EnvMaxProjectConcurrency, "1")
	g := NewGovernor()

	release, err := g.AcquireProject(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	blockedRelease, err := g.AcquireProject(ctx)
	if err == nil {
		t.Fatal("expected the acquire to give up when the context expired")
	}
	// Safe to call even on the error path.
	blockedRelease()
}
