package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/services"
)

// K-1 ordering: a snapshot whose sweep started no later than the last
// accepted one of its source and cluster -- a replay, or one that arrived
// late -- is refused (sweep_stale) instead of becoming the newest generation
// and ending grants a newer reading confirmed.
func TestK8sSweepOrdering(t *testing.T) {
	k := newK8sGraphLab(t, "k8s-sweep-order")
	w := k8sFullWorld()
	first := k.sweep(w)
	accepted := k.at

	for name, at := range map[string]time.Time{"a replay": accepted, "an older sweep": accepted.Add(-10 * time.Minute)} {
		if _, err := k.mgr.Ingest(k.ws, w.snapshot(k, at)); !errors.Is(err, services.ErrSweepStale) {
			t.Fatalf("%s: %v, want ErrSweepStale", name, err)
		}
	}
	var n int64
	k.db.Table("iga_k8s_sweep").Where("workspace_id = ?", k.ws).Count(&n)
	if n != 1 {
		t.Fatalf("a refused sweep was recorded: %d sweeps", n)
	}
	// A newer sweep is accepted and takes the next generation.
	if next := k.sweep(w); next.Generation != first.Generation+1 {
		t.Fatalf("generation %d after %d", next.Generation, first.Generation)
	}
}
