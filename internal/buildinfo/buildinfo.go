// Package buildinfo carries the identity of the binary that is running.
//
// It exists to answer one question that was, until now, unanswerable: IS THE
// CODE I PUSHED THE CODE THAT IS RUNNING?
//
// It used to be answerable from the image tag, because deployments referenced
// the commit SHA. They now reference a floating `:production` tag, so the tag
// says nothing about which commit produced the image -- and because the tag
// does not change between builds, Kubernetes sees no diff and will not roll on
// its own. Both failure modes are silent: you build, push, and keep serving
// yesterday's binary with nothing on screen to say so.
//
// The values below are injected at link time. A binary built without them says
// "unknown", which is the honest answer for a `go run` or a local build, and is
// distinguishable from a stale deploy rather than being confused with one.
package buildinfo

import (
	"runtime"
	"time"
)

// Injected with -ldflags "-X github.com/authsec-ai/authsec/internal/buildinfo.Commit=..."
//
// Package-level vars rather than constants because that is the only shape the
// linker can write to.
var (
	// Commit is the full git SHA this binary was built from.
	Commit = "unknown"
	// Branch is the ref it was built from, for a human reading a status page.
	Branch = "unknown"
	// BuiltAt is an RFC3339 timestamp from the build, NOT from process start.
	// The difference matters: a pod restarted an hour ago may be running a
	// binary built last month, and only one of those two times reveals it.
	BuiltAt = "unknown"
)

// startedAt is when this process began, which is a different fact from BuiltAt
// and is why both are reported.
var startedAt = time.Now()

// Info is the wire shape of the version endpoint.
type Info struct {
	Commit string `json:"commit"`
	// ShortCommit is the first 12 characters, which is what a person compares
	// against `git log --oneline`.
	ShortCommit string `json:"short_commit"`
	Branch      string `json:"branch"`
	BuiltAt     string `json:"built_at"`
	StartedAt   string `json:"started_at"`
	// UptimeSeconds distinguishes "just deployed" from "has been up for days",
	// which is the first thing to check when a deploy appears not to have
	// landed.
	UptimeSeconds int64  `json:"uptime_seconds"`
	GoVersion     string `json:"go_version"`
	// Injected is false when the binary was built without ldflags. A caller
	// comparing commits must not treat "unknown" as a mismatch with everything.
	Injected bool `json:"injected"`
}

// Current returns this binary's identity.
func Current() Info {
	short := Commit
	if len(short) > 12 {
		short = short[:12]
	}
	return Info{
		Commit:        Commit,
		ShortCommit:   short,
		Branch:        Branch,
		BuiltAt:       BuiltAt,
		StartedAt:     startedAt.UTC().Format(time.RFC3339),
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		GoVersion:     runtime.Version(),
		Injected:      Commit != "unknown",
	}
}
