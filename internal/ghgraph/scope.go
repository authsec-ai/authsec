package ghgraph

import (
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Partition is the evidence boundary reconciliation may never cross.
//
// A GitHub scan succeeds or fails per (repository, object class): a repository
// whose deploy keys returned 403 still had its workflows read, and the legacy
// absence sweep keys completeness on exactly that pair for the same reason
// (iga_service.go, sweepAbsent). So a row is owned by the partition of its
// integration, its repository and its class, and only a reading that covered
// that partition may end it.
//
// The App installation belongs to no repository: it is the binding itself, so
// it has a partition of its own (Repo "").
type Partition struct {
	IntegrationID uuid.UUID
	// Repo is the repository's native id, "" for the installation.
	Repo  string
	Class string
}

// Classes a partition may own. Each is the coverage class the scan records for
// the same read, so CanEnd can ask the scan directly.
const (
	ClassRepository   = models.ClassRepository
	ClassInstallation = models.ClassAppInstallation
	ClassDeployKey    = models.ClassDeployKey
	ClassCopilotAgent = models.ClassAgentProfile
	ClassWorkflow     = models.ClassRepoDeclaration
)

const installationScope = "-installation-"

// Key is the partition's stable identity and the value stamped on every
// support row and grant it owns.
//
// Frozen once deployed: changing the spelling orphans every support row
// written under the old one, and an orphaned support row reads as "nothing
// supports this object", which retires it.
func (p Partition) Key() string {
	repo := p.Repo
	if repo == "" {
		repo = installationScope
	}
	return p.IntegrationID.String() + "|" + repo + "|" + p.Class
}

// ParsePartition reads a key back. The integration id and the class never
// contain "|"; the repository id between them is taken whole, so an unusual
// native id cannot shift the class.
func ParsePartition(key string) (Partition, bool) {
	first := strings.Index(key, "|")
	last := strings.LastIndex(key, "|")
	if first <= 0 || last <= first {
		return Partition{}, false
	}
	id, err := uuid.Parse(key[:first])
	if err != nil {
		return Partition{}, false
	}
	repo := key[first+1 : last]
	if repo == installationScope {
		repo = ""
	}
	return Partition{IntegrationID: id, Repo: repo, Class: key[last+1:]}, true
}

// Scope is one scan's authority to close rows: whether it finished, and what
// it could read in each repository it listed.
type Scope struct {
	IntegrationID uuid.UUID
	ScanRunID     uuid.UUID
	// Succeeded is the scan's own verdict: published, authoritative. A scan
	// that failed proves nothing about anything.
	Succeeded bool
	// Repos holds, per repository the scan's listing returned, its coverage by
	// class (see Repo.Coverage for what an absent class means).
	Repos map[string]map[string]string
}

// ScopeOf lifts the coverage facts off a snapshot.
func ScopeOf(s Snapshot, scanRunID uuid.UUID, succeeded bool) Scope {
	out := Scope{
		IntegrationID: s.IntegrationID, ScanRunID: scanRunID, Succeeded: succeeded,
		Repos: make(map[string]map[string]string, len(s.Repos)),
	}
	for _, r := range s.Repos {
		cov := map[string]string{}
		for k, v := range r.Coverage {
			cov[k] = v
		}
		out.Repos[r.NativeID] = cov
	}
	return out
}

// CanEnd reports whether this scan is entitled to END rows in a partition
// rather than only mark them stale.
//
//  1. the scan succeeded -- a failed scan read nothing it can vouch for;
//  2. the partition is this integration's;
//  3. either the repository was absent from the scan's listing -- the listing
//     is one authoritative read, and a scan whose listing failed does not
//     succeed -- or the scan read this class of it completely.
//
// The installation partition closes on any successful scan: the scan ran
// under the binding, so an installation the integration no longer names is
// one GitHub no longer reports for it.
//
// Anything short of that yields `stale`, never `ended`. Collapsing the two is
// how a permission change reads as a mass deletion.
func (s Scope) CanEnd(p Partition) bool {
	if !s.Succeeded || p.IntegrationID != s.IntegrationID {
		return false
	}
	if p.Repo == "" {
		return p.Class == ClassInstallation
	}
	cov, listed := s.Repos[p.Repo]
	if !listed {
		return true
	}
	if p.Class == ClassRepository {
		return true // the listing itself is the read, and it returned this repository
	}
	state, recorded := cov[p.Class]
	return !recorded || state == models.CoverageComplete
}
