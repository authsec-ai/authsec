package platform

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/internal/k8sread"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// K8sGraphController serves the Kubernetes identity graph.
//
// Separate from the AWS graph controller for the reason k8sread is separate
// from igaread: the questions differ. AWS asks "which account, which region";
// Kubernetes asks "which cluster, which namespace, and could the agent see
// cluster-scoped objects at all". A shared controller would have to answer both
// with one shape and would end up answering neither honestly.
type K8sGraphController struct {
	db *gorm.DB

	// cursors signs the identities list cursor (IGA_CURSOR_SECRET, as the
	// graph routes and the AWS run history), built on first use.
	cursorsOnce sync.Once
	cursors     *igaread.Reader
}

func NewK8sGraphController(db *gorm.DB) *K8sGraphController {
	return &K8sGraphController{db: db}
}

// ListClusters handles GET /authsec/discovery/k8s/clusters.
//
// The sweep is part of the answer, not metadata beside it. A caller that reads
// the counts without reading last_sweep.coverage can draw exactly the wrong
// conclusion from a cluster whose agent lost cluster-wide read this morning.
func (ctl *K8sGraphController) ListClusters(c *gin.Context) {
	ws, ok := ctl.ws(c)
	if !ok {
		return
	}
	out, err := k8sread.New(ctl.db, ws).Clusters()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"clusters": out,
		"meta": gin.H{
			"note": "coverage is a state, never a percentage: a partially swept " +
				"cluster is not 'mostly covered', it is covered in the namespaces " +
				"named and unknown everywhere else",
		},
	})
}

// identitiesNote is the identities list's note, unchanged since D-112.
const identitiesNote = "a ServiceAccount is an identity, not a workload; grant counts " +
	"are declared rules, not observed calls, and include grants reached " +
	"through implicit group membership"

// identityKindsNote is added to it when the page may hold Users or Groups.
const identityKindsNote = "; a User's or Group's counts are its own grants (Kubernetes " +
	"records no membership of a User), and a Group's members are the ServiceAccounts " +
	"placed in it, a lower bound"

// identitiesRoute and identitiesSort bind the list cursor (D-113).
const (
	identitiesRoute = "k8s/identities"
	identitiesSort  = "anchor,id"
)

// identitiesCursorKey is the cursor's sort key: the last row's anchor (its
// id is the cursor's own).
type identitiesCursorKey struct {
	Anchor *string `json:"a"`
}

func (ctl *K8sGraphController) cursorSigner() *igaread.Reader {
	ctl.cursorsOnce.Do(func() { ctl.cursors = igaread.NewReader(ctl.db, cursorKeyFromEnv()) })
	return ctl.cursors
}

// ListIdentities handles GET /authsec/discovery/k8s/identities.
//
// Parameters (D-113), all optional, all additive:
//   - kind: service_account | user | group, repeatable or comma-separated.
//     Default service_account only -- the list's contract before D-113.
//   - cluster, namespace: one value each. A User or Group has no namespace,
//     so a namespace filter keeps ServiceAccounts only.
//   - limit: 1-1000, default 500; anything else is the default (as before).
//   - cursor: meta.next_cursor of the previous page. HMAC-signed and bound to
//     the workspace, this route, the filter set and the sort: presented with
//     other filters it is 400 cursor_invalid.
//
// Order: anchor, then id. The page is chosen first and its rows' counts are
// read for that page alone, so the order cannot be the grant count (D-113).
// meta.total is how many identities the filter matches across all pages.
func (ctl *K8sGraphController) ListIdentities(c *gin.Context) {
	ws, ok := ctl.ws(c)
	if !ok {
		return
	}
	vals := c.Request.URL.Query()

	var kinds []string
	seen := map[string]bool{}
	for _, raw := range vals["kind"] {
		for _, k := range strings.Split(raw, ",") {
			if strings.TrimSpace(k) == "" {
				continue
			}
			ak, ok := k8sread.AccountKind(k)
			if !ok {
				k8sBadParam(c, "kind", "kind must be service_account, user or group")
				return
			}
			if !seen[ak] {
				seen[ak] = true
				kinds = append(kinds, ak)
			}
		}
	}
	if len(kinds) == 0 {
		kinds = []string{k8sread.AccountKinds[0]} // service_account: the default
	}
	sort.Strings(kinds)
	one := func(name string) (string, bool) {
		if len(vals[name]) > 1 {
			k8sBadParam(c, name, name+" takes one value")
			return "", false
		}
		return strings.TrimSpace(vals.Get(name)), true
	}
	cluster, ok := one("cluster")
	if !ok {
		return
	}
	namespace, ok := one("namespace")
	if !ok {
		return
	}
	limit := identitiesLimit(vals.Get("limit"))

	// The cursor binds the NORMALISED filter set, so kind=user,group and
	// kind=group&kind=user are one filter.
	want := igaread.CursorContext{
		WS: ws, Route: identitiesRoute, Sort: identitiesSort,
		Filter: igaread.FilterHash(url.Values{"kind": kinds, "cluster": {cluster}, "namespace": {namespace}}),
	}
	f := k8sread.IdentityFilter{Kinds: kinds, Cluster: cluster, Namespace: namespace, Limit: limit}
	if token := vals.Get("cursor"); token != "" {
		cur, cerr := ctl.cursorSigner().OpenCursor(token, want)
		if cerr != nil {
			c.JSON(cerr.Status, gin.H{"error": cerr.Message, "code": cerr.Code})
			return
		}
		var key identitiesCursorKey
		if err := json.Unmarshal(cur.Key, &key); err != nil || key.Anchor == nil || cur.ID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Malformed cursor.", "code": "cursor_invalid"})
			return
		}
		f.After = &k8sread.IdentityPosition{Anchor: *key.Anchor, ID: cur.ID}
	}

	page, err := k8sread.New(ctl.db, ws).ListIdentities(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var next any
	if page.Next != nil {
		key, _ := json.Marshal(identitiesCursorKey{Anchor: &page.Next.Anchor})
		next = ctl.cursorSigner().SignCursor(igaread.Cursor{
			WS: ws, Route: want.Route, Filter: want.Filter, Sort: want.Sort,
			Key: key, ID: page.Next.ID,
		})
	}
	note := identitiesNote
	if len(kinds) > 1 || kinds[0] != k8sread.AccountKinds[0] {
		note += identityKindsNote
	}
	c.JSON(http.StatusOK, gin.H{
		"identities": page.Items,
		"meta": gin.H{
			"note":        note,
			"kinds":       kinds,
			"cluster":     nullIfEmpty(cluster),
			"namespace":   nullIfEmpty(namespace),
			"limit":       limit,
			"total":       page.Total,
			"next_cursor": next,
		},
	})
}

// GetIdentity handles GET /authsec/discovery/k8s/identities/:id (D-113): one
// Kubernetes identity of any kind -- ServiceAccount, User or Group -- with the
// fields and counts of its list row, so a page can open any identity without
// finding it in a capped list. 404 when the token's workspace has no
// Kubernetes identity with that id: another workspace's id, an AWS
// identity's and an unknown one read the same.
func (ctl *K8sGraphController) GetIdentity(c *gin.Context) {
	ws, ok := ctl.ws(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity id"})
		return
	}
	out, err := k8sread.New(ctl.db, ws).Identity(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if out == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity not found", "code": "not_found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"identity": out,
		"meta": gin.H{
			"note": "grant counts are declared rules, not observed calls: a ServiceAccount's " +
				"include grants reached through implicit group membership; a User's or " +
				"Group's are its own. The rules are at /identities/:id/access",
		},
	})
}

// GetAccess handles GET /authsec/discovery/k8s/identities/:id/access.
//
// Any Kubernetes identity (D-113): a ServiceAccount's own grants and its
// groups'; a User's or Group's own grants.
//
// Returns the whole chain per grant -- binding, role, rule, and the group a
// grant came through -- because the question behind this screen is "why can
// this account do that", and three separately-paged objects do not answer it.
// Grants are declared, not evaluated; each says where its rule applies
// (effective_scope, D-109) and how it was reached (via, D-112).
func (ctl *K8sGraphController) GetAccess(c *gin.Context) {
	ws, ok := ctl.ws(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity id"})
		return
	}
	grants, sum, err := k8sread.New(ctl.db, ws).AccessFor(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// The summary ships even when the list is empty, because an empty list has
	// two very different meanings and only the summary distinguishes them.
	c.JSON(http.StatusOK, gin.H{"grants": grants, "summary": sum})
}

// ListWorkloads handles GET /authsec/discovery/k8s/workloads.
//
// The screen this serves answers the product's actual question -- "what can
// this agent reach" -- by naming the identity each workload runs as and how
// much that identity can do. Ordered by name (then id); the counts are read
// for the page's execution identities alone (D-113).
func (ctl *K8sGraphController) ListWorkloads(c *gin.Context) {
	ws, ok := ctl.ws(c)
	if !ok {
		return
	}
	out, err := k8sread.New(ctl.db, ws).Workloads(igaLimit(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"workloads": out,
		"meta": gin.H{
			"note": "runs_as is the configured or observed execution identity; it " +
				"does not assert the workload made any request",
		},
	})
}

func (ctl *K8sGraphController) ws(c *gin.Context) (uuid.UUID, bool) {
	raw := c.GetString("workspace_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in token"})
		return uuid.Nil, false
	}
	return id, true
}

func igaLimit(c *gin.Context) int {
	var n int
	if v := c.Query("limit"); v != "" {
		for _, r := range v {
			if r < '0' || r > '9' {
				return 0
			}
			n = n*10 + int(r-'0')
			if n > 10000 {
				return 0
			}
		}
	}
	return n
}

// identitiesLimit is the identities list's page size (D-113): 1-1000, 500
// when absent or unreadable -- as the list answered before, never a 400.
func identitiesLimit(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	switch {
	case err != nil || n <= 0:
		return k8sread.IdentityDefaultLimit
	case n > k8sread.IdentityMaxLimit:
		return k8sread.IdentityMaxLimit
	}
	return n
}

func k8sBadParam(c *gin.Context, param, msg string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": msg, "code": "invalid_parameter", "parameter": param})
}
