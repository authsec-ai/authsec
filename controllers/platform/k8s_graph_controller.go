package platform

import (
	"net/http"

	"github.com/authsec-ai/authsec/internal/k8sread"
	"github.com/authsec-ai/authsec/internal/tenancy"
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
	var out []k8sread.Cluster
	err := k8sread.Read(c.Request.Context(), ctl.db, func(q *k8sread.Query) (err error) {
		out, err = q.Clusters()
		return err
	})
	if err != nil {
		respondK8sReadError(c, err)
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

// ListIdentities handles GET /authsec/discovery/k8s/identities.
func (ctl *K8sGraphController) ListIdentities(c *gin.Context) {
	var out []k8sread.Identity
	err := k8sread.Read(c.Request.Context(), ctl.db, func(q *k8sread.Query) (err error) {
		out, err = q.Identities(igaLimit(c))
		return err
	})
	if err != nil {
		respondK8sReadError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"identities": out,
		"meta": gin.H{
			"note": "a ServiceAccount is an identity, not a workload; grant counts " +
				"are declared rules, not observed calls",
		},
	})
}

// GetAccess handles GET /authsec/discovery/k8s/identities/:id/access.
//
// Returns the whole chain per grant -- binding, role, rule -- because the
// question behind this screen is "why can this account do that", and three
// separately-paged objects do not answer it.
func (ctl *K8sGraphController) GetAccess(c *gin.Context) {
	if _, err := tenancy.Workspace(c); err != nil {
		respondK8sReadError(c, err)
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity id"})
		return
	}
	var (
		grants []k8sread.Grant
		sum    k8sread.AccessSummary
	)
	err = k8sread.Read(c.Request.Context(), ctl.db, func(q *k8sread.Query) error {
		// Another workspace's identity, or an unknown one, is 404 -- never
		// an empty list that would read as "no access".
		ok, err := q.HasIdentity(id)
		if err != nil {
			return err
		}
		if !ok {
			return tenancy.ErrNotFound
		}
		grants, sum, err = q.AccessFor(id)
		return err
	})
	if err != nil {
		respondK8sReadError(c, err)
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
// much that identity can do.
func (ctl *K8sGraphController) ListWorkloads(c *gin.Context) {
	var out []k8sread.Workload
	err := k8sread.Read(c.Request.Context(), ctl.db, func(q *k8sread.Query) (err error) {
		out, err = q.Workloads(igaLimit(c))
		return err
	})
	if err != nil {
		respondK8sReadError(c, err)
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

// respondK8sReadError maps a read failure: no workspace in the token is 401,
// an identity outside the caller's workspace 404, anything else 500.
func respondK8sReadError(c *gin.Context, err error) {
	switch tenancy.HTTPStatus(err) {
	case http.StatusUnauthorized:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in token"})
	case http.StatusNotFound:
		c.JSON(http.StatusNotFound, gin.H{"error": "identity not found"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
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
