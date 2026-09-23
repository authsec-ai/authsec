package integration

// Harness for the S2 routes (T2.1-T2.3): the REAL CloudAWSController behind
// gin, with the token's workspace set the way AuthMiddleware sets it, over the
// P2-0 lab's database; a fake ec2:DescribeRegions; and one-scan helpers that
// let a test act while the REAL worker is mid-run.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// s2FakeRegions answers ec2:DescribeRegions with the account's ENABLED
// regions, or an error.
type s2FakeRegions struct {
	mu      sync.Mutex
	enabled []string // opt-in-not-required unless listed in optedIn
	optedIn map[string]bool
	err     error
	calls   int
	lastIn  *ec2.DescribeRegionsInput
}

func s2Regions(enabled ...string) *s2FakeRegions {
	return &s2FakeRegions{enabled: enabled, optedIn: map[string]bool{}}
}

func (f *s2FakeRegions) DescribeRegions(_ context.Context, in *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastIn = in
	if f.err != nil {
		return nil, f.err
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.enabled {
		status := "opt-in-not-required"
		if f.optedIn[r] {
			status = "opted-in"
		}
		out.Regions = append(out.Regions, ec2types.Region{RegionName: aws.String(r), OptInStatus: aws.String(status)})
	}
	return out, nil
}

// s2Discovery is the discovery route table the S2 handlers live on.
type s2Discovery struct {
	t   *testing.T
	eng *gin.Engine
	mu  sync.Mutex
	ws  uuid.UUID
}

// s2DiscoveryAPI builds the S2 discovery routes around a controller whose
// onboarding service is svc (fake AWS, memory vault).
func s2DiscoveryAPI(t *testing.T, l *p2Lab, svc *services.AWSOnboardingService) *s2Discovery {
	t.Helper()
	gin.SetMode(gin.TestMode)
	d := &s2Discovery{t: t, ws: l.ws}
	ctl := platform.NewCloudAWSController(l.db).WithOnboardingService(svc)
	eng := gin.New()
	g := eng.Group("/authsec/discovery")
	g.Use(func(c *gin.Context) {
		d.mu.Lock()
		ws := d.ws
		d.mu.Unlock()
		if ws != uuid.Nil {
			c.Set("workspace_id", ws.String())
		}
		c.Next()
	})
	g.GET("/aws/connectors/:id/regions", ctl.GetConnectorRegions)
	g.PATCH("/aws/connectors/:id", ctl.UpdateConnector)
	g.GET("/aws/connectors/:id/scan-runs", ctl.ListConnectorScanRuns)
	g.GET("/aws/scan-runs/:id", ctl.GetScanRun)
	d.eng = eng
	return d
}

func (d *s2Discovery) asWorkspace(ws uuid.UUID) *s2Discovery {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ws = ws
	return d
}

// do calls a discovery route. body may be a value to encode, or a
// json.RawMessage sent verbatim.
func (d *s2Discovery) do(method, path string, body any) (int, map[string]any) {
	d.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case json.RawMessage:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			d.t.Fatalf("encode body: %v", err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/authsec/discovery"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	d.eng.ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			d.t.Fatalf("%s %s: status %d, body is not JSON: %q", method, path, w.Code, w.Body.String())
		}
	}
	return w.Code, out
}

func (d *s2Discovery) patchRegions(conn uuid.UUID, regions ...string) (int, map[string]any) {
	d.t.Helper()
	return d.do(http.MethodPatch, "/aws/connectors/"+conn.String(), map[string]any{"regions": regions})
}

// s2ConnectorRegions reads a connector's stored region selection.
func s2ConnectorRegions(t *testing.T, l *p2Lab, conn uuid.UUID) []string {
	t.Helper()
	var c models.CloudConnector
	if err := l.db.First(&c, "id = ?", conn).Error; err != nil {
		t.Fatalf("read connector: %v", err)
	}
	return c.AWSAttrs().Regions
}

// s2ScanWith runs ONE scan of the account through the REAL worker, with extra
// scanner configuration applied after the account's own fakes, and returns
// the run as it ended.
func s2ScanWith(l *p2Lab, a *p2Account, owner string, extra services.ScannerHook) models.CloudScanRun {
	l.t.Helper()
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	base := a.hook()
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).WithGraphProjection(l.gate).
		WithScannerHook(func(i *services.AWSIAMScanner, p *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
			base(i, p, wl)
			if extra != nil {
				extra(i, p, wl)
			}
		})
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker %s: worked=%v err=%v", owner, worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		l.t.Fatalf("read run: %v", err)
	}
	return run
}

// s2DuringEKS is an EKS fake that runs `during` on its FIRST ListClusters --
// i.e. inside the permission scan, after the IAM scan and before the workload
// scan: the moment a mid-run connector change used to leak into the run.
type s2DuringEKS struct {
	*fakeEKS
	once   sync.Once
	during func()
}

func (f *s2DuringEKS) ListClusters(ctx context.Context, in *eks.ListClustersInput, opts ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	f.once.Do(f.during)
	return f.fakeEKS.ListClusters(ctx, in, opts...)
}

// s2Coverage decodes a run's own coverage.
func s2Coverage(run models.CloudScanRun) models.ScanCoverage {
	return models.DecodeScanCoverage(run.Coverage)
}
