package igaread

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// graph=v2 is the opt-in for TRD 2 providers (linux, kubernetes, ad) and the
// fields that only exist on that graph. Absent, every read keeps the AWS
// predicate and the AWS JSON. A value other than v2 is 400.
//
// The widen is a gorm callback on the reader's database. It rewrites the
// literal provider = 'aws' only when the request context carries v2, and it
// leaves the statement untouched otherwise, so a default read sends the same
// SQL it did before this package grew a second provider set. Bind parameters
// (pipeline and coverage connector lookups) are not that literal and stay AWS
// until the caller opts in and the handler applies includeProvider.
const (
	graphParamV2       = "v2"
	providerAWSLiteral = "provider = 'aws'"
)

// graphV2ProviderOrder is the closed set, sorted, used when v2 names no
// provider. Every name is [a-z] so it can be interpolated into SQL.
var graphV2ProviderOrder = []string{
	models.ProviderAD, models.ProviderAWS, models.ProviderKubernetes, models.ProviderLinux,
}

var graphV2ProviderSet = func() map[string]bool {
	out := make(map[string]bool, len(graphV2ProviderOrder))
	for _, p := range graphV2ProviderOrder {
		out[p] = true
	}
	return out
}()

// GraphScope is the opt-in a single request asked for.
type GraphScope struct {
	V2        bool
	Providers []string
}

type graphScopeKey struct{}

func isOptInParam(name string) bool { return name == "graph" || name == "provider" }

func withGraphScope(ctx context.Context, sc GraphScope) context.Context {
	return context.WithValue(ctx, graphScopeKey{}, sc)
}

func graphScopeFrom(ctx context.Context) GraphScope {
	if ctx == nil {
		return GraphScope{}
	}
	sc, _ := ctx.Value(graphScopeKey{}).(GraphScope)
	return sc
}

// parseGraphOnly reads graph. It does not look at provider.
func parseGraphOnly(vals url.Values) (GraphScope, *Error) {
	raw, ok := vals["graph"]
	if !ok {
		return GraphScope{}, nil
	}
	if len(raw) != 1 {
		return GraphScope{}, InvalidParameter("graph", "graph may be given once")
	}
	switch strings.TrimSpace(raw[0]) {
	case graphParamV2:
		return GraphScope{V2: true}, nil
	default:
		return GraphScope{}, InvalidParameter("graph", "graph must be v2")
	}
}

func providerValues(vals url.Values) []string {
	var out []string
	for _, v := range vals["provider"] {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseV2Providers is the provider filter once graph=v2 is set. No value
// means every v2 provider. Names outside the set are 400.
func parseV2Providers(vals url.Values) ([]string, *Error) {
	raw := providerValues(vals)
	if len(raw) == 0 {
		return append([]string(nil), graphV2ProviderOrder...), nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range raw {
		if !graphV2ProviderSet[p] || strings.ContainsAny(p, "'\\") {
			return nil, InvalidParameter("provider", "provider must be one of "+strings.Join(graphV2ProviderOrder, ", "))
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// BindOptIn attaches graph=v2 to ctx. provider without graph=v2 is 400:
func BindOptIn(ctx context.Context, vals url.Values) (context.Context, *Error) {
	return bindOptIn(ctx, vals)
}

// bindOptIn attaches graph=v2 to ctx. provider without graph=v2 is 400:
// these routes did not accept provider before, and a bare provider=aws must
// not become a silent no-op. Lists do not use this; they keep D-75's
// "provider must be aws" until the caller opts in.
func bindOptIn(ctx context.Context, vals url.Values) (context.Context, *Error) {
	sc, perr := parseGraphOnly(vals)
	if perr != nil {
		return ctx, perr
	}
	if len(providerValues(vals)) > 0 && !sc.V2 {
		return ctx, InvalidParameter("provider", "provider requires graph=v2")
	}
	if sc.V2 {
		provs, perr := parseV2Providers(vals)
		if perr != nil {
			return ctx, perr
		}
		sc.Providers = provs
	}
	return withGraphScope(ctx, sc), nil
}

func (s GraphScope) predicate() string {
	if len(s.Providers) == 1 {
		return "provider = '" + s.Providers[0] + "'"
	}
	quoted := make([]string, len(s.Providers))
	for i, p := range s.Providers {
		quoted[i] = "'" + p + "'"
	}
	return "provider IN (" + strings.Join(quoted, ",") + ")"
}

// rewrite replaces the AWS literal. !V2 returns s unchanged, including its
// bytes: that is the reader half of T25.
func (s GraphScope) rewrite(sql string) string {
	if !s.V2 || !strings.Contains(sql, providerAWSLiteral) {
		return sql
	}
	return strings.ReplaceAll(sql, providerAWSLiteral, s.predicate())
}

// SQL is rewrite for a snapshot. Callers that already go through the gorm
// callback do not need it; tests use it to prove the default is an identity.
func (q *Query) SQL(sql string) string {
	if q == nil {
		return sql
	}
	return (GraphScope{V2: q.V2, Providers: q.Providers}).rewrite(sql)
}

// includeProvider reports whether this snapshot should read that provider.
// The default snapshot reads AWS only.
func (q *Query) includeProvider(provider string) bool {
	if q == nil || !q.V2 {
		return provider == models.ProviderAWS
	}
	for _, p := range q.Providers {
		if p == provider {
			return true
		}
	}
	return false
}

// edgeKinds is the traversal order. The default list is unchanged; v2 appends
// backed_by_directory and observed_access after it.
func (q *Query) edgeKinds() []string {
	if q != nil && q.V2 {
		return graphV2EdgeKinds
	}
	return graphEdgeKinds
}

var graphWidenOnce sync.Map

func installGraphWiden(db *gorm.DB) {
	if db == nil || db.Callback() == nil {
		return
	}
	key := fmt.Sprintf("%p", db.Callback())
	if _, loaded := graphWidenOnce.LoadOrStore(key, true); loaded {
		return
	}
	_ = db.Callback().Row().Before("gorm:row").Register("igaread:v2_provider", widenProviderSQL)
	_ = db.Callback().Raw().Before("gorm:raw").Register("igaread:v2_provider", widenProviderSQL)
}

func widenProviderSQL(db *gorm.DB) {
	if db == nil || db.Statement == nil {
		return
	}
	sc := graphScopeFrom(db.Statement.Context)
	if !sc.V2 {
		return
	}
	sql := db.Statement.SQL.String()
	widened := sc.rewrite(sql)
	if widened == sql {
		return
	}
	db.Statement.SQL.Reset()
	db.Statement.SQL.WriteString(widened)
}
